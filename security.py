"""Workspace Boundary Guard, path normalization, script auditing, and Windows popup approval."""

from __future__ import annotations

import base64
import ctypes
import logging
import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

LOG = logging.getLogger("pc-work-mcp.security")
IS_WINDOWS = os.name == "nt"

_MSYS_PATH_RE = re.compile(r"^/([a-zA-Z])(?:/(.*))?$")
_EXT_DRIVE_RE = re.compile(r"(?:[A-Za-z]:[\\/]|/(?:[a-zA-Z])/)[^\s\"'`|;><]+")
_WRITE_HINT_RE = re.compile(
    r"(?:\b(?:Remove-Item|Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|"
    r"Rename-Item|New-Item|Clear-Content|rm|mv|cp|mkdir|rmdir|touch|tee|chmod|chown|"
    r"del|erase|shutil\.|os\.remove|os\.unlink|os\.rmdir|os\.rename|os\.replace)\b"
    r"|\.write_text\s*\(|\.write_bytes\s*\(|open\s*\([^)]*['\"][wax+]|>>?\s*\S+)",
    re.IGNORECASE,
)


class PermissionDeniedByUser(PermissionError):
    """Raised when a red-zone action is rejected or times out."""


def normalize_path_str(raw_path: str) -> str:
    """Convert Git Bash / MSYS2 (/g/foo) or mixed-slash paths into clean Windows paths."""
    s = str(raw_path or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    if not s:
        return s
    m = _MSYS_PATH_RE.match(s)
    if m:
        drive = m.group(1).upper()
        rest = (m.group(2) or "").replace("/", "\\")
        s = f"{drive}:\\{rest}" if rest else f"{drive}:\\"
    s = os.path.expanduser(os.path.expandvars(s))
    if IS_WINDOWS and len(s) >= 2 and s[1] == ":" and "/" in s:
        s = s.replace("/", "\\")
    return s


def resolve_path(raw_path: str, base_dir: Path | None = None) -> Path:
    """Normalize and resolve symlinks / .. segments without requiring the target to exist."""
    norm = normalize_path_str(raw_path)
    p = Path(norm)
    if not p.is_absolute() and base_dir is not None:
        p = Path(base_dir) / p
    try:
        return p.resolve(strict=False)
    except OSError:
        return Path(os.path.abspath(str(p)))


def _is_under(target: Path, parent: Path) -> bool:
    try:
        t_norm = os.path.normcase(str(target))
        p_norm = os.path.normcase(str(parent))
        return os.path.commonpath([t_norm, p_norm]) == p_norm
    except ValueError:
        return False


def _winforms_popup(tool_name: str, target_desc: str, summary: str,
                    timeout_sec: int, allow_session_trust: bool,
                    parent_dir: str) -> tuple[bool, bool]:
    """Show a topmost WinForms dialog with countdown and optional session-trust checkbox."""
    trust_block = ""
    if allow_session_trust and parent_dir:
        trust_block = """
$chk = New-Object System.Windows.Forms.CheckBox
$chk.Text = "本会话信任该父目录: " + $parentDir
$chk.AutoSize = $true
$chk.Location = New-Object System.Drawing.Point(16, 210)
$form.Controls.Add($chk)
"""
    else:
        trust_block = "$chk = $null\n"

    ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$toolName = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{base64.b64encode(tool_name.encode('utf-8')).decode('ascii')}"))
$targetDesc = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{base64.b64encode(target_desc.encode('utf-8')).decode('ascii')}"))
$summaryText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{base64.b64encode(summary.encode('utf-8')).decode('ascii')}"))
$parentDir = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{base64.b64encode(parent_dir.encode('utf-8')).decode('ascii')}"))

$form = New-Object System.Windows.Forms.Form
$form.Text = "pc-work-mcp 安全审批"
$form.Size = New-Object System.Drawing.Size(560, 315)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.TopMost = $true

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "检测到工作区外写/执行操作，是否允许？"
$lblTitle.Font = New-Object System.Drawing.Font("Microsoft YaHei UI", 10, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::DarkRed
$lblTitle.AutoSize = $true
$lblTitle.Location = New-Object System.Drawing.Point(16, 14)
$form.Controls.Add($lblTitle)

$txtInfo = New-Object System.Windows.Forms.TextBox
$txtInfo.Multiline = $true
$txtInfo.ReadOnly = $true
$txtInfo.ScrollBars = "Vertical"
$txtInfo.BackColor = [System.Drawing.Color]::WhiteSmoke
$txtInfo.Location = New-Object System.Drawing.Point(16, 44)
$txtInfo.Size = New-Object System.Drawing.Size(512, 155)
$txtInfo.Text = "工具: $toolName`r`n目标: $targetDesc`r`n摘要: $summaryText"
$form.Controls.Add($txtInfo)

{trust_block}

$remaining = {max(5, int(timeout_sec))}
$btnAllow = New-Object System.Windows.Forms.Button
$btnAllow.Text = "允许本次"
$btnAllow.Location = New-Object System.Drawing.Point(320, 240)
$btnAllow.Size = New-Object System.Drawing.Size(96, 30)
$btnAllow.DialogResult = [System.Windows.Forms.DialogResult]::Yes
$form.Controls.Add($btnAllow)

$btnDeny = New-Object System.Windows.Forms.Button
$btnDeny.Text = "拒绝 ($remaining" + "s)"
$btnDeny.Location = New-Object System.Drawing.Point(432, 240)
$btnDeny.Size = New-Object System.Drawing.Size(96, 30)
$btnDeny.DialogResult = [System.Windows.Forms.DialogResult]::No
$form.Controls.Add($btnDeny)

$form.AcceptButton = $btnAllow
$form.CancelButton = $btnDeny

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({{
    $script:remaining--
    if ($script:remaining -le 0) {{
        $timer.Stop()
        $form.DialogResult = [System.Windows.Forms.DialogResult]::No
        $form.Close()
    }} else {{
        $btnDeny.Text = "拒绝 (" + $script:remaining + "s)"
    }}
}})
$form.Add_Shown({{ $form.Activate(); $timer.Start() }})
$res = $form.ShowDialog()
$timer.Stop()
$trusted = ($null -ne $chk -and $chk.Checked)
if ($res -eq [System.Windows.Forms.DialogResult]::Yes) {{
    Write-Output ("ALLOW|" + $trusted)
}} else {{
    Write-Output "DENY|False"
}}
"""
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=max(10, timeout_sec + 10),
    )
    out = (proc.stdout or "").strip().splitlines()
    last = out[-1] if out else "DENY|False"
    parts = last.split("|", 1)
    allowed = parts[0].strip().upper() == "ALLOW"
    trusted = len(parts) > 1 and parts[1].strip().lower() == "true"
    return allowed, trusted


def _win32_messagebox_popup(tool_name: str, target_desc: str, summary: str,
                            timeout_sec: int) -> tuple[bool, bool]:
    """Fallback native Win32 MessageBoxW with WM_CLOSE fail-closed timeout."""
    user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    title = f"pc-work-mcp 安全审批 [{uuid.uuid4().hex[:6]}]"
    body = (
        f"检测到工作区外写/执行操作（{timeout_sec} 秒内未响应将自动拒绝）：\n\n"
        f"工具：{tool_name}\n"
        f"目标：{target_desc}\n"
        f"摘要：{summary}\n\n"
        "是否允许执行本次操作？"
    )
    timed_out = threading.Event()

    def close_on_timeout():
        timed_out.set()
        hwnd = user32.FindWindowW(None, title)
        if hwnd:
            user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE

    timer = threading.Timer(max(1, timeout_sec), close_on_timeout)
    timer.daemon = True
    timer.start()
    try:
        # MB_YESNO (0x4) | MB_ICONWARNING (0x30) | MB_TOPMOST (0x40000) | MB_SETFOREGROUND (0x10000)
        flags = 0x4 | 0x30 | 0x40000 | 0x10000
        res = user32.MessageBoxW(0, body, title, flags)
    finally:
        timer.cancel()

    if timed_out.is_set():
        return False, False
    return (res == 6), False  # IDYES == 6


class WorkspaceBoundaryGuard:
    """Enforces Green / Yellow / Red zone rules and local popup approval."""

    def __init__(self, cfg: dict, server_root: Path,
                 approval_cb: Callable[[str, str, str, int, bool, str], tuple[bool, bool]] | None = None,
                 protected_write_files: list[Path | str] | None = None):
        self.cfg = cfg
        self.server_root = server_root.resolve(strict=False)
        ws = cfg.get("workspace") or {}
        self.default_dir = resolve_path(ws.get("default_dir") or str((cfg.get("exec") or {}).get("workdir") or Path.home()))

        outbox_cfg = (cfg.get("push") or {}).get("outbox_dir")
        outbox_dir = resolve_path(outbox_cfg) if outbox_cfg else (self.server_root / "outbox")
        self._base_shared_dirs: list[Path] = []
        for d in [outbox_dir, self.server_root / "tmp"]:
            if d not in self._base_shared_dirs:
                self._base_shared_dirs.append(d)

        self.blocked_read_prefixes: list[Path] = [
            resolve_path(p) for p in (ws.get("blocked_read_prefixes") or []) if p
        ]

        self.protected_write_files: list[Path] = []
        for fp in (protected_write_files or []):
            if fp:
                rp = resolve_path(str(fp))
                if rp not in self.protected_write_files:
                    self.protected_write_files.append(rp)

        popup_cfg = ws.get("popup_approval") or {}
        self.popup_enabled = bool(popup_cfg.get("enabled", True))
        self.popup_timeout_sec = max(5, int(popup_cfg.get("timeout_sec", 45)))
        self.allow_session_trust = bool(popup_cfg.get("allow_session_trust", True))

        self._lock = threading.Lock()
        self.session_trusted_dirs: list[Path] = []
        self._approval_cb = approval_cb
        self.whitelist_entries: list[dict[str, Any]] = []
        self.shared_green_dirs: list[Path] = []
        self.green_dirs: list[Path] = []
        self._load_whitelist_from_raw(ws.get("extra_allowed_dirs") or [])
        with self._lock:
            self._rebuild_green_dirs_locked()

    def _normalize_whitelist_entry(self, item: Any, *, require_exists: bool = False) -> dict[str, Any] | None:
        if isinstance(item, str):
            raw_path = item.strip()
            mode = "readwrite"
            allow_exec = False
            label = ""
            added_at = 0.0
        elif isinstance(item, dict):
            raw_path = str(item.get("path") or item.get("dir") or "").strip()
            mode = str(item.get("mode") or "readwrite").strip().lower()
            allow_exec = bool(item.get("allow_exec", False))
            label = str(item.get("label") or "").strip()
            added_at = float(item.get("added_at") or 0.0)
        else:
            return None
        if not raw_path:
            return None
        if mode not in ("readwrite", "readonly"):
            raise ValueError(f"invalid whitelist mode: {mode!r} (expected 'readwrite' or 'readonly')")
        if mode == "readonly":
            allow_exec = False
        target = resolve_path(raw_path, base_dir=self.default_dir)
        if self.is_blocked_read(target):
            raise ValueError(f"whitelist directory is inside blocked path: {target}")
        if require_exists and not target.is_dir():
            raise ValueError(f"whitelist directory does not exist: {target}")
        return {
            "path": str(target),
            "label": label or target.name or str(target),
            "mode": mode,
            "allow_exec": allow_exec,
            "added_at": added_at or time.time(),
        }

    def _load_whitelist_from_raw(self, raw_items: list[Any]) -> None:
        loaded: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_items:
            try:
                norm = self._normalize_whitelist_entry(item, require_exists=False)
            except ValueError as exc:
                LOG.warning("ignoring invalid extra_allowed_dirs entry %r: %s", item, exc)
                continue
            if not norm:
                continue
            key = os.path.normcase(norm["path"])
            if key in seen:
                continue
            seen.add(key)
            loaded.append(norm)
        with self._lock:
            self.whitelist_entries = loaded

    def _rebuild_green_dirs_locked(self) -> None:
        writable_wl = [
            Path(e["path"]) for e in self.whitelist_entries
            if e.get("mode", "readwrite") == "readwrite"
        ]
        shared: list[Path] = []
        for d in [*writable_wl, *self._base_shared_dirs]:
            if d not in shared:
                shared.append(d)
        self.shared_green_dirs = shared

        gdirs: list[Path] = []
        for d in [
            self.default_dir,
            self.default_dir / ".tmp_outputs",
            self.default_dir / ".mcp_snapshots",
            *self.shared_green_dirs,
        ]:
            if d not in gdirs:
                gdirs.append(d)
        self.green_dirs = gdirs

    def get_global_whitelist(self) -> list[dict[str, Any]]:
        with self._lock:
            entries = [dict(e) for e in self.whitelist_entries]
        for e in entries:
            e["exists"] = Path(e["path"]).is_dir()
        return entries

    def export_whitelist_config(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "path": e["path"],
                    "label": e.get("label") or Path(e["path"]).name or e["path"],
                    "mode": e.get("mode", "readwrite"),
                    "allow_exec": bool(e.get("allow_exec", False)),
                }
                for e in self.whitelist_entries
            ]

    def add_global_whitelist_dir(
        self,
        raw_path: str,
        *,
        mode: str = "readwrite",
        allow_exec: bool = False,
        label: str = "",
    ) -> dict[str, Any]:
        norm = self._normalize_whitelist_entry(
            {
                "path": raw_path,
                "mode": mode,
                "allow_exec": allow_exec,
                "label": label,
                "added_at": time.time(),
            },
            require_exists=True,
        )
        assert norm is not None
        key = os.path.normcase(norm["path"])
        with self._lock:
            for idx, existing in enumerate(self.whitelist_entries):
                if os.path.normcase(existing["path"]) == key:
                    merged = dict(existing)
                    merged["mode"] = norm["mode"]
                    merged["allow_exec"] = norm["allow_exec"]
                    if label:
                        merged["label"] = label.strip()
                    self.whitelist_entries[idx] = merged
                    self._rebuild_green_dirs_locked()
                    out = dict(merged)
                    out["exists"] = True
                    return out
            self.whitelist_entries.append(norm)
            self._rebuild_green_dirs_locked()
            out = dict(norm)
        out["exists"] = True
        return out

    def update_global_whitelist_dir(
        self,
        raw_path: str,
        *,
        mode: str | None = None,
        allow_exec: bool | None = None,
        label: str | None = None,
    ) -> dict[str, Any]:
        cleaned = normalize_path_str(raw_path)
        if not cleaned:
            raise ValueError("path is required")
        target = resolve_path(cleaned, base_dir=self.default_dir)
        key = os.path.normcase(str(target))
        with self._lock:
            for idx, existing in enumerate(self.whitelist_entries):
                if os.path.normcase(existing["path"]) != key:
                    continue
                updated = dict(existing)
                if mode is not None:
                    m_norm = str(mode).strip().lower()
                    if m_norm not in ("readwrite", "readonly"):
                        raise ValueError(f"invalid whitelist mode: {mode!r}")
                    updated["mode"] = m_norm
                    if m_norm == "readonly":
                        updated["allow_exec"] = False
                if allow_exec is not None:
                    updated["allow_exec"] = bool(allow_exec) if updated.get("mode", "readwrite") == "readwrite" else False
                if label is not None and label.strip():
                    updated["label"] = label.strip()
                self.whitelist_entries[idx] = updated
                self._rebuild_green_dirs_locked()
                out = dict(updated)
                out["exists"] = Path(out["path"]).is_dir()
                return out
        raise ValueError(f"whitelist directory not found: {target}")

    def remove_global_whitelist_dir(self, raw_path: str) -> bool:
        cleaned = normalize_path_str(raw_path)
        if not cleaned:
            return False
        target = resolve_path(cleaned, base_dir=self.default_dir)
        key = os.path.normcase(str(target))
        with self._lock:
            before = len(self.whitelist_entries)
            self.whitelist_entries = [
                e for e in self.whitelist_entries
                if os.path.normcase(e["path"]) != key
            ]
            removed = len(self.whitelist_entries) != before
            if removed:
                self._rebuild_green_dirs_locked()
            return removed

    def match_whitelist_entry(self, target: Path) -> dict[str, Any] | None:
        """Return the most-specific global whitelist entry covering `target`, if any."""
        with self._lock:
            entries = list(self.whitelist_entries)
        best: dict[str, Any] | None = None
        best_len = -1
        for entry in entries:
            ep = Path(entry["path"])
            if _is_under(target, ep):
                elen = len(os.path.normcase(str(ep)))
                if elen > best_len:
                    best = dict(entry)
                    best_len = elen
        return best

    def is_whitelisted_for_action(
        self,
        raw_path: str,
        *,
        access: str = "read",
        active_workspace: Path | None = None,
    ) -> bool:
        """Check whether `raw_path` falls under a global whitelist entry granting `access`."""
        eff_ws = self._effective_workspace(active_workspace)
        target = resolve_path(raw_path, base_dir=eff_ws)
        if self.is_blocked_read(target):
            return False
        if access in ("write", "exec") and self.is_protected_write(target):
            return False
        entry = self.match_whitelist_entry(target)
        if not entry:
            return False
        mode = entry.get("mode", "readwrite")
        if access == "read":
            return mode in ("readonly", "readwrite")
        if access == "write":
            return mode == "readwrite"
        if access == "exec":
            return mode == "readwrite" and bool(entry.get("allow_exec", False))
        return False

    def has_protected_write_reference(self, code: str) -> str | None:
        if not _WRITE_HINT_RE.search(code):
            return None
        lowered = code.lower()
        for fp in self.protected_write_files:
            if fp.name.lower() in lowered:
                return fp.name
        return None

    def _effective_workspace(self, active_workspace: Path | None = None) -> Path:
        if active_workspace is None:
            return self.default_dir
        return resolve_path(str(active_workspace))

    def _green_dirs_for(self, active_workspace: Path | None = None) -> tuple[Path, list[Path]]:
        eff_ws = self._effective_workspace(active_workspace)
        with self._lock:
            base_gdirs = list(self.green_dirs)
            shared = list(self.shared_green_dirs)
        if os.path.normcase(str(eff_ws)) == os.path.normcase(str(self.default_dir)):
            return self.default_dir, base_gdirs
        dirs: list[Path] = []
        for d in [eff_ws, eff_ws / ".tmp_outputs", eff_ws / ".mcp_snapshots", *shared]:
            if d not in dirs:
                dirs.append(d)
        return eff_ws, dirs

    def is_green(self, target: Path, active_workspace: Path | None = None) -> bool:
        with self._lock:
            trusted = list(self.session_trusted_dirs)
        _, gdirs = self._green_dirs_for(active_workspace)
        return any(_is_under(target, d) for d in (*gdirs, *trusted))

    def is_blocked_read(self, target: Path) -> bool:
        return any(_is_under(target, b) for b in self.blocked_read_prefixes)

    def is_protected_write(self, target: Path) -> bool:
        t_norm = os.path.normcase(str(target))
        for p in self.protected_write_files:
            p_norm = os.path.normcase(str(p))
            if (
                t_norm == p_norm
                or t_norm == os.path.normcase(str(p.with_suffix(".tmp")))
                or t_norm == os.path.normcase(str(p) + ".tmp")
            ):
                return True
        return False

    def get_session_trusted(self) -> list[str]:
        with self._lock:
            return [str(p) for p in self.session_trusted_dirs]

    def classify_path(self, raw_path: str, active_workspace: Path | None = None) -> tuple[str, Path]:
        eff_ws = self._effective_workspace(active_workspace)
        target = resolve_path(raw_path, base_dir=eff_ws)
        if self.is_blocked_read(target):
            return "blocked", target
        if self.is_green(target, active_workspace=eff_ws):
            return "green", target
        return "yellow", target

    def check_read(self, tool_name: str, raw_path: str, active_workspace: Path | None = None) -> Path:
        zone, target = self.classify_path(raw_path, active_workspace=active_workspace)
        if zone == "blocked":
            raise PermissionDeniedByUser(
                f"PermissionDenied: {tool_name} cannot read protected path: {target}"
            )
        return target

    def check_write(self, tool_name: str, raw_path: str, summary: str,
                    active_workspace: Path | None = None) -> Path:
        eff_ws = self._effective_workspace(active_workspace)
        zone, target = self.classify_path(raw_path, active_workspace=eff_ws)
        if self.is_protected_write(target):
            raise PermissionDeniedByUser(
                f"PermissionDenied: {tool_name} cannot modify control-plane file '{target}'. "
                "权限与鉴权配置仅由本机与油猴本地桥管理，不由会话内 Agent 修改。"
            )
        if zone == "blocked":
            raise PermissionDeniedByUser(
                f"PermissionDenied: {tool_name} cannot write protected path: {target}"
            )
        if zone == "green":
            return target
        # External write -> Red Zone
        wl = self.match_whitelist_entry(target)
        if wl and wl.get("mode") == "readonly":
            summary = f"{summary}（该目录在全局白名单中设为仅只读）" if summary else "该目录在全局白名单中设为仅只读"
        parent = str(target.parent)
        self._require_approval(tool_name, str(target), summary, parent, effective_ws=eff_ws)
        return target

    def check_exec(self, tool_name: str, code: str, cwd: str | None,
                   active_workspace: Path | None = None) -> Path:
        eff_ws = self._effective_workspace(active_workspace)
        workdir = resolve_path(cwd, base_dir=eff_ws) if (cwd and str(cwd).strip()) else eff_ws
        if self.is_blocked_read(workdir):
            raise PermissionDeniedByUser(
                f"PermissionDenied: {tool_name} cwd is in protected directory: {workdir}"
            )
        prot_hit = self.has_protected_write_reference(code)
        if prot_hit:
            raise PermissionDeniedByUser(
                f"PermissionDenied: {tool_name} script appears to modify protected control-plane file ({prot_hit})."
            )
        cwd_green = self.is_green(workdir, active_workspace=eff_ws)
        external_targets = self._detect_external_write_targets(code, workdir, active_workspace=eff_ws)
        if cwd_green and not external_targets:
            return workdir

        reasons = []
        if not cwd_green:
            reasons.append(f"工作目录位于工作区外 ({workdir})")
        if external_targets:
            reasons.append(f"脚本包含跨区写入特征 ({', '.join(external_targets[:3])})")
        summary = "；".join(reasons)
        trust_dir = str(workdir) if not cwd_green else ""
        self._require_approval(tool_name, str(workdir), summary, trust_dir, effective_ws=eff_ws)
        return workdir

    def _detect_external_write_targets(self, code: str, workdir: Path,
                                       active_workspace: Path | None = None) -> list[str]:
        if not _WRITE_HINT_RE.search(code):
            return []
        hits = []
        for match in _EXT_DRIVE_RE.findall(code):
            resolved = resolve_path(match)
            if not self.is_green(resolved, active_workspace=active_workspace):
                hits.append(str(resolved))
        if ".." in code and not self.is_green(workdir, active_workspace=active_workspace):
            hits.append("relative '..' outside green zone")
        elif ".." in code:
            # Check if any .. token escapes active workspace
            for tok in re.findall(r"[^\s\"'`|;><]*\.\.[^\s\"'`|;><]*", code):
                cand = resolve_path(str(workdir / tok))
                if not self.is_green(cand, active_workspace=active_workspace):
                    hits.append(str(cand))
        return hits

    def _require_approval(self, tool_name: str, target_desc: str, summary: str,
                          parent_dir: str, effective_ws: Path | None = None) -> None:
        if not self.popup_enabled:
            raise PermissionDeniedByUser(
                f"PermissionDeniedByUser: {tool_name} on '{target_desc}' rejected (popup approval disabled)"
            )

        if self._approval_cb is not None:
            allowed, trust_parent = self._approval_cb(
                tool_name, target_desc, summary,
                self.popup_timeout_sec, self.allow_session_trust, parent_dir,
            )
        elif IS_WINDOWS:
            try:
                allowed, trust_parent = _winforms_popup(
                    tool_name, target_desc, summary,
                    self.popup_timeout_sec, self.allow_session_trust, parent_dir,
                )
            except Exception as exc:  # noqa: BLE001
                LOG.warning("WinForms popup failed (%s), falling back to MessageBoxW", exc)
                allowed, trust_parent = _win32_messagebox_popup(
                    tool_name, target_desc, summary, self.popup_timeout_sec,
                )
        else:
            allowed, trust_parent = False, False

        if not allowed:
            ws_hint = effective_ws or self.default_dir
            raise PermissionDeniedByUser(
                f"PermissionDeniedByUser: user denied or timed out ({self.popup_timeout_sec}s) "
                f"for {tool_name} on '{target_desc}'. Use workspace '{ws_hint}' instead."
            )

        if trust_parent and self.allow_session_trust and parent_dir:
            p = resolve_path(parent_dir)
            with self._lock:
                if p not in self.session_trusted_dirs:
                    self.session_trusted_dirs.append(p)
                    LOG.info("session trusted directory added: %s", p)
