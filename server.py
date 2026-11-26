#!/usr/bin/env python3
"""pc-work-mcp —— Windows 本机工作台 MCP 服务（本地派发鉴权 + 网关/沙箱边界声明与像素探针）。"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import difflib
import fnmatch
import hashlib
import hmac
import html
import io
import ipaddress
import json
import logging
import mimetypes
import os
import queue
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from bridge import BridgeManager  # noqa: E402
from checks import PostEditChecker  # noqa: E402
from jobs import JobManager, kill_tree, popen_platform_kwargs  # noqa: E402
from output_guard import OutputGuard  # noqa: E402
from permissions import ConversationPermissionManager  # noqa: E402
from search_tools import (  # noqa: E402
    DEFAULT_IGNORED_DIRS,
    find_files as search_find_files,
    grep_search as search_grep,
    is_ignored_dir_name,
    normalize_ignore_entry,
)
from security import PermissionDeniedByUser, WorkspaceBoundaryGuard, resolve_path  # noqa: E402
from snapshot import SnapshotManager  # noqa: E402
from task_plans import TaskPlanManager  # noqa: E402
from workspace_rules import (  # noqa: E402
    DEFAULT_MAX_TOTAL_CHARS,
    DEFAULT_REINJECT_EVERY_CALLS,
    DEFAULT_REINJECT_EVERY_OUTPUT_CHARS,
    DEFAULT_RULE_PATTERNS,
    WorkspaceRulesManager,
)
from workspaces import WorkspaceBindingManager  # noqa: E402

try:
    from PIL import Image as PilImage, ImageOps as PilImageOps
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

IS_WINDOWS = os.name == "nt"
MCP_RUNTIME_SUBDIR = "Gemini-Windows-Mcp"


def _default_clean_workspace_dir(src_dir: Path | None = None) -> Path:
    """若脚本已位于 Gemini-Windows-Mcp 子目录，默认回退到外层干净工作区目录；否则留在当前目录。"""
    base = (src_dir or HERE).resolve(strict=False)
    if base.name == MCP_RUNTIME_SUBDIR:
        return base.parent.resolve(strict=False)
    return base


class WorkspaceSelectionCancelled(RuntimeError):
    """首次运行用户取消选择工作区且拒绝隐式回退时抛出。"""


# ---------------------------------------------------------------------------
# 默认配置（config.json 覆盖）
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "listen": {
        "host": "0.0.0.0",
        "port": 15672,
        "bind_retry_sec": 120,
    },
    "auth": {
        "enabled": True,
        "token": "",
        "health_requires_auth": False,
    },
    "oauth": {
        "enabled": True,
        "public_base_url": "",
        "authorize_password": "",
        "access_token_ttl_sec": 28800,
        "refresh_token_ttl_sec": 2592000,
        "startup_tcp_check": False,
    },
    "workspace": {
        "initialized": False,
        "default_dir": "",
        "extra_allowed_dirs": [],
        "ignored_dirs": [],
        "blocked_read_prefixes": [
            r"C:\Windows\System32",
            str(Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data"),
        ],
        "popup_approval": {
            "enabled": True,
            "timeout_sec": 45,
            "allow_session_trust": True,
        },
        "snapshot": {
            "enabled": True,
            "max_versions_per_file": 20,
        },
    },
    "exec": {
        "sync_timeout_sec": 60,
        "max_sync_timeout_sec": 180,
        "max_inline_chars": 16000,
        "max_concurrency": 4,
        "workdir": "",
        "powershell_exe": "",
        "python_exe": "",
        "bash_exe": "",
    },
    "vision": {
        "max_dimension": 1600,
        "jpeg_quality": 85,
        "max_image_bytes": 4194304,
        "canary_pixel": True,
    },
    "push": {
        "outbox_dir": "",
        "url_ttl_sec": 86400,
    },
    "permissions": {
        "per_conversation_enabled": True,
        "new_conversation_default_profile": "ask",
        "ambiguous_window_policy": "ask",
        "approval_timeout_sec": 45,
        "store_file": "",
    },
    "workspace_rules": {
        "enabled": True,
        "reinject_every_calls": DEFAULT_REINJECT_EVERY_CALLS,
        "reinject_every_output_chars": DEFAULT_REINJECT_EVERY_OUTPUT_CHARS,
        "max_total_chars": DEFAULT_MAX_TOTAL_CHARS,
        "patterns": list(DEFAULT_RULE_PATTERNS),
    },
    "post_edit_checks": {
        "syntax_check": True,
        "on_edit_commands": [],
        "command_timeout_sec": 15,
        "allow_workspace_checks_file": True,
    },
    "task_plan": {
        "default_max_auto_turns": 5,
        "max_allowed_auto_turns": 10,
        "min_cooldown_sec": 5,
        "max_handoff_chars": 220,
    },
    "log": {
        "file": "",
        "level": "INFO",
    },
}

SERVER_NAME = "pc-work-mcp"
SERVER_VERSION = "1.0.0-dist"
SUPPORTED_PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_PROTOCOL = "2025-06-18"

# 1x1 像素 PNG 探测图（用于探测网关是否放开 MCP 图像读权限）
CANARY_PIXEL_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mP4z8AAAAMBAQD3A0FDAAAAAElFTkSuQmCC"
)
BOUNDARY_EFFECTIVE_DATE = "2026-11-26"
MEDIA_BOUNDARY_NOTICE = (
    f"【当前边界缺陷声明（截至 {BOUNDARY_EFFECTIVE_DATE} 依然生效）】"
    "1) 写入/导出受限：Gemini 网页端的生图内容被锁定在沙箱内，无法通过 MCP 回传的方式落盘到用户本机；"
    "2) 读取/传入受限：同理，用户电脑内的图片也无法通过 MCP 到达模型层面，工具返回的 MCP 图像块会被网关层面丢弃（仅纯文本与可选 OCR 可达）。"
    "3) 动态松动探测：不能排除后期 Google 松动部分限制，如果后期松动，Agent 应主动知情并告知用户——"
    "如果你发现调用时 MCP 会塞一个小像素点到眼前（如 workspace_status 附带的 1×1 像素探测图，或 read_image 返回的图片块），"
    "就证明 Google 放开了读的权限；至于能不能写入（将网页端沙箱生图回传落盘），还是交由 Agent 自行判断。"
)
ENV_ADAPT_AND_SAFETY_NOTICE = (
    "【运行环境适配与交付原则】不同用户电脑已安装的工具与依赖各不相同，不要默认假定 python 第三方库或 bash 已预装；"
    "请先以 workspace_status 返回的 engines 探测结果为准。如果本机只有 PowerShell（pwsh / powershell.exe）可用，"
    "且任务确实需要其他命令工具或依赖库，请直接引导用户安装，或由模型在征得确认后通过 winget/pip 等命令自行安装以完成交付。"
    "【严禁原地改坏运行中工具】工作区内已复制本 MCP 的源码与配置供后续按需定制，但严禁直接修改当前正在运行、"
    "自己正在调用的工具代码与接口定义（避免工具失效）；若需要定制运行提示词或扩展功能，必须先在工作区内新建独立目录（新版本文件夹），"
    "在新目录内修改并交由用户切换重启后再使用。"
)
PER_CONVERSATION_GUIDE_NOTICE = (
    "【按会话链接细化授权提示】当前若未连接浏览器油猴插件，将先以工作区兜底默认权限运行；"
    "强烈建议安装搭配本服务内置的 Tampermonkey 油猴桥接脚本（/bridge/pc-work-mcp-gemini.user.js），"
    "即可基于每个 Gemini 会话网页链接（/app/<conversation_id>）独立分配只读、仅媒体、工作区读写、命令执行等颗粒度权限，"
    "不再一次性全局生效。该授权完全由用户通过本地桥与本机配置掌控，不由会话内 Agent 掌管，也不由 Google 掌管。"
)

LOG = logging.getLogger("pc-work-mcp")


# ---------------------------------------------------------------------------
# 通用工具函数
# ---------------------------------------------------------------------------

def deep_merge(base, override):
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: str | None):
    cfg = deep_merge(DEFAULT_CONFIG, {})
    cfg_base = Path(path).resolve(strict=False).parent if path else HERE
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8-sig") as fh:
            user = json.load(fh)
        cfg = deep_merge(cfg, user)
    if not str((cfg.get("workspace") or {}).get("default_dir") or "").strip():
        cfg.setdefault("workspace", {})["default_dir"] = str(_default_clean_workspace_dir(cfg_base))
    if not str((cfg.get("exec") or {}).get("workdir") or "").strip():
        cfg.setdefault("exec", {})["workdir"] = str(cfg["workspace"]["default_dir"])
    if not str((cfg.get("push") or {}).get("outbox_dir") or "").strip():
        cfg["push"]["outbox_dir"] = str(cfg_base / "outbox")
    if not str((cfg.get("log") or {}).get("file") or "").strip():
        cfg["log"]["file"] = str(cfg_base / "logs" / "server.log")
    return cfg


def mask_token(token: str) -> str:
    tok = str(token or "").strip()
    if not tok:
        return ""
    if len(tok) <= 10:
        return "*" * len(tok)
    return f"{tok[:8]}...{tok[-4:]}"


def is_local_token_configured(cfg: dict) -> bool:
    auth_cfg = cfg.get("auth") or {}
    if not auth_cfg.get("enabled", True):
        return True
    return bool(str(auth_cfg.get("token") or "").strip())


def get_windows_desktop() -> Path:
    """获取当前用户真实的 Windows 桌面路径（兼容桌面重定向）。"""
    if IS_WINDOWS:
        try:
            import winreg
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            ) as key:
                raw, _ = winreg.QueryValueEx(key, "Desktop")
                expanded = os.path.expandvars(str(raw or "").strip())
                if expanded:
                    return Path(expanded)
        except OSError:
            pass
    return Path.home() / "Desktop"


def _pick_folder_winforms(prompt_title: str, initial_dir: Path) -> Path | None:
    """弹出置顶 Windows 文件夹选择框；取消或失败返回 None。"""
    if not IS_WINDOWS:
        return None
    title_b64 = base64.b64encode(prompt_title.encode("utf-8")).decode("ascii")
    init_b64 = base64.b64encode(str(initial_dir).encode("utf-8")).decode("ascii")
    ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()
$title = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{title_b64}"))
$initDir = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{init_b64}"))
$owner = New-Object System.Windows.Forms.Form
$owner.TopMost = $true
$owner.StartPosition = 'CenterScreen'
$owner.Width = 1
$owner.Height = 1
$owner.ShowInTaskbar = $false
$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
$dlg.Description = $title
$dlg.UseDescriptionForTitle = $true
if (Test-Path -LiteralPath $initDir) {{ $dlg.SelectedPath = $initDir }}
$res = $dlg.ShowDialog($owner)
$owner.Dispose()
if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $dlg.SelectedPath) {{
    Write-Output $dlg.SelectedPath
}}
"""
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell.exe", "-STA", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=180,
        )
        chosen = (proc.stdout or "").strip().splitlines()
        if proc.returncode == 0 and chosen and chosen[-1].strip():
            return Path(chosen[-1].strip())
    except Exception as exc:  # noqa: BLE001
        LOG.warning("folder picker failed: %s", exc)
    return None


def _sync_config_file(path: Path, updater) -> dict:
    if path.is_file():
        with open(path, "r", encoding="utf-8-sig") as fh:
            disk = json.load(fh)
    else:
        disk = deep_merge(DEFAULT_CONFIG, {})
        disk["workspace"]["default_dir"] = ""
        disk["exec"]["workdir"] = ""
        disk["push"]["outbox_dir"] = ""
        disk["log"]["file"] = ""
    updater(disk)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_cfg = path.with_suffix(".json.tmp")
    tmp_cfg.write_text(json.dumps(disk, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp_cfg.replace(path)
    return disk


def _resolve_mcp_runtime_dir(ws_dir: Path) -> Path:
    """工作区根目录保持洁净，所有 MCP 源码/配置统一放在 Gemini-Windows-Mcp 子目录下。"""
    resolved = ws_dir.resolve(strict=False)
    if resolved.name == MCP_RUNTIME_SUBDIR:
        return resolved
    return resolved / MCP_RUNTIME_SUBDIR


def _resolve_synced_config_paths(config_path: Path, ws_dir_str: str) -> list[Path]:
    if not ws_dir_str:
        return []
    ws_path = Path(ws_dir_str)
    src_res = config_path.resolve(strict=False)
    out: list[Path] = []
    for cand in (_resolve_mcp_runtime_dir(ws_path) / "config.json", ws_path / "config.json"):
        if cand.is_file() and cand.resolve(strict=False) != src_res and cand not in out:
            out.append(cand)
    return out


def copy_all_assets_to_workspace(src_root: Path, dst_ws: Path) -> list[str]:
    """首次执行时将服务端全部源码、配置、文档与测试一次性复制到独立 MCP 子目录内。"""
    src_resolved = src_root.resolve(strict=False)
    dst_resolved = dst_ws.resolve(strict=False)
    dst_resolved.mkdir(parents=True, exist_ok=True)
    (dst_resolved / "logs").mkdir(exist_ok=True)
    (dst_resolved / "outbox").mkdir(exist_ok=True)

    if src_resolved == dst_resolved:
        return []

    skip_dirs = frozenset({
        "__pycache__", ".pytest_cache", ".mypy_cache",
        ".mcp_snapshots", ".tmp_outputs", ".git", "logs", "outbox",
    })
    copied: list[str] = []
    for root, dirnames, filenames in os.walk(src_resolved):
        root_path = Path(root)
        # Skip target workspace if it lives inside src_root, plus transient/runtime dirs
        dirnames[:] = [
            d for d in sorted(dirnames)
            if d not in skip_dirs and (root_path / d).resolve(strict=False) != dst_resolved
        ]
        rel_dir = root_path.relative_to(src_resolved)
        target_dir = dst_resolved / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for fname in sorted(filenames):
            if fname.endswith((".pyc", ".pyo", ".tmp")):
                continue
            src_file = root_path / fname
            dst_file = target_dir / fname
            shutil.copy2(src_file, dst_file)
            rel_file = fname if str(rel_dir) == "." else str(rel_dir / fname)
            copied.append(rel_file)
    return copied


def ensure_first_run_workspace(
    config_path: Path,
    requested_workspace: str | None = None,
    interactive: bool = True,
    use_gui: bool = True,
    allow_gui: bool | None = None,
    use_desktop_workspace: bool = False,
    desktop_dir: Path | None = None,
    source_root: Path | None = None,
) -> dict:
    """首次运行强制选择工作区：取消即中止；仅当已处于 Gemini-Windows-Mcp 子目录时回退到外层干净目录（或显式传 use_desktop_workspace）。"""
    disk = {}
    if config_path.is_file():
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            disk = json.load(fh)

    src_root = (source_root or HERE).resolve(strict=False)
    in_runtime_subdir = (src_root.name == MCP_RUNTIME_SUBDIR)

    ws_sec = disk.get("workspace") or {}
    existing_dir = str(ws_sec.get("default_dir") or "").strip()
    already_init = bool(ws_sec.get("initialized", False))
    if (already_init or existing_dir) and not requested_workspace and not use_desktop_workspace:
        fallback_ws = str(_default_clean_workspace_dir(src_root))
        return {
            "initialized_now": False,
            "workspace_dir": existing_dir or fallback_ws,
            "copied_files": [],
        }

    desktop_base = desktop_dir or get_windows_desktop()
    default_desktop_ws = desktop_base / "pc-work-mcp-workspace"
    gui_allowed = (bool(interactive) and bool(use_gui) and IS_WINDOWS) if allow_gui is None else (bool(allow_gui) and bool(use_gui) and IS_WINDOWS)

    chosen: Path | None = None
    source_mode = "outer_clean_dir"
    if requested_workspace and requested_workspace.strip():
        chosen = Path(os.path.expanduser(os.path.expandvars(requested_workspace.strip())))
        source_mode = "cli_argument"
    elif use_desktop_workspace:
        chosen = default_desktop_ws
        source_mode = "desktop_flag"
    else:
        gui_tried = False
        if gui_allowed:
            gui_tried = True
            picker_title = (
                "pc-work-mcp 首次运行：请选择工作区目录（取消则留在当前外层目录）"
                if in_runtime_subdir
                else "pc-work-mcp 首次运行：请选择工作区目录（点取消将中止初始化，不会自动建桌面目录）"
            )
            chosen = _pick_folder_winforms(picker_title, desktop_base)
            if chosen is not None:
                source_mode = "gui_picker"
        if chosen is None and interactive and not gui_tried:
            prompt_msg = (
                f"[首次运行] 请输入工作区路径（直接回车将留在当前外层干净目录 {src_root.parent}）："
                if in_runtime_subdir
                else "[首次运行] 请输入工作区路径（例 D:\\MyWorkspace；直接回车将取消初始化）："
            )
            try:
                raw_in = input(prompt_msg).strip()
            except (EOFError, KeyboardInterrupt):
                raw_in = ""
            if raw_in:
                chosen = Path(os.path.expanduser(os.path.expandvars(raw_in)))
                source_mode = "console_input"

    if chosen is None:
        if in_runtime_subdir:
            chosen = src_root.parent
            source_mode = "outer_clean_dir"
        else:
            raise WorkspaceSelectionCancelled(
                "未选择工作区（已取消），未创建桌面默认目录或复制任何文件。"
                "请重新运行并选择文件夹，或显式传 --workspace \"<路径>\" / --use-desktop-workspace。"
            )

    ws_dir = chosen.resolve(strict=False)
    ws_dir.mkdir(parents=True, exist_ok=True)
    mcp_dir = _resolve_mcp_runtime_dir(ws_dir)
    mcp_dir.mkdir(parents=True, exist_ok=True)
    copied = copy_all_assets_to_workspace(src_root, mcp_dir)

    def apply_ws(cfg_obj: dict):
        w = cfg_obj.setdefault("workspace", {})
        w["initialized"] = True
        w["default_dir"] = str(ws_dir)
        e = cfg_obj.setdefault("exec", {})
        e["workdir"] = str(ws_dir)
        cfg_obj.setdefault("push", {})["outbox_dir"] = ""
        cfg_obj.setdefault("log", {})["file"] = ""

    updated_disk = _sync_config_file(config_path, apply_ws)
    ws_cfg_path = mcp_dir / "config.json"
    if ws_cfg_path.resolve(strict=False) != config_path.resolve(strict=False):
        def copy_with_auth(cfg_obj: dict):
            apply_ws(cfg_obj)
            if (updated_disk.get("auth") or {}).get("token"):
                cfg_obj.setdefault("auth", {})["token"] = updated_disk["auth"]["token"]
                cfg_obj["auth"]["enabled"] = bool(updated_disk["auth"].get("enabled", True))
        _sync_config_file(ws_cfg_path, copy_with_auth)

    return {
        "initialized_now": True,
        "mode": source_mode,
        "workspace_dir": str(ws_dir),
        "mcp_dir": str(mcp_dir),
        "copied_count": len(copied),
        "copied_files": copied,
    }


def issue_local_token(config_path: Path, rotate: bool = False) -> dict:
    """在连接 Google 服务前，于本机派发并持久化鉴权 token。"""
    disk = {}
    if config_path.is_file():
        with open(config_path, "r", encoding="utf-8-sig") as fh:
            disk = json.load(fh)

    auth_sec = disk.get("auth") or {}
    existing = str(auth_sec.get("token") or "").strip()
    if existing and not rotate:
        return {
            "issued": False,
            "already_configured": True,
            "masked_token": mask_token(existing),
            "config_path": str(config_path),
        }

    new_token = "pcmcp_" + secrets.token_urlsafe(24)

    def set_tok(cfg_obj: dict):
        a = cfg_obj.setdefault("auth", {})
        a["enabled"] = True
        a["token"] = new_token

    updated = _sync_config_file(config_path, set_tok)
    ws_dir_str = str((updated.get("workspace") or {}).get("default_dir") or "").strip()
    for ws_cfg_path in _resolve_synced_config_paths(config_path, ws_dir_str):
        _sync_config_file(ws_cfg_path, set_tok)

    if rotate:
        cfg_eff = load_config(str(config_path))
        log_file = Path((cfg_eff.get("log") or {}).get("file") or (HERE / "logs" / "server.log"))
        oauth_candidates = [
            Path((cfg_eff.get("oauth") or {}).get("state_file") or (log_file.parent / "oauth_state.json")),
        ]
        if ws_dir_str:
            oauth_candidates.append(_resolve_mcp_runtime_dir(Path(ws_dir_str)) / "logs" / "oauth_state.json")
        for oauth_state in oauth_candidates:
            if oauth_state.is_file():
                try:
                    state = json.loads(oauth_state.read_text(encoding="utf-8"))
                    state["tokens"] = {}
                    state["refresh_tokens"] = {}
                    tmp_state = oauth_state.with_suffix(".tmp")
                    tmp_state.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
                    tmp_state.replace(oauth_state)
                except Exception as exc:  # noqa: BLE001
                    LOG.warning("failed to clear old oauth tokens during rotation: %s", exc)

    return {
        "issued": True,
        "rotated": bool(existing),
        "token": new_token,
        "masked_token": mask_token(new_token),
        "config_path": str(config_path),
    }


def _is_private_or_loopback_host(host: str) -> bool:
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return True
    if h in ("localhost", "ip6-localhost") or h.endswith((".local", ".lan", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast)
    except ValueError:
        return False


def _probe_edis_family(host: str, port: int, family: str, timeout_sec: float = 8.0) -> dict:
    """使用 EDIS 双栈在线 TCP 探测接口检查单栈（IPv6 或 IPv4）外网端口可达性。"""
    payload = json.dumps({"target": host, "port": int(port), "family": family}).encode("utf-8")
    req = urllib.request.Request(
        "https://at.edisglobal.com/api/v1/port",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        st = str(data.get("status") or "").lower()
        if st == "open":
            return {
                "state": "open",
                "provider": "edisglobal",
                "family": family,
                "resolved": data.get("resolved"),
                "connect_ms": data.get("connectTimeMs"),
                "source": data.get("source"),
            }
        if st in ("closed", "timeout", "filtered", "unreachable"):
            return {
                "state": "timeout" if st == "timeout" else "closed",
                "provider": "edisglobal",
                "family": family,
                "resolved": data.get("resolved"),
                "detail": st,
                "source": data.get("source"),
            }
        return {"state": "api_error", "provider": "edisglobal", "family": family, "detail": st or "unknown"}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        if exc.code == 400 and ("family_unavailable" in body or "resolve" in body.lower() or "nxdomain" in body.lower()):
            return {"state": "dns_missing", "provider": "edisglobal", "family": family, "detail": body.strip()}
        return {"state": "api_error", "provider": "edisglobal", "family": family, "detail": f"HTTP {exc.code}: {body[:120]}"}
    except Exception as exc:
        return {"state": "api_error", "provider": "edisglobal", "family": family, "detail": str(exc)}


def _probe_globalping_family(host: str, port: int, scheme: str, family: str, timeout_sec: float = 12.0) -> dict:
    """备选 Globalping 全球多节点双栈探针（兼容中国大陆直连与 IPv6 AAAA）。"""
    ip_ver = 6 if family == "6" else 4
    proto = "HTTPS" if (scheme or "").lower() == "https" else "HTTP"
    payload = json.dumps({
        "type": "http",
        "target": host,
        "locations": [{"continent": "NA", "limit": 1}, {"continent": "EU", "limit": 1}, {"continent": "AS", "limit": 1}],
        "measurementOptions": {
            "protocol": proto,
            "port": int(port),
            "request": {"path": "/health", "method": "GET"},
            "ipVersion": ip_ver,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.globalping.io/v1/measurements",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=min(8.0, timeout_sec)) as resp:
            meta = json.loads(resp.read().decode("utf-8"))
        mid = meta.get("id")
        if not mid:
            return {"state": "api_error", "provider": "globalping", "family": family, "detail": "no measurement id"}
    except Exception as exc:
        return {"state": "api_error", "provider": "globalping", "family": family, "detail": str(exc)}

    deadline = time.monotonic() + max(4.0, timeout_sec)
    last_res = None
    while time.monotonic() < deadline:
        time.sleep(0.9)
        try:
            r2 = urllib.request.Request(
                f"https://api.globalping.io/v1/measurements/{mid}",
                headers={"User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}"},
            )
            with urllib.request.urlopen(r2, timeout=6.0) as resp2:
                last_res = json.loads(resp2.read().decode("utf-8"))
            if last_res.get("status") != "in-progress":
                break
        except Exception as exc:
            return {"state": "api_error", "provider": "globalping", "family": family, "detail": str(exc)}

    results = (last_res or {}).get("results") or []
    if not results:
        return {"state": "api_error", "provider": "globalping", "family": family, "detail": "empty results"}

    states: list[str] = []
    details: list[str] = []
    for item in results:
        res_obj = item.get("result") or {}
        code = res_obj.get("statusCode")
        raw = str(res_obj.get("rawOutput") or "")
        if isinstance(code, int) and code > 0:
            return {"state": "open", "provider": "globalping", "family": family, "detail": f"HTTP {code}"}
        upper = raw.upper()
        # 自签名证书或 TLS 主机名告警说明 TCP 三次握手已经通了
        if any(tok in upper for tok in ("SELF_SIGNED", "UNABLE_TO_VERIFY", "CERT_", "TLS", "SSL")):
            if "ECONNREFUSED" not in upper and "ETIMEDOUT" not in upper:
                return {"state": "open", "provider": "globalping", "family": family, "detail": "TCP+TLS reached"}
        if "ENOTFOUND" in upper or "EAI_NONAME" in upper or "NO AAAA" in upper or "NO A RECORD" in upper:
            states.append("dns_missing")
        elif "ETIMEDOUT" in upper:
            states.append("timeout")
        elif "ECONNREFUSED" in upper or "EHOSTUNREACH" in upper or "ENETUNREACH" in upper:
            states.append("closed")
        else:
            states.append("api_error")
        if raw:
            details.append(raw.strip().splitlines()[0][:100])

    if "closed" in states:
        return {"state": "closed", "provider": "globalping", "family": family, "detail": "; ".join(details[:2])}
    if "timeout" in states:
        return {"state": "timeout", "provider": "globalping", "family": family, "detail": "; ".join(details[:2])}
    if states and all(s == "dns_missing" for s in states):
        return {"state": "dns_missing", "provider": "globalping", "family": family, "detail": "; ".join(details[:2])}
    return {"state": "api_error", "provider": "globalping", "family": family, "detail": "; ".join(details[:2]) or "inconclusive"}


def verify_public_tcp_reachability(
    public_base_url: str,
    *,
    probe_fn=None,
    timeout_sec: float = 10.0,
) -> dict:
    """从外网在线探测双栈（IPv6 + IPv4）TCP 可达性，用于启动自检锁。"""
    raw = str(public_base_url or "").strip()
    if not raw:
        return {"status": "skipped", "reason": "empty_url"}
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").strip()
    if not host:
        return {"status": "skipped", "reason": "invalid_url", "url": raw}
    scheme = (parsed.scheme or "https").lower()
    port = parsed.port or (443 if scheme == "https" else 80)

    if _is_private_or_loopback_host(host):
        return {"status": "skipped", "reason": "private_or_loopback_host", "host": host, "port": port}

    def run_dual(fn):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f6 = pool.submit(fn, host, port, "6")
            f4 = pool.submit(fn, host, port, "4")
            return {"ipv6": f6.result(), "ipv4": f4.result()}

    if probe_fn is not None:
        fam_res = run_dual(probe_fn)
    else:
        fam_res = run_dual(lambda h, p, fam: _probe_edis_family(h, p, fam, timeout_sec=min(8.0, timeout_sec)))
        # 若主探针服务本身不可用，自动回退到 Globalping 多节点探测
        if all((fam_res[k] or {}).get("state") == "api_error" for k in ("ipv6", "ipv4")):
            fam_res = run_dual(lambda h, p, fam: _probe_globalping_family(h, p, scheme, fam, timeout_sec=timeout_sec))

    s6 = str((fam_res["ipv6"] or {}).get("state") or "api_error")
    s4 = str((fam_res["ipv4"] or {}).get("state") or "api_error")
    open_families = [name for name, st in (("IPv6", s6), ("IPv4", s4)) if st == "open"]
    if open_families:
        return {
            "status": "reachable",
            "host": host,
            "port": port,
            "reachable_families": open_families,
            "families": fam_res,
        }
    if s6 in ("closed", "timeout") or s4 in ("closed", "timeout") or (s6 == "dns_missing" and s4 == "dns_missing"):
        return {
            "status": "unreachable",
            "host": host,
            "port": port,
            "reachable_families": [],
            "families": fam_res,
        }
    return {
        "status": "unavailable",
        "host": host,
        "port": port,
        "reachable_families": [],
        "families": fam_res,
    }


def setup_logging(cfg):
    log_cfg = cfg.get("log") or {}
    level = getattr(logging, str(log_cfg.get("level", "INFO")).upper(), logging.INFO)
    handlers = [logging.StreamHandler(sys.stderr)]
    log_file = log_cfg.get("file")
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
        except OSError:
            pass
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=handlers,
        force=True,
    )


def decode_bytes(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def read_text_auto(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf-8-sig"
    for enc in ("utf-8", "gbk", "utf-16", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), "utf-8-replace"


# ---------------------------------------------------------------------------
# 多引擎执行器（PowerShell / Python / Git Bash）
# ---------------------------------------------------------------------------

class MultiRunner:
    """支持 PowerShell、Python、Git Bash 三种执行引擎，共享并发信号量。"""

    def __init__(self, cfg):
        self.cfg = cfg
        self.sem = threading.BoundedSemaphore(max(1, int(cfg["exec"].get("max_concurrency", 4))))
        self.pwsh_exe = self._find_powershell()
        self.python_exe = self._find_python()
        self.bash_exe = self._find_bash()

    def _find_powershell(self) -> str:
        configured = str(self.cfg["exec"].get("powershell_exe") or "").strip()
        candidates = [configured] if configured else []
        if IS_WINDOWS:
            for name in ("powershell.exe", "pwsh.exe"):
                found = shutil.which(name)
                if found:
                    candidates.append(found)
            system_root = os.environ.get("SystemRoot") or r"C:\Windows"
            candidates.append(os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
        else:
            found = shutil.which("pwsh") or shutil.which("powershell")
            if found:
                candidates.append(found)
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand
        return "powershell.exe" if IS_WINDOWS else "pwsh"

    def _find_python(self) -> str:
        configured = str(self.cfg["exec"].get("python_exe") or "").strip()
        candidates = [configured, sys.executable] if configured else [sys.executable]
        found = shutil.which("python") or shutil.which("python3")
        if found:
            candidates.append(found)
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand
        return sys.executable or "python"

    def _find_bash(self) -> str:
        configured = str(self.cfg["exec"].get("bash_exe") or "").strip()
        candidates = [configured] if configured else []
        if IS_WINDOWS:
            candidates.extend([
                r"C:\Program Files\Git\usr\bin\bash.exe",
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
            ])
        found = shutil.which("bash")
        if found and "System32" not in found:
            candidates.append(found)
        for cand in candidates:
            if cand and os.path.isfile(cand):
                return cand
        return ""

    def _clamp_timeout(self, timeout_sec: int | None) -> int:
        default_t = int(self.cfg["exec"].get("sync_timeout_sec", 60))
        hard_cap = int(self.cfg["exec"].get("max_sync_timeout_sec", 180))
        return max(1, min(int(timeout_sec or default_t), hard_cap))

    def _exec_process(self, cmd: list[str], workdir: str, timeout: int, env_extra: dict | None = None):
        if not os.path.isdir(workdir):
            raise ValueError(f"cwd does not exist: {workdir}")
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        started = time.time()
        timed_out = False
        with self.sem:
            proc = subprocess.Popen(
                cmd, cwd=workdir, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, **popen_platform_kwargs(),
            )
            try:
                out_b, err_b = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                kill_tree(proc)
                out_b, err_b = proc.communicate()
                timed_out = True
            code_rc = proc.returncode

        result = {
            "exit_code": code_rc,
            "timed_out": timed_out,
            "duration_sec": round(time.time() - started, 2),
            "stdout": decode_bytes(out_b or b""),
            "stderr": decode_bytes(err_b or b""),
        }
        if timed_out:
            result["error"] = f"command timed out after {timeout}s (use start_job for long-running tasks)"
        return result

    def run_powershell(self, script: str, timeout_sec: int | None = None, workdir: str = "."):
        timeout = self._clamp_timeout(timeout_sec)
        preamble = (
            "$ErrorActionPreference = 'Continue'\n"
            "$ProgressPreference = 'SilentlyContinue'\n"
            "if ($null -ne $PSStyle) { $PSStyle.OutputRendering = 'PlainText' }\n"
        )
        tail = "\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } else { exit 0 }\n"
        fd, script_path = tempfile.mkstemp(prefix="pc_work_pwsh_", suffix=".ps1")
        try:
            with os.fdopen(fd, "w", encoding="utf-8-sig", newline="\r\n") as fh:
                fh.write(preamble)
                fh.write(script)
                fh.write(tail)
            cmd = [self.pwsh_exe, "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-File", script_path]
            return self._exec_process(cmd, workdir, timeout)
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    def run_python(self, code: str, timeout_sec: int | None = None, workdir: str = "."):
        timeout = self._clamp_timeout(timeout_sec)
        fd, script_path = tempfile.mkstemp(prefix="pc_work_py_", suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            cmd = [self.python_exe, "-u", script_path]
            return self._exec_process(cmd, workdir, timeout, env_extra={"PYTHONIOENCODING": "utf-8"})
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    def run_bash(self, script: str, timeout_sec: int | None = None, workdir: str = "."):
        if not self.bash_exe:
            raise ValueError("Git Bash executable not found on this machine")
        timeout = self._clamp_timeout(timeout_sec)
        fd, script_path = tempfile.mkstemp(prefix="pc_work_sh_", suffix=".sh")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(script)
            git_usr_bin = str(Path(self.bash_exe).parent)
            cur_path = os.environ.get("PATH", "")
            env_extra = {
                "PATH": f"{git_usr_bin};{cur_path}" if git_usr_bin not in cur_path else cur_path,
                "LANG": "C.UTF-8",
            }
            cmd = [self.bash_exe, "--noprofile", "--norc", script_path]
            return self._exec_process(cmd, workdir, timeout, env_extra=env_extra)
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# 图像读取与预处理（原生 MCP image block + 可选 Windows OCR）
# ---------------------------------------------------------------------------

def load_image_for_mcp(path_obj: Path, max_dim: int = 1600, quality: int = 85,
                       with_ocr: bool = False, runner: MultiRunner | None = None,
                       ocr_workdir: str | None = None) -> dict:
    p = path_obj
    if not p.is_file():
        raise ValueError(f"image file not found: {p}")

    orig_bytes = p.stat().st_size
    mime_guess, _ = mimetypes.guess_type(str(p))
    mime_guess = mime_guess or "image/jpeg"

    meta = {
        "path": str(p.resolve()),
        "orig_bytes": orig_bytes,
    }

    if HAS_PIL:
        with PilImage.open(p) as im:
            im = PilImageOps.exif_transpose(im)
            orig_w, orig_h = im.size
            meta["orig_size"] = f"{orig_w}x{orig_h}"
            meta["orig_format"] = im.format or p.suffix.lstrip(".").upper()

            if max_dim > 0 and max(orig_w, orig_h) > max_dim:
                scale = max_dim / float(max(orig_w, orig_h))
                new_w = max(1, int(round(orig_w * scale)))
                new_h = max(1, int(round(orig_h * scale)))
                im = im.resize((new_w, new_h), PilImage.Resampling.LANCZOS)
            meta["sent_size"] = f"{im.width}x{im.height}"

            buf = io.BytesIO()
            has_alpha = im.mode in ("RGBA", "LA") or (im.mode == "P" and "transparency" in im.info)
            if has_alpha:
                im.save(buf, format="PNG", optimize=True)
                out_mime = "image/png"
            else:
                if im.mode != "RGB":
                    im = im.convert("RGB")
                im.save(buf, format="JPEG", quality=max(30, min(95, quality)), optimize=True)
                out_mime = "image/jpeg"
            raw_out = buf.getvalue()
    else:
        raw_out = p.read_bytes()
        out_mime = mime_guess if mime_guess.startswith("image/") else "image/jpeg"
        meta["sent_size"] = "original (Pillow unavailable)"

    meta["sent_bytes"] = len(raw_out)
    meta["mime_type"] = out_mime
    b64_data = base64.b64encode(raw_out).decode("ascii")

    if with_ocr and IS_WINDOWS and runner is not None:
        ocr_ps = f"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType = WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime]
function Await($WinRtTask, $ResultType) {{
    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {{ $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.IsGenericMethod }})[0].MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}}
$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync("{str(p.resolve()).replace('"', '`"')}")) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($engine) {{
    $res = Await ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
    Write-Output $res.Text
}}
"""
        wd = ocr_workdir if (ocr_workdir and os.path.isdir(ocr_workdir)) else str(HERE)
        ocr_res = runner.run_powershell(ocr_ps, timeout_sec=30, workdir=wd)
        if ocr_res["exit_code"] == 0 and ocr_res["stdout"].strip():
            meta["ocr_text"] = ocr_res["stdout"].strip()

    return {"b64": b64_data, "mime_type": out_mime, "meta": meta}


# ---------------------------------------------------------------------------
# 投递箱（push_file：生成签名下载链接 + 桌面提醒）
# ---------------------------------------------------------------------------

class OutboxManager:
    def __init__(self, cfg):
        push_cfg = cfg.get("push") or {}
        self.outbox_dir = Path(push_cfg.get("outbox_dir") or (HERE / "outbox"))
        self.outbox_dir.mkdir(parents=True, exist_ok=True)
        self.url_ttl = max(60, int(push_cfg.get("url_ttl_sec", 86400)))
        self.secret = str((cfg.get("auth") or {}).get("token") or secrets.token_hex(16)).encode("utf-8")
        self.state_file = self.outbox_dir / "records.json"
        self.lock = threading.Lock()
        self.records: dict[str, dict] = {}
        self._load_state()

    def _load_state(self):
        if not self.state_file.is_file():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            now = int(time.time())
            valid = {}
            for k, v in (data or {}).items():
                if isinstance(v, dict) and v.get("exp", 0) >= now and os.path.isfile(str(v.get("path") or "")):
                    valid[k] = v
            self.records = valid
        except Exception as exc:
            LOG.warning("failed to load outbox records: %s", exc)

    def _save_state_locked(self):
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.records, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception as exc:
            LOG.warning("failed to save outbox records: %s", exc)

    def _sign(self, file_id: str, exp: int) -> str:
        msg = f"{file_id}:{exp}".encode("utf-8")
        return hmac.new(self.secret, msg, hashlib.sha256).hexdigest()[:32]

    def register(self, src_path: Path, title: str = "", copy_to_outbox: bool = True) -> dict:
        if not src_path.is_file():
            raise ValueError(f"file not found: {src_path}")

        file_id = uuid.uuid4().hex[:16]
        if copy_to_outbox:
            dst = self.outbox_dir / f"{file_id}_{src_path.name}"
            shutil.copy2(src_path, dst)
            target = dst
        else:
            target = src_path.resolve()

        exp = int(time.time()) + self.url_ttl
        sig = self._sign(file_id, exp)
        mime, _ = mimetypes.guess_type(str(target))
        mime = mime or "application/octet-stream"
        rec = {
            "id": file_id,
            "name": src_path.name,
            "title": title or src_path.name,
            "path": str(target),
            "size": target.stat().st_size,
            "mime": mime,
            "exp": exp,
            "sig": sig,
            "created": time.time(),
        }
        with self.lock:
            self._purge_locked()
            self.records[file_id] = rec
            self._save_state_locked()
        return rec

    def resolve(self, file_id: str, exp_str: str, sig: str) -> dict | None:
        try:
            exp = int(exp_str)
        except (TypeError, ValueError):
            return None
        if exp < int(time.time()):
            return None
        expected = self._sign(file_id, exp)
        if not hmac.compare_digest(expected, sig or ""):
            return None
        with self.lock:
            rec = self.records.get(file_id)
        if not rec or not os.path.isfile(rec["path"]):
            return None
        return rec

    def _purge_locked(self):
        now = int(time.time())
        expired = [k for k, v in self.records.items() if v["exp"] < now]
        for k in expired:
            rec = self.records.pop(k, None)
            if rec and str(Path(rec["path"]).parent.resolve()) == str(self.outbox_dir.resolve()):
                try:
                    os.unlink(rec["path"])
                except OSError:
                    pass
        if expired:
            self._save_state_locked()


# ---------------------------------------------------------------------------
# MCP 工具定义（13 项本机工作台核心工具）
# ---------------------------------------------------------------------------

TOOL_DEFS = [
    {
        "name": "powershell",
        "description": "在 Windows 本机执行 PowerShell 脚本（Windows 原生内置可用；默认在配置的工作区内执行，同步默认 60s / 上限 180s；长任务请使用 start_job；缺其余命令工具时可用它安装或引导用户安装）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "要执行的 PowerShell 脚本。"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 180, "description": "同步超时秒数（默认 60，上限 180）。"},
                "cwd": {"type": "string", "description": "工作目录，默认自由工作区。"},
            },
            "required": ["script"],
        },
    },
    {
        "name": "python",
        "description": "使用本机 Python 执行脚本（不假定任何第三方库已预装，以 workspace_status 实际探测及本机环境为准；缺包时可按需引导用户或自行 pip 安装以完成交付；同步默认 60s / 上限 180s）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "要执行的 Python 代码。"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 180, "description": "同步超时秒数（默认 60，上限 180）。"},
                "cwd": {"type": "string", "description": "工作目录，默认自由工作区。"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "bash",
        "description": "使用本机 Bash（如 Git Bash）执行 Shell 脚本（不保证所有用户已预装；若仅 PowerShell 可用，请改用 powershell 或先安装 Bash 工具后再交付；同步默认 60s / 上限 180s）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "要执行的 Bash 脚本。"},
                "timeout_sec": {"type": "integer", "minimum": 1, "maximum": 180, "description": "同步超时秒数（默认 60，上限 180）。"},
                "cwd": {"type": "string", "description": "工作目录，默认自由工作区。"},
            },
            "required": ["script"],
        },
    },
    {
        "name": "start_job",
        "description": "在后台独立进程组异步启动长耗时任务（powershell / python / bash），立即返回 job_id 与日志路径。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "engine": {"type": "string", "enum": ["powershell", "python", "bash"], "description": "执行引擎。"},
                "code": {"type": "string", "description": "要执行的脚本或代码。"},
                "cwd": {"type": "string", "description": "工作目录，默认自由工作区。"},
            },
            "required": ["engine", "code"],
        },
    },
    {
        "name": "get_job_status",
        "description": "非阻塞查询异步作业状态（running / completed / failed / killed）、退出码、耗时与最新日志尾部。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "start_job 返回的作业 ID。"},
                "tail_lines": {"type": "integer", "minimum": 1, "maximum": 500, "description": "返回最新日志行数（默认 50）。"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "kill_job",
        "description": "强制终止异步作业及其整个子进程树（taskkill /F /T），防止孤儿进程残留。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "要终止的作业 ID。"},
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "workspace_status",
        "description": (
            "轻量探活与环境/边界探测工具：返回当前可用执行引擎（powershell/python/bash/pillow）、默认工作区、全局白名单目录（global_whitelist）、"
            "本会话临时信任目录、活跃后台作业、磁盘空间、当前媒体隔离边界声明与自改安全规则。"
            + MEDIA_BOUNDARY_NOTICE + " " + ENV_ADAPT_AND_SAFETY_NOTICE
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "read_image",
        "description": (
            "原生读取本地图片文件，返回 MCP 图像块 + 可选 Windows OCR 文字（支持 /g/ 与 G:\\ 路径；若本机未装 Pillow 则自动透传原图字节）。"
            f"【边界缺陷声明（截至 {BOUNDARY_EFFECTIVE_DATE} 生效）】用户电脑内的图片无法通过 MCP 图像块到达模型层面，会被网关层面丢弃（仅文本与 OCR 可达）；"
            "同理，Gemini 网页端的生图内容也被锁定在沙箱内，无法通过回传方式落盘。"
            "如果你发现调用时 MCP 会塞一个小像素点（或本工具返回的图像块）到眼前，就证明 Google 放开了读的权限；至于能不能写入，还是交由 Agent 判断。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "图片文件路径。"},
                "max_dimension": {"type": "integer", "minimum": 256, "maximum": 4096, "description": "最大边长像素（默认 1600）。"},
                "quality": {"type": "integer", "minimum": 30, "maximum": 95, "description": "JPEG 压缩质量（默认 85）。"},
                "ocr": {"type": "boolean", "description": "是否同时运行 Windows OCR 提取图中文字（默认 true）。"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "read_file",
        "description": "读取 Windows 文本文件内容（自动识别 UTF-8 / UTF-8-SIG / GBK 编码，支持按行号区间分段读取大文件及 /g/ 路径）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "目标文件路径。"},
                "start_line": {"type": "integer", "minimum": 1, "description": "起始行号（从 1 开始，可选）。"},
                "end_line": {"type": "integer", "minimum": 1, "description": "结束行号（含该行，可选）。"},
                "with_line_numbers": {"type": "boolean", "description": "是否在每行前显示行号（默认 false）。"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "write_file",
        "description": "写入或追加内容到 Windows 文件（工作区与全局可写白名单之外触发本地置顶弹窗审批；覆盖前自动生成 .bak 快照；写入后自动执行轻量语法/可选工程检查并结构化回喂）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "目标文件路径。"},
                "content": {"type": "string", "description": "要写入的文本内容。"},
                "mode": {"type": "string", "enum": ["overwrite", "append"], "description": "写入模式：overwrite（覆盖，默认）或 append（追加）。"},
                "encoding": {"type": "string", "description": "文件编码，默认 utf-8（可选 utf-8-sig / gbk）。"},
                "auto_check": {"type": "boolean", "description": "写后是否自动做瞬时语法/配置的检查（默认 true；连续改多个关联文件时可临时设为 false）。"},
                "run_checks": {"type": "boolean", "description": "可选：强制执行或跳过工作区 .gemini/checks.json 与配置中的 lint/test 命令。"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "edit_file",
        "description": "对 Windows 文本文件执行精确字符串查找替换（支持单次 old_text/new_text 或原子多处替换 edits 列表，支持 CRLF/LF 兼容匹配；匹配失败时返回最相近行号提示；修改前自动生成 .bak 快照，全部改完后做一次轻量语法/可选 lint-test 结构化回喂）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "目标文件路径。"},
                "old_text": {"type": "string", "description": "单处替换时的待替换原文本片段（与 edits 二选一）。"},
                "new_text": {"type": "string", "description": "单处替换后的新文本片段（与 edits 二选一）。"},
                "edits": {
                    "type": "array",
                    "description": "可选：同一文件内多处原子替换 [{old_text, new_text, replace_all?}]；全部在内存校验通过后再一次性快照、写盘与校验。",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old_text": {"type": "string", "description": "待替换原文本片段。"},
                            "new_text": {"type": "string", "description": "替换后新文本片段。"},
                            "replace_all": {"type": "boolean", "description": "本项是否替换全部匹配（默认继承顶层 replace_all）。"},
                        },
                        "required": ["old_text", "new_text"],
                    },
                },
                "replace_all": {"type": "boolean", "description": "是否替换所有匹配项（默认 false，仅当唯一匹配时才替换）。"},
                "auto_check": {"type": "boolean", "description": "改后是否自动做瞬时语法/配置的检查（默认 true）。"},
                "run_checks": {"type": "boolean", "description": "可选：强制执行或跳过工作区 .gemini/checks.json 与配置中的 lint/test 命令。"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_dir",
        "description": "列出指定目录下的文件与子文件夹（默认过滤 .git/node_modules/__pycache__/.venv/浏览器配置目录及 workspace.ignored_dirs，支持 /g/ 路径）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "目录路径。"},
                "pattern": {"type": "string", "description": "文件名通配符（如 *.py，默认 *）。"},
                "recursive": {"type": "boolean", "description": "是否递归子目录（默认 false）。"},
                "max_entries": {"type": "integer", "minimum": 1, "maximum": 2000, "description": "最多返回条目数（默认 200）。"},
                "include_ignored": {"type": "boolean", "description": "是否包含默认/配置的忽略目录（默认 false）。"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "find_files",
        "description": "原生只读按文件名/通配符快速检索工作区文件（无需启动 shell，属于 read 权限，默认过滤 .git/node_modules/__pycache__/浏览器配置目录及 workspace.ignored_dirs）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "起始目录或文件路径（默认当前工作区 '.'）。"},
                "pattern": {"type": "string", "description": "通配符（如 '*.py' 或 'tests/*.py'，默认 '*'）。"},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "最多返回数量（默认 200）。"},
                "include_ignored": {"type": "boolean", "description": "是否包含默认/配置的忽略目录（默认 false）。"},
            },
        },
    },
    {
        "name": "grep_search",
        "description": "原生只读全文检索（支持字面子串与正则，无需启动 shell，属于 read 权限；自动跳过二进制、超限大文件及忽略目录）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "要查找的关键词或正则表达式。"},
                "path": {"type": "string", "description": "搜索目录或单文件路径（默认当前工作区 '.'）。"},
                "is_regex": {"type": "boolean", "description": "是否按正则匹配（默认 false）。"},
                "case_sensitive": {"type": "boolean", "description": "是否区分大小写（默认 true）。"},
                "include": {"type": "string", "description": "仅检索匹配该通配符的文件（如 '*.py'）。"},
                "max_matches": {"type": "integer", "minimum": 1, "maximum": 300, "description": "最多返回匹配行数（默认 60）。"},
                "context_lines": {"type": "integer", "minimum": 0, "maximum": 3, "description": "匹配行前后附带的上下文行数（默认 0）。"},
                "include_ignored": {"type": "boolean", "description": "是否包含默认/配置的忽略目录（默认 false）。"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "push_file",
        "description": (
            "将本机已有文件注册到 outbox 并生成带签名校验的临时下载链接（可选本机打开或桌面提醒）。"
            f"注意（截至 {BOUNDARY_EFFECTIVE_DATE}）：虽然本工具可附带 inline_preview 图像块，但云端网关会丢弃 MCP 图像块；"
            "且 Gemini 网页端沙箱内生成的图片无法通过 MCP 回传落盘，本工具仅用于本机已有文件。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "要推送的本地文件路径。"},
                "title": {"type": "string", "description": "展示标题或说明（可选）。"},
                "inline_preview": {"type": "boolean", "description": "若为图片或短文本，是否在 MCP 返回结果中直接内联预览（默认 true）。"},
                "open_on_desktop": {"type": "boolean", "description": "是否在 Windows 本机直接用默认程序打开该文件（默认 false）。"},
                "notify_desktop": {"type": "boolean", "description": "是否在 Windows 右下角弹出系统通知提醒（默认 false）。"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "bridge_status",
        "description": (
            "查看 Tampermonkey 油猴浏览器桥接状态：当前已连接的 Gemini 标签页、实时会话链接 ID（conversation_id）以及异步媒体任务队列。"
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "bridge_upload_media",
        "description": (
            "通过 Tampermonkey 浏览器油猴桥接，异步将本机图片 / 视频 / 音频 / 文档上传到对应 Gemini 会话窗口并等待上传完成后自动点击发送。"
            "支持透传 conversation_id（自动定位或打开该会话）；若在首轮回答完成前调用导致暂无会话 ID，插件会异步等待首轮 ID 生成后再自动绑定执行。"
            "【重要调用规则】本工具必须异步完成：调用本工具后，Agent 必须立即停止当前回合输出，等待插件上传并发送开启下一回合后才能读取媒体内容。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "要上传到对话窗口的本机文件路径列表（1~6 个，支持图片、视频、音频、文档）。",
                },
                "prompt": {"type": "string", "description": "上传完成后附带发送的提示词文本（可选）。"},
                "conversation_id": {"type": "string", "description": "目标会话 ID（可选；留空自动绑定当前活跃或首轮待生成会话）。"},
                "delay_sec": {"type": "integer", "minimum": 1, "maximum": 30, "description": "当前回合停稳后的延时秒数（默认 2 秒）。"},
                "auto_send": {"type": "boolean", "description": "监听到上传完成后是否自动点击发送（默认 true）。"},
                "tool_mode": {
                    "type": "string",
                    "enum": ["none", "image", "video", "music"],
                    "description": "可选：在发送前切换 Gemini `+` 菜单中的制作模式（默认 none）。",
                },
            },
            "required": ["files"],
        },
    },
    {
        "name": "bridge_save_generated_media",
        "description": (
            "通过 Tampermonkey 浏览器油猴桥接，异步将 Gemini 网页端生成的图片 / 视频 / 音乐下载并保存到 Agent 指定的本机目标路径或目录（工作区外会触发本机弹窗审批）。"
            "Agent 只需传入目标路径即可由 MCP 与油猴插件协同完成全链路落盘；可选传 trigger_prompt 与 kind 让插件在停止本回合后自动切换制作模式并等待生成完成后下载。"
            "【重要调用规则】无论是保存刚生成的图，还是触发制作图片/视频/音乐并保存，调用本工具后 Agent 都必须立即停止当前回合输出，交由插件异步完成。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {"type": "string", "description": "本机保存目标目录或完整文件路径。"},
                "kind": {
                    "type": "string",
                    "enum": ["auto", "image", "video", "music"],
                    "description": "目标产物类型（默认 auto）。",
                },
                "trigger_prompt": {"type": "string", "description": "可选：若需由插件在下一轮自动发起制作图片/视频/音乐，传入提示词。"},
                "conversation_id": {"type": "string", "description": "目标会话 ID（可选；留空自动绑定当前或首轮待生成会话）。"},
                "delay_sec": {"type": "integer", "minimum": 1, "maximum": 30, "description": "停稳等待秒数（默认 2 秒）。"},
                "timeout_sec": {"type": "integer", "minimum": 15, "maximum": 600, "description": "插件等待产物就绪的最大秒数（默认 240 秒）。"},
            },
            "required": ["target_path"],
        },
    },
    {
        "name": "bridge_get_task",
        "description": "查询指定 Tampermonkey 桥接异步任务（task_id）的当前状态、已保存文件路径或错误详情。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "bridge_upload_media 或 bridge_save_generated_media 返回的 task_id。"},
            },
            "required": ["task_id"],
        },
    },
    {
        "name": "bridge_suggest_ignore_dirs",
        "description": (
            "向本地油猴桥推送工作区目录屏蔽建议（用于过滤噪音/缓存/历史目录到 workspace.ignored_dirs）。"
            "注意：config.json 受本地安全边界保护，禁止模型直接改写；调用本工具后请在回复正文中列出建议屏蔽的目录及原因并立即停止当前回合，"
            "待你停笔后油猴插件会在页面弹窗，由用户勾选并保存后永久生效。若只是当前对话需要聚焦某个子项目，也可建议用户通过油猴「会话工作区」单独切工作区。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "dirs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "建议加入 workspace.ignored_dirs 的目录名、目录路径或通配符列表（如 ['logs', 'outbox', 'pc-work-mcp-v*']）。",
                },
                "reason": {
                    "type": "string",
                    "description": "简短说明建议屏蔽这些目录的原因（展示在用户确认弹窗中）。",
                },
            },
            "required": ["dirs"],
        },
    },
    {
        "name": "task_plan",
        "description": (
            "轻量持久化任务清单与受控自唤醒续跑工具（应对网页端单轮步数限制，无需用户守候多轮也能逐步完善目标）。"
            "支持 action: set（建/重置计划）、update（更新步骤状态）、get（查看当前进度）、complete（完成收口）、"
            "schedule_continue（通过油猴桥在本回合停稳冷却后自动发下一轮消息唤醒自己继续干活；唤醒提示词会自动内嵌当前与下一步进度，额度仅在实际发送成功后扣减）、stop（停止自唤醒）。"
            "【极简上下文规范】调用 schedule_continue 回调自己时，handoff 必须用极简干练语言只写下一步具体动作、路径与验收点"
            "（建议 ≤120 字，上限 220 字，严禁复述历史上下文或客套话），否则长会话会被无效信息占满；调用 schedule_continue 后请立即结束本回合输出。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["get", "set", "update", "complete", "schedule_continue", "stop"],
                    "description": "操作类型。",
                },
                "goal": {"type": "string", "description": "action=set 时必填：总体目标（简明扼要）。"},
                "steps": {
                    "type": "array",
                    "items": {},
                    "description": "action=set 时必填：步骤列表（字符串或 {title, status, note}，最多 12 步）。",
                },
                "step_updates": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "action=update 时传入：[{id, status, note}]。",
                },
                "status": {
                    "type": "string",
                    "enum": ["active", "paused", "completed", "stopped"],
                    "description": "action=update 时可选更新整体状态。",
                },
                "max_auto_turns": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                    "description": "action=set 时可选：最多连续自唤醒轮数上限（默认 5）。",
                },
                "handoff": {
                    "type": "string",
                    "description": "action=schedule_continue 时必填：极简干练的下一轮自我唤醒指令（建议 ≤120 字，只写下一步动作与验证条件）。",
                },
                "delay_sec": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": 60,
                    "description": "action=schedule_continue 时可选：本轮停稳后的最短冷却秒数（默认 8s，再叠加随机抖动以避开风控）。",
                },
                "note": {"type": "string", "description": "可选简短备注。"},
            },
            "required": ["action"],
        },
    },
]


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def text_result(text: str, is_error: bool = False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def format_exec_output(res: dict, output_guard: OutputGuard) -> dict:
    parts = []
    if res.get("error"):
        parts.append(f"{res['error']} (exit={res['exit_code']}, {res['duration_sec']}s)")
    else:
        parts.append(f"exit_code: {res['exit_code']}  duration: {res['duration_sec']}s")
    if res["stdout"]:
        parts.append("--- stdout ---\n" + res["stdout"]
                     + ("" if res["stdout"].endswith("\n") else "\n"))
    if res["stderr"]:
        parts.append("--- stderr ---\n" + res["stderr"]
                     + ("" if res["stderr"].endswith("\n") else "\n"))
    if not res["stdout"] and not res["stderr"]:
        parts.append("(no output)")
    combined = "\n".join(parts)
    guarded, _ = output_guard.format_or_bypass(combined, prefix="cmd")
    return text_result(guarded, is_error=res["exit_code"] != 0)


def _list_dir_entries(
    root: Path,
    pattern: str,
    recursive: bool,
    max_entries: int,
    include_ignored: bool,
    extra_ignored: list[str] | tuple[str, ...] | set[str] | None = None,
) -> list[str]:
    rows: list[str] = []
    count = 0
    if not recursive:
        with os.scandir(root) as it:
            entries = sorted(it, key=lambda e: e.name.lower())
        for entry in entries:
            if not include_ignored and is_ignored_dir_name(entry.name, extra_ignored):
                continue
            if not fnmatch.fnmatch(entry.name, pattern):
                continue
            if count >= max_entries:
                rows.append(f"... [truncated at {max_entries} entries]")
                break
            is_dir = entry.is_dir(follow_symlinks=False)
            kind = "DIR " if is_dir else "FILE"
            size = entry.stat(follow_symlinks=False).st_size if not is_dir else 0
            rows.append(f"{kind}  {size:>10}  {entry.name}")
            count += 1
        return rows

    for dirpath, dirnames, filenames in os.walk(root):
        if not include_ignored:
            dirnames[:] = sorted(d for d in dirnames if not is_ignored_dir_name(d, extra_ignored))
        else:
            dirnames.sort()
        rel_dir = Path(dirpath).relative_to(root)
        for d in dirnames:
            if not fnmatch.fnmatch(d, pattern):
                continue
            if count >= max_entries:
                rows.append(f"... [truncated at {max_entries} entries]")
                return rows
            rel = d if str(rel_dir) == "." else str(rel_dir / d)
            rows.append(f"DIR   {0:>10}  {rel}")
            count += 1
        for f in sorted(filenames):
            if not fnmatch.fnmatch(f, pattern):
                continue
            if count >= max_entries:
                rows.append(f"... [truncated at {max_entries} entries]")
                return rows
            full_f = Path(dirpath) / f
            try:
                size = full_f.stat().st_size
            except OSError:
                size = 0
            rel = f if str(rel_dir) == "." else str(rel_dir / f)
            rows.append(f"FILE  {size:>10}  {rel}")
            count += 1
    return rows


def _suggest_closest_lines(text: str, needle: str, limit: int = 3) -> list[str]:
    """Return top closest line hints (`L<n>: <snippet>`) when edit_file fails to match."""
    non_empty = [ln.strip() for ln in needle.splitlines() if ln.strip()]
    if not non_empty:
        return []
    anchor = non_empty[0]
    if len(anchor) < 12 and len(non_empty) > 1:
        anchor = max(non_empty[:4], key=len)
    anchor_cmp = anchor[:160]
    lines = text.splitlines()
    many_lines = len(lines) > 1500
    scored: list[tuple[float, int, str]] = []
    for idx, raw_line in enumerate(lines, start=1):
        cand = raw_line.strip()
        if not cand:
            continue
        cand_cmp = cand[:160]
        sm = difflib.SequenceMatcher(None, anchor_cmp, cand_cmp)
        if many_lines and sm.quick_ratio() < 0.45:
            continue
        score = sm.ratio()
        if anchor_cmp in cand_cmp or (len(cand_cmp) >= 6 and cand_cmp in anchor_cmp):
            score = max(score, 0.72)
        if score >= 0.45:
            snippet = cand[:80] + ("..." if len(cand) > 80 else "")
            scored.append((score, idx, snippet))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [f"L{idx}: {snippet}" for _, idx, snippet in scored[:limit]]


class McpCore:
    def __init__(self, cfg, approval_cb=None, config_path: Path | str | None = None):
        self.cfg = cfg
        self.runner = MultiRunner(cfg)
        self.outbox = OutboxManager(cfg)
        self.config_path = Path(config_path) if config_path else (HERE / "config.json")
        cfg_base = self.config_path.resolve(strict=False).parent
        log_file = Path((cfg.get("log") or {}).get("file") or (cfg_base / "logs" / "server.log"))
        oauth_state_file = Path((cfg.get("oauth") or {}).get("state_file") or (log_file.parent / "oauth_state.json"))
        perm_store_cfg = str((cfg.get("permissions") or {}).get("store_file") or "").strip()
        perm_store_file = Path(perm_store_cfg) if perm_store_cfg else (log_file.parent / "bridge_permissions.json")
        rules_store_file = log_file.parent / "bridge_rules.json"
        ws_store_file = log_file.parent / "bridge_workspaces.json"
        task_plan_store_file = log_file.parent / "task_plans.json"
        self.guard = WorkspaceBoundaryGuard(
            cfg, cfg_base, approval_cb=approval_cb,
            protected_write_files=[
                self.config_path, oauth_state_file, perm_store_file,
                rules_store_file, ws_store_file, task_plan_store_file,
            ],
        )
        ws = cfg.get("workspace") or {}
        snap_cfg = ws.get("snapshot") or {}
        self._snap_enabled = bool(snap_cfg.get("enabled", True))
        self._snap_max_versions = int(snap_cfg.get("max_versions_per_file", 20))
        self.snapshots = SnapshotManager(
            self.guard.default_dir / ".mcp_snapshots",
            enabled=self._snap_enabled,
            max_versions=self._snap_max_versions,
        )
        self._max_inline_chars = int((cfg.get("exec") or {}).get("max_inline_chars", 16000))
        self.output_guard = OutputGuard(
            self.guard.default_dir / ".tmp_outputs",
            max_inline_chars=self._max_inline_chars,
        )
        self._snapshot_cache: dict[str, SnapshotManager] = {
            os.path.normcase(str(self.guard.default_dir)): self.snapshots,
        }
        self._output_guard_cache: dict[str, OutputGuard] = {
            os.path.normcase(str(self.guard.default_dir)): self.output_guard,
        }
        self.jobs = JobManager(self.guard.default_dir / ".tmp_outputs", self.output_guard)
        self.checker = PostEditChecker(cfg, self.runner)
        self.permissions = ConversationPermissionManager(cfg, perm_store_file)
        self.workspaces = WorkspaceBindingManager(
            self.guard.default_dir,
            store_path=ws_store_file,
            blocked_prefixes=self.guard.blocked_read_prefixes,
            folder_picker=_pick_folder_winforms if IS_WINDOWS else None,
        )
        self.rules = WorkspaceRulesManager(
            cfg,
            self.guard.default_dir,
            store_path=rules_store_file,
            blocked_prefixes=self.guard.blocked_read_prefixes,
        )
        self.task_plans = TaskPlanManager(task_plan_store_file, cfg)
        self.bridge = BridgeManager(
            snapshot_mgr=self.snapshots,
            permission_mgr=self.permissions,
            rules_mgr=self.rules,
            workspace_mgr=self.workspaces,
            task_plan_mgr=self.task_plans,
        )
        self.started = time.time()
        self.stats = {"requests": 0, "tool_calls": {}}
        self.lock = threading.Lock()

    def persist_config_mutation(self, mutator) -> dict:
        cfg_path = Path(self.config_path)
        if not cfg_path.is_file():
            return self.cfg
        updated = _sync_config_file(cfg_path, mutator)
        ws_dir_str = str((updated.get("workspace") or {}).get("default_dir") or "").strip()
        for ws_cfg in _resolve_synced_config_paths(cfg_path, ws_dir_str):
            _sync_config_file(ws_cfg, mutator)
        return updated

    def persist_global_whitelist(self) -> list[dict]:
        entries = self.guard.export_whitelist_config()
        self.cfg.setdefault("workspace", {})["extra_allowed_dirs"] = entries

        def update_wl(obj: dict):
            obj.setdefault("workspace", {})["extra_allowed_dirs"] = entries

        self.persist_config_mutation(update_wl)
        return self.guard.get_global_whitelist()

    def _snapshot_mgr_for(self, active_ws: Path) -> SnapshotManager:
        key = os.path.normcase(str(active_ws))
        with self.lock:
            mgr = self._snapshot_cache.get(key)
            if mgr is None:
                mgr = SnapshotManager(
                    active_ws / ".mcp_snapshots",
                    enabled=self._snap_enabled,
                    max_versions=self._snap_max_versions,
                )
                self._snapshot_cache[key] = mgr
            return mgr

    def _output_guard_for(self, active_ws: Path) -> OutputGuard:
        key = os.path.normcase(str(active_ws))
        with self.lock:
            og = self._output_guard_cache.get(key)
            if og is None:
                og = OutputGuard(
                    active_ws / ".tmp_outputs",
                    max_inline_chars=self._max_inline_chars,
                )
                self._output_guard_cache[key] = og
            return og

    def _effective_ignored_dirs(self) -> list[str]:
        raw = (self.cfg.get("workspace") or {}).get("ignored_dirs") or []
        return [str(x).strip() for x in raw if str(x).strip()]

    def get_ignored_dirs_snapshot(self) -> dict:
        return {
            "ok": True,
            "default_ignored": sorted(DEFAULT_IGNORED_DIRS),
            "ignored_dirs": self._effective_ignored_dirs(),
            "default_workspace": str(self.guard.default_dir),
        }

    def persist_ignored_dirs(self, entries: list[str]) -> list[str]:
        clean: list[str] = []
        seen: set[str] = set()
        for raw in entries or ():
            norm = normalize_ignore_entry(raw)
            if not norm or norm in DEFAULT_IGNORED_DIRS:
                continue
            key = norm.lower()
            if key in seen:
                continue
            seen.add(key)
            clean.append(norm)
        self.cfg.setdefault("workspace", {})["ignored_dirs"] = list(clean)

        def update_ign(obj: dict):
            obj.setdefault("workspace", {})["ignored_dirs"] = list(clean)

        self.persist_config_mutation(update_ign)
        return clean

    def add_ignored_dirs(self, entries: list[str]) -> list[str]:
        cur = self._effective_ignored_dirs()
        return self.persist_ignored_dirs(cur + list(entries or ()))

    def remove_ignored_dir(self, target: str) -> list[str]:
        norm = normalize_ignore_entry(target)
        key = norm.lower() if norm else str(target or "").strip().lower()
        cur = [x for x in self._effective_ignored_dirs() if x.lower() != key]
        return self.persist_ignored_dirs(cur)

    def _public_base(self) -> str:
        base = str((self.cfg.get("oauth") or {}).get("public_base_url") or "").rstrip("/")
        if base:
            return base
        host = str((self.cfg.get("listen") or {}).get("host") or "127.0.0.1")
        port = int((self.cfg.get("listen") or {}).get("port") or 15672)
        if host == "0.0.0.0":
            host = "127.0.0.1"
        return f"http://{host}:{port}"

    def handle(self, method: str, params: dict | None, mcp_session_id: str | None = None):
        params = params or {}
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
            return {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": (
                    "Windows workstation MCP server providing powershell, python, bash execution, "
                    "async job management (start_job/get_job_status/kill_job), workspace_status, "
                    "native image reading (read_image), file & read-only search operations "
                    "(read_file/write_file/edit_file/list_dir/find_files/grep_search) "
                    "with three-zone boundary protection, pre-write snapshots, and automatic post-edit verification feedback, "
                    "signed URL delivery (push_file), persistent task plan & bounded self-wake (task_plan), "
                    "and Tampermonkey browser bridge tools (bridge_status/bridge_upload_media/bridge_save_generated_media/bridge_get_task). "
                    "【检索与改写效率】查找文件或全文检索优先用只读工具 find_files / grep_search（无需消耗 exec 权限）；"
                    "write_file / edit_file 会自动执行轻量语法及配置的 lint/test 校验并结构化回喂，请直接依据反馈修复；"
                    "同一文件需改多处时优先用 edit_file(edits=[...]) 一次原子替换以节省步数。"
                    "【长任务自主续跑约束】多步任务可用 task_plan 跟踪进度；若受单回合步数限制仍未收口且连接了油猴桥，"
                    "可调用 task_plan(action='schedule_continue', handoff=...) 后立即停笔等待唤醒（唤醒消息已内嵌当前与下一步进度，无需再调 task_plan(get)）。"
                    "每次回调的 handoff 必须极简干练（只写下一步动作、文件路径与验收条件，≤120 字，严禁复述历史），避免长会话上下文膨胀。"
                    "【油猴桥接调用协议】若已连接浏览器油猴插件（可用 bridge_status 确认），需要读图/读视频请调 bridge_upload_media，"
                    "需要把网页生成图片/视频/音乐落盘到本机请调 bridge_save_generated_media；"
                    "两者均为异步链路，调用后 Agent 必须立即停止当前回合输出，交由插件完成上传/发送或下载落盘。"
                    "【会话权限边界】当油猴本地桥在线时，各对话窗口权限按会话网页链接独立受控，完全由用户在本地桥面板掌控，不由会话内 Agent 或 Google 掌管。"
                    "【全局白名单目录】用户可在本地桥维护全局白名单（可通过 workspace_status 的 global_whitelist 查看）；白名单内目录在所有未「禁止」的会话中按其权限（readwrite 自由读写 / readonly 仅只读）直接免审批放行，无需每轮单独向用户确认。"
                    "【目录噪音治理与工作区分离】当 list_dir / find_files / grep_search 命中过多杂项或觉得根目录太乱时，可提醒用户通过油猴「会话工作区」将当前对话切到干净子目录（本架构原生支持按会话隔离工作区），"
                    "或把噪音目录加入 workspace.ignored_dirs：因 config.json 受本地安全边界保护禁止模型直接改写（若你所在环境确有显式权限才可另行配置），标准做法是调用 bridge_suggest_ignore_dirs(dirs=[...], reason=...) "
                    "并在正文中写明建议屏蔽的目录名/路径后立即停止当前回合输出，待你停笔后油猴插件会在页面弹窗由用户一键保存并永久生效。"
                    "【动态工作区规则注入】若工作区存在规则文档（AGENTS.md / GEMINI.md / .gemini/rules/*.md），"
                    "服务端会在会话首次调用任意工具、规则文件发生变动、或达到重锚阈值（默认每 20 步调用或累计 96,000 字符工具输出）时，"
                    "自动在工具返回末尾附带 <workspace_rules> 块；收到后请将其视为当前工作区的权威约束执行。 "
                    + MEDIA_BOUNDARY_NOTICE + " " + ENV_ADAPT_AND_SAFETY_NOTICE
                ),
            }
        if method == "ping":
            return {}
        if method in ("notifications/initialized", "notifications/cancelled",
                      "notifications/roots/list_changed"):
            return None
        if method == "tools/list":
            return {"tools": TOOL_DEFS}
        if method == "tools/call":
            return self._call_tool(params, mcp_session_id=mcp_session_id)
        if method in ("resources/list", "resources/templates/list"):
            return {"resources": [], "resourceTemplates": []}
        if method in ("prompts/list",):
            return {"prompts": []}
        if method == "logging/setLevel":
            return {}
        if method == "completion/complete":
            return {"completion": {"values": [], "total": 0, "hasMore": False}}
        raise JsonRpcError(-32601, f"Method not found: {method}")

    def _call_tool(self, params, mcp_session_id: str | None = None):
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise JsonRpcError(-32602, "arguments must be an object")

        with self.lock:
            self.stats["tool_calls"][name] = self.stats["tool_calls"].get(name, 0) + 1

        try:
            auth_info = self.permissions.authorize_tool(
                name, args, self.bridge,
                guard=self.guard, workspace_mgr=self.workspaces,
            )
            session_key = self.rules.resolve_session_key(auth_info, mcp_session_id)
            active_ws = self.workspaces.resolve_active_dir(auth_info)
            result = self._execute_tool(
                name, args, auth_info=auth_info, session_key=session_key, active_ws=active_ws,
            )
        except PermissionDeniedByUser as exc:
            return text_result(str(exc), is_error=True)
        except ValueError as exc:
            raise JsonRpcError(-32602, str(exc))

        if isinstance(result, dict) and isinstance(result.get("content"), list):
            output_chars = sum(
                len(item.get("text") or "")
                for item in result["content"]
                if isinstance(item, dict) and item.get("type") == "text"
            )
            inj = self.rules.maybe_build_injection(
                session_key=session_key,
                cid=auth_info.get("conversation_id"),
                tab_id=auth_info.get("tab_id"),
                output_chars=output_chars,
                default_rules_dir=active_ws,
            )
            if inj:
                result = dict(result)
                content_list = list(result["content"])
                last_text_idx = None
                for idx in range(len(content_list) - 1, -1, -1):
                    item = content_list[idx]
                    if isinstance(item, dict) and item.get("type") == "text":
                        last_text_idx = idx
                        break
                if last_text_idx is not None:
                    merged_item = dict(content_list[last_text_idx])
                    base_text = merged_item.get("text") or ""
                    merged_item["text"] = f"{base_text}\n\n{inj['text']}" if base_text else inj["text"]
                    content_list[last_text_idx] = merged_item
                else:
                    content_list.append({"type": "text", "text": inj["text"]})
                result["content"] = content_list
        return result

    def _execute_tool(self, name: str, args: dict, *, auth_info: dict, session_key: str, active_ws: Path):
            out_guard = self._output_guard_for(active_ws)
            snap_mgr = self._snapshot_mgr_for(active_ws)

            if name == "powershell":
                script = args.get("script")
                if not isinstance(script, str) or not script.strip():
                    raise ValueError("script is required")
                workdir = self.guard.check_exec("powershell", script, args.get("cwd"), active_workspace=active_ws)
                res = self.runner.run_powershell(script, args.get("timeout_sec"), str(workdir))
                return format_exec_output(res, out_guard)

            if name == "python":
                code = args.get("code")
                if not isinstance(code, str) or not code.strip():
                    raise ValueError("code is required")
                workdir = self.guard.check_exec("python", code, args.get("cwd"), active_workspace=active_ws)
                res = self.runner.run_python(code, args.get("timeout_sec"), str(workdir))
                return format_exec_output(res, out_guard)

            if name == "bash":
                script = args.get("script")
                if not isinstance(script, str) or not script.strip():
                    raise ValueError("script is required")
                workdir = self.guard.check_exec("bash", script, args.get("cwd"), active_workspace=active_ws)
                res = self.runner.run_bash(script, args.get("timeout_sec"), str(workdir))
                return format_exec_output(res, out_guard)

            if name == "start_job":
                engine = args.get("engine")
                code = args.get("code")
                if not isinstance(engine, str) or not engine.strip():
                    raise ValueError("engine is required")
                if not isinstance(code, str) or not code.strip():
                    raise ValueError("code is required")
                workdir = self.guard.check_exec(f"start_job:{engine}", code, args.get("cwd"), active_workspace=active_ws)
                if not workdir.is_dir():
                    raise ValueError(f"cwd does not exist: {workdir}")
                info = self.jobs.start_job(
                    engine, code, str(workdir), self.runner,
                    tmp_outputs_dir=active_ws / ".tmp_outputs",
                    output_guard=out_guard,
                )
                return text_result(json.dumps(info, ensure_ascii=False, indent=2))

            if name == "get_job_status":
                job_id = args.get("job_id")
                if not isinstance(job_id, str) or not job_id.strip():
                    raise ValueError("job_id is required")
                info = self.jobs.get_status(job_id.strip(), tail_lines=int(args.get("tail_lines") or 50))
                return text_result(json.dumps(info, ensure_ascii=False, indent=2))

            if name == "kill_job":
                job_id = args.get("job_id")
                if not isinstance(job_id, str) or not job_id.strip():
                    raise ValueError("job_id is required")
                info = self.jobs.kill_job(job_id.strip())
                return text_result(json.dumps(info, ensure_ascii=False, indent=2))

            if name == "workspace_status":
                ws_dir = active_ws
                _, eff_gdirs = self.guard._green_dirs_for(active_ws)
                ws_binding = self.workspaces.get_effective_workspace(
                    cid=auth_info.get("conversation_id"),
                    tab_id=auth_info.get("tab_id"),
                )
                disk_target = ws_dir if ws_dir.exists() else HERE
                usage = shutil.disk_usage(disk_target)
                canary_enabled = bool((self.cfg.get("vision") or {}).get("canary_pixel", True))
                status = {
                    "server": SERVER_NAME,
                    "version": SERVER_VERSION,
                    "uptime_sec": round(time.time() - self.started, 1),
                    "default_workspace": str(ws_dir),
                    "server_default_workspace": str(self.guard.default_dir),
                    "workspace_binding": {
                        "is_switched": bool(ws_binding.get("is_custom")),
                        "scope": ws_binding.get("scope", "default"),
                        "label": ws_binding.get("label", ""),
                        "conversation_id": auth_info.get("conversation_id"),
                        "tab_id": auth_info.get("tab_id"),
                    },
                    "extra_allowed_dirs": [str(p) for p in eff_gdirs[1:]],
                    "global_whitelist": self.guard.get_global_whitelist(),
                    "ignored_dirs": self._effective_ignored_dirs(),
                    "session_trusted_dirs": self.guard.get_session_trusted(),
                    "active_jobs": self.jobs.list_active(),
                    "disk_free_gb": round(usage.free / (1024 ** 3), 2),
                    "disk_total_gb": round(usage.total / (1024 ** 3), 2),
                    "engines": {
                        "powershell": self.runner.pwsh_exe or None,
                        "python": self.runner.python_exe or None,
                        "bash": self.runner.bash_exe or None,
                        "pillow_installed": HAS_PIL,
                    },
                    "permission_mode": {
                        "mode": (
                            "per_conversation_bridge"
                            if (self.permissions.enabled and len(self.bridge.status_snapshot()["tabs"]) > 0)
                            else "fallback_default"
                        ),
                        "per_conversation_enabled": self.permissions.enabled,
                        "connected_bridge_tabs": len(self.bridge.status_snapshot()["tabs"]),
                        "new_conversation_default_profile": self.permissions.default_profile,
                        "controlled_by": "local_user_via_tampermonkey_bridge_only (not agent or Google)",
                        "recommendation": (
                            ""
                            if len(self.bridge.status_snapshot()["tabs"]) > 0
                            else "当前未连接油猴插件，使用默认工作区兜底权限；建议搭配 Tampermonkey 油猴脚本实现按会话网页链接细化权限控制。"
                        ),
                    },
                    "workspace_rules": self.rules.peek_status(
                        session_key=session_key,
                        cid=auth_info.get("conversation_id"),
                        tab_id=auth_info.get("tab_id"),
                        default_rules_dir=active_ws,
                    ),
                    "task_plan": self.task_plans.get_plan(
                        cid=auth_info.get("conversation_id"),
                        tab_id=auth_info.get("tab_id"),
                    ).get("plan"),
                    "boundary_notice": {
                        "effective_as_of": BOUNDARY_EFFECTIVE_DATE,
                        "gemini_web_sandbox_export": "blocked (Gemini网页端的生图内容被锁定在沙箱内，无法通过回传的方式落盘)",
                        "mcp_image_to_model": "dropped_by_gateway (用户电脑内的图片无法通过MCP到达模型层面，会被网关层面丢弃)",
                        "canary_pixel_attached": canary_enabled,
                        "relaxation_rule": "如果你发现调用时mcp会塞一个小像素点到眼前，就证明Google放开了读的权限。至于能不能写入，还是交由agent判断。",
                    },
                    "self_modification_rule": (
                        "严禁直接修改当前正在运行并被调用的 MCP 入口与工具定义（避免工具失效）；"
                        "如需定制运行提示词或改造代码，请在工作区内新建独立版本文件夹后修改并提示用户切换。"
                    ),
                }
                content = [{"type": "text", "text": json.dumps(status, ensure_ascii=False, indent=2)}]
                if canary_enabled:
                    content.append({
                        "type": "image",
                        "data": CANARY_PIXEL_PNG_B64,
                        "mimeType": "image/png",
                    })
                return {"content": content, "isError": False}

            if name == "read_image":
                path_str = args.get("path")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                target = self.guard.check_read("read_image", path_str, active_workspace=active_ws)
                vcfg = self.cfg.get("vision") or {}
                max_dim = int(args.get("max_dimension") or vcfg.get("max_dimension", 1600))
                quality = int(args.get("quality") or vcfg.get("jpeg_quality", 85))
                with_ocr = bool(args.get("ocr", True))
                img = load_image_for_mcp(
                    target, max_dim=max_dim, quality=quality,
                    with_ocr=with_ocr, runner=self.runner,
                    ocr_workdir=str(active_ws if active_ws.is_dir() else HERE),
                )
                meta_text = json.dumps(img["meta"], ensure_ascii=False, indent=2)
                return {
                    "content": [
                        {"type": "image", "data": img["b64"], "mimeType": img["mime_type"]},
                        {"type": "text", "text": meta_text},
                    ],
                    "isError": False,
                }

            if name == "read_file":
                path_str = args.get("path")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                p = self.guard.check_read("read_file", path_str, active_workspace=active_ws)
                if not p.is_file():
                    raise ValueError(f"file not found: {p}")
                text, enc = read_text_auto(p)
                lines = text.splitlines()
                total_lines = len(lines)
                start = max(1, int(args.get("start_line") or 1))
                end = min(total_lines, int(args.get("end_line") or total_lines)) if total_lines > 0 else 0
                selected = lines[start - 1:end] if total_lines > 0 and start <= end else []
                if args.get("with_line_numbers"):
                    body = "\n".join(f"{idx}: {ln}" for idx, ln in enumerate(selected, start=start))
                else:
                    body = "\n".join(selected)
                header = f"[path: {p} | encoding: {enc} | lines: {start}-{end}/{total_lines}]\n"
                if len(body) > out_guard.max_inline_chars:
                    half_cap = max(200, (out_guard.max_inline_chars - 200) // 2)
                    h_len = min(out_guard.head_chars, half_cap)
                    t_len = min(out_guard.tail_chars, half_cap)
                    if h_len + t_len < len(body):
                        head = body[:h_len]
                        tail = body[-t_len:]
                        middle = body[h_len:len(body) - t_len]
                        omitted_lines = middle.count("\n")
                        omitted_chars = len(middle)
                        head_end_line = start + head.count("\n")
                        tail_start_line = max(head_end_line, end - tail.count("\n"))
                        body = (
                            f"{head}\n\n"
                            f"... [内容共 {len(body)} 字符，超出 {out_guard.max_inline_chars} 字符上限；"
                            f"已省略中间约 {omitted_lines} 行（约第 {head_end_line}~{tail_start_line} 行，{omitted_chars} 字符）。"
                            f"原文件已在磁盘上，无需额外落盘；请直接对原路径 {p} 调用 "
                            f"read_file(start_line={head_end_line}, end_line={tail_start_line}) 分段读取] ...\n\n"
                            f"{tail}"
                        )
                return text_result(header + body)

            if name == "write_file":
                path_str = args.get("path")
                content = args.get("content")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                if not isinstance(content, str):
                    raise ValueError("content must be a string")
                mode = str(args.get("mode") or "overwrite").lower()
                enc = str(args.get("encoding") or "utf-8")
                p = self.guard.check_write("write_file", path_str, f"mode={mode}, chars={len(content)}", active_workspace=active_ws)
                snap_path = snap_mgr.backup(p) if mode == "overwrite" else None
                p.parent.mkdir(parents=True, exist_ok=True)
                file_mode = "a" if mode == "append" else "w"
                with open(p, file_mode, encoding=enc, newline="") as fh:
                    fh.write(content)
                msg = f"OK: {mode} {len(content)} chars -> {p} ({enc})"
                if snap_path:
                    msg += f" | snapshot: {snap_path}"
                allow_ws_cmds = (
                    "exec" in (auth_info.get("capabilities") or ())
                    or auth_info.get("mode") in ("disabled", "fallback_default")
                )
                ver = self.checker.run_for_file(
                    p,
                    active_ws=active_ws,
                    allow_workspace_commands=allow_ws_cmds,
                    run_checks=args.get("run_checks") if isinstance(args.get("run_checks"), bool) else None,
                    auto_check=bool(args.get("auto_check", True)),
                    output_guard=out_guard,
                )
                if ver is not None:
                    if ver.get("ok"):
                        msg += "\n" + json.dumps({"verification": ver}, ensure_ascii=False)
                    else:
                        msg += "\n【写后校验未通过，请直接依据结构化结果修复】\n" + json.dumps(
                            {"verification": ver}, ensure_ascii=False, indent=2
                        )
                return text_result(msg)

            if name == "edit_file":
                path_str = args.get("path")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                raw_edits = args.get("edits")
                default_replace_all = bool(args.get("replace_all", False))
                ops: list[tuple[str, str, bool]] = []
                if raw_edits is not None:
                    if args.get("old_text") is not None or args.get("new_text") is not None:
                        raise ValueError("pass either (old_text, new_text) or edits, not both")
                    if not isinstance(raw_edits, list) or not raw_edits:
                        raise ValueError("edits must be a non-empty array of {old_text, new_text}")
                    for idx, item in enumerate(raw_edits, start=1):
                        if not isinstance(item, dict):
                            raise ValueError(f"edits[{idx}] must be an object")
                        op_old = item.get("old_text")
                        op_new = item.get("new_text")
                        if not isinstance(op_old, str) or op_old == "":
                            raise ValueError(f"edits[{idx}].old_text must be a non-empty string")
                        if not isinstance(op_new, str):
                            raise ValueError(f"edits[{idx}].new_text must be a string")
                        op_ra = bool(item.get("replace_all", default_replace_all))
                        ops.append((op_old, op_new, op_ra))
                else:
                    old_text = args.get("old_text")
                    new_text = args.get("new_text")
                    if not isinstance(old_text, str) or old_text == "":
                        raise ValueError("old_text must be a non-empty string")
                    if not isinstance(new_text, str):
                        raise ValueError("new_text must be a string")
                    ops.append((old_text, new_text, default_replace_all))

                total_old = sum(len(o) for o, _, _ in ops)
                total_new = sum(len(n) for _, n, _ in ops)
                p = self.guard.check_write(
                    "edit_file", path_str,
                    f"edits={len(ops)}, replace_all={default_replace_all}, old_chars={total_old}, new_chars={total_new}",
                    active_workspace=active_ws,
                )
                if not p.is_file():
                    raise ValueError(f"file not found: {p}")
                text, enc = read_text_auto(p)
                had_crlf = "\r\n" in text
                working = text
                used_eol_norm = False
                total_replaced = 0

                for idx, (op_old, op_new, op_ra) in enumerate(ops, start=1):
                    prefix = f"edit #{idx}/{len(ops)}: " if len(ops) > 1 else ""
                    count = working.count(op_old)
                    if count == 0:
                        norm_text = working.replace("\r\n", "\n")
                        norm_old = op_old.replace("\r\n", "\n")
                        norm_new = op_new.replace("\r\n", "\n")
                        count = norm_text.count(norm_old)
                        if count == 0:
                            hints = _suggest_closest_lines(working, op_old, limit=3)
                            hint_str = f"; closest lines: {', '.join(hints)}" if hints else ""
                            raise ValueError(f"{prefix}old_text not found in file{hint_str}")
                        if count > 1 and not op_ra:
                            raise ValueError(
                                f"{prefix}old_text matched {count} times; set replace_all=true or provide more context"
                            )
                        working = norm_text.replace(norm_old, norm_new) if op_ra else norm_text.replace(norm_old, norm_new, 1)
                        if had_crlf:
                            working = working.replace("\n", "\r\n")
                        used_eol_norm = True
                    else:
                        if count > 1 and not op_ra:
                            raise ValueError(
                                f"{prefix}old_text matched {count} times; set replace_all=true or provide more context"
                            )
                        working = working.replace(op_old, op_new) if op_ra else working.replace(op_old, op_new, 1)
                    total_replaced += count if op_ra else 1

                snap_path = snap_mgr.backup(p)
                with open(p, "w", encoding=enc, newline="") as fh:
                    fh.write(working)
                if len(ops) == 1:
                    msg = f"OK: replaced {total_replaced} occurrence(s) in {p}"
                else:
                    msg = f"OK: applied {len(ops)} edit(s), replaced {total_replaced} occurrence(s) in {p}"
                if used_eol_norm:
                    msg += " (EOL-normalized)"
                if snap_path:
                    msg += f" | snapshot: {snap_path}"
                allow_ws_cmds = (
                    "exec" in (auth_info.get("capabilities") or ())
                    or auth_info.get("mode") in ("disabled", "fallback_default")
                )
                ver = self.checker.run_for_file(
                    p,
                    active_ws=active_ws,
                    allow_workspace_commands=allow_ws_cmds,
                    run_checks=args.get("run_checks") if isinstance(args.get("run_checks"), bool) else None,
                    auto_check=bool(args.get("auto_check", True)),
                    output_guard=out_guard,
                )
                if ver is not None:
                    if ver.get("ok"):
                        msg += "\n" + json.dumps({"verification": ver}, ensure_ascii=False)
                    else:
                        msg += "\n【改后校验未通过，请直接依据结构化结果修复】\n" + json.dumps(
                            {"verification": ver}, ensure_ascii=False, indent=2
                        )
                return text_result(msg)

            if name == "list_dir":
                path_str = args.get("path")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                p = self.guard.check_read("list_dir", path_str, active_workspace=active_ws)
                if not p.is_dir():
                    raise ValueError(f"directory not found: {p}")
                pattern = str(args.get("pattern") or "*")
                recursive = bool(args.get("recursive", False))
                max_entries = max(1, min(int(args.get("max_entries") or 200), 2000))
                include_ignored = bool(args.get("include_ignored", False))
                rows = _list_dir_entries(
                    p, pattern, recursive, max_entries, include_ignored,
                    extra_ignored=self._effective_ignored_dirs(),
                )
                raw_body = "\n".join(rows) if rows else "(empty directory)"
                guarded, _ = out_guard.format_or_bypass(raw_body, prefix="list")
                if len(rows) >= 80 or (rows and rows[-1].startswith("... [truncated")):
                    guarded += (
                        "\n[提示: 当前目录条目较多；若觉得工作区杂乱，可建议用户通过油猴「会话工作区」切到干净子目录，"
                        "或调用 bridge_suggest_ignore_dirs 推送要屏蔽的目录并在正文中写明路径后停笔，待停止后由油猴弹窗让用户永久保存。]"
                    )
                return text_result(guarded)

            if name == "find_files":
                raw_path = str(args.get("path") or ".").strip() or "."
                p = self.guard.check_read("find_files", raw_path, active_workspace=active_ws)
                res = search_find_files(
                    p,
                    base_dir=active_ws,
                    pattern=str(args.get("pattern") or "*"),
                    max_results=int(args.get("max_results") or 200),
                    include_ignored=bool(args.get("include_ignored", False)),
                    extra_ignored=self._effective_ignored_dirs(),
                )
                guarded, _ = out_guard.format_or_bypass(res["text"], prefix="find")
                if res.get("truncated") or int(res.get("count") or 0) >= 80:
                    guarded += (
                        "\n[提示: 检索命中较多；若包含噪音/历史/缓存目录，可建议用户通过油猴「会话工作区」隔离目录，"
                        "或调用 bridge_suggest_ignore_dirs 推送屏蔽建议并在正文中写明目录后停笔，由用户弹窗永久保存。]"
                    )
                return text_result(guarded)

            if name == "grep_search":
                query = args.get("query")
                if not isinstance(query, str) or not query:
                    raise ValueError("query is required")
                raw_path = str(args.get("path") or ".").strip() or "."
                p = self.guard.check_read("grep_search", raw_path, active_workspace=active_ws)
                res = search_grep(
                    p,
                    query,
                    base_dir=active_ws,
                    is_regex=bool(args.get("is_regex", False)),
                    case_sensitive=bool(args.get("case_sensitive", True)),
                    include=str(args.get("include") or ""),
                    max_matches=int(args.get("max_matches") or 60),
                    context_lines=int(args.get("context_lines") or 0),
                    include_ignored=bool(args.get("include_ignored", False)),
                    extra_ignored=self._effective_ignored_dirs(),
                )
                guarded, _ = out_guard.format_or_bypass(res["text"], prefix="grep")
                return text_result(guarded)

            if name == "push_file":
                path_str = args.get("path")
                if not isinstance(path_str, str) or not path_str.strip():
                    raise ValueError("path is required")
                src_path = self.guard.check_read("push_file", path_str, active_workspace=active_ws)
                title = str(args.get("title") or "")
                inline_preview = bool(args.get("inline_preview", True))
                open_desktop = bool(args.get("open_on_desktop", False))
                notify_desktop = bool(args.get("notify_desktop", False))

                rec = self.outbox.register(src_path, title=title, copy_to_outbox=True)
                encoded_name = urllib.parse.quote(rec["name"])
                url = f"{self._public_base()}/files/{rec['id']}/{encoded_name}?exp={rec['exp']}&sig={rec['sig']}"

                if open_desktop and IS_WINDOWS:
                    try:
                        os.startfile(rec["path"])  # type: ignore[attr-defined]
                    except OSError as exc:
                        LOG.warning("open_on_desktop failed: %s", exc)

                if notify_desktop and IS_WINDOWS:
                    safe_title = rec["title"].replace("'", "''")
                    safe_path = rec["path"].replace("'", "''")
                    toast_ps = (
                        f"Add-Type -AssemblyName System.Windows.Forms; "
                        f"$n = New-Object System.Windows.Forms.NotifyIcon; "
                        f"$n.Icon = [System.Drawing.SystemIcons]::Information; "
                        f"$n.Visible = $true; "
                        f"$n.ShowBalloonTip(5000, 'pc-work-mcp 已生成文件', '{safe_title}`n{safe_path}', [System.Windows.Forms.ToolTipIcon]::Info); "
                        f"Start-Sleep -Milliseconds 5200; $n.Dispose()"
                    )
                    threading.Thread(
                        target=self.runner.run_powershell,
                        args=(toast_ps, 15, str(HERE)),
                        daemon=True,
                    ).start()

                info = {
                    "pushed": True,
                    "title": rec["title"],
                    "file_name": rec["name"],
                    "size_bytes": rec["size"],
                    "mime_type": rec["mime"],
                    "download_url": url,
                    "expires_in_sec": rec["exp"] - int(time.time()),
                    "local_outbox_path": rec["path"],
                }
                text_payload = json.dumps(info, ensure_ascii=False, indent=2)
                content_blocks = []

                if inline_preview:
                    if rec["mime"].startswith("image/"):
                        img = load_image_for_mcp(Path(rec["path"]), max_dim=1600, quality=85)
                        content_blocks.append({"type": "image", "data": img["b64"], "mimeType": img["mime_type"]})
                    elif rec["size"] <= 65536 and rec["mime"].startswith(("text/", "application/json", "application/xml")):
                        preview_txt, _ = read_text_auto(Path(rec["path"]))
                        preview_txt, _ = out_guard.format_or_bypass(preview_txt, prefix="preview")
                        text_payload += "\n\n--- 预览 ---\n" + preview_txt

                content_blocks.append({"type": "text", "text": text_payload})
                return {"content": content_blocks, "isError": False}

            if name == "bridge_status":
                return text_result(json.dumps(self.bridge.status_snapshot(), ensure_ascii=False, indent=2))

            if name == "bridge_upload_media":
                raw_files = args.get("files") or []
                if isinstance(raw_files, str):
                    raw_files = [raw_files]
                if not isinstance(raw_files, list) or not raw_files:
                    raise ValueError("files must be a non-empty array of local paths")
                if len(raw_files) > 6:
                    raise ValueError("too many files (max 6)")
                resolved_files = []
                for item in raw_files:
                    if not isinstance(item, str) or not item.strip():
                        continue
                    p_obj = self.guard.check_read("bridge_upload_media", item, active_workspace=active_ws)
                    if not p_obj.is_file():
                        raise ValueError(f"file not found: {p_obj}")
                    resolved_files.append(p_obj)
                if not resolved_files:
                    raise ValueError("no valid files provided")
                task = self.bridge.enqueue_upload(
                    files=resolved_files,
                    prompt=str(args.get("prompt") or ""),
                    conversation_id=args.get("conversation_id") or auth_info.get("conversation_id"),
                    delay_sec=int(args.get("delay_sec") or 2),
                    auto_send=bool(args.get("auto_send", True)),
                    tool_mode=str(args.get("tool_mode") or "none"),
                )
                task["instruction"] = (
                    "任务已异步入队。请立即停止当前回合输出，等待油猴插件确认会话 ID、上传完成并自动点击发送开启下一回合。"
                )
                return text_result(json.dumps(task, ensure_ascii=False, indent=2))

            if name == "bridge_save_generated_media":
                raw_target = args.get("target_path")
                if not isinstance(raw_target, str) or not raw_target.strip():
                    raise ValueError("target_path is required")
                norm_target = resolve_path(raw_target, base_dir=active_ws)
                is_dir = (
                    raw_target.strip().endswith(("/", "\\"))
                    or norm_target.is_dir()
                    or not norm_target.suffix
                )
                if is_dir:
                    self.guard.check_write(
                        "bridge_save_generated_media",
                        str(norm_target / "__artifact__"),
                        f"save generated media into directory {norm_target}",
                        active_workspace=active_ws,
                    )
                else:
                    self.guard.check_write(
                        "bridge_save_generated_media",
                        str(norm_target),
                        f"save generated media to file {norm_target}",
                        active_workspace=active_ws,
                    )
                task = self.bridge.enqueue_save_media(
                    target_path=norm_target,
                    is_dir=is_dir,
                    media_kind=str(args.get("kind") or "auto"),
                    trigger_prompt=str(args.get("trigger_prompt") or ""),
                    conversation_id=args.get("conversation_id") or auth_info.get("conversation_id"),
                    delay_sec=int(args.get("delay_sec") or 2),
                    timeout_sec=int(args.get("timeout_sec") or 240),
                    snapshot_mgr=snap_mgr,
                )
                task["instruction"] = (
                    "下载任务已异步入队。请立即停止当前回合输出，油猴插件将在生成完成后自动提取并保存到目标路径。"
                )
                return text_result(json.dumps(task, ensure_ascii=False, indent=2))

            if name == "bridge_get_task":
                task_id = args.get("task_id")
                if not isinstance(task_id, str) or not task_id.strip():
                    raise ValueError("task_id is required")
                task = self.bridge.get_task(task_id.strip())
                if not task:
                    raise ValueError(f"unknown task_id: {task_id}")
                return text_result(json.dumps(task, ensure_ascii=False, indent=2))

            if name == "bridge_suggest_ignore_dirs":
                raw_dirs = args.get("dirs")
                if not isinstance(raw_dirs, list) or not raw_dirs:
                    raise ValueError("dirs must be a non-empty array of directory names or patterns")
                reason = str(args.get("reason") or "").strip()[:240]
                cur_ignored = self._effective_ignored_dirs()
                new_dirs: list[str] = []
                seen_new: set[str] = set()
                for item in raw_dirs:
                    norm = normalize_ignore_entry(str(item or ""))
                    if not norm:
                        continue
                    if is_ignored_dir_name(norm, cur_ignored):
                        continue
                    k = norm.lower()
                    if k not in seen_new:
                        seen_new.add(k)
                        new_dirs.append(norm)
                if not new_dirs:
                    return text_result(json.dumps({
                        "ok": True,
                        "queued": False,
                        "already_ignored": True,
                        "ignored_dirs": cur_ignored,
                        "message": "所提目录已在默认或已配置忽略列表中，无需重复弹窗。",
                    }, ensure_ascii=False, indent=2))
                sug = self.bridge.enqueue_ignore_suggestion(
                    dirs=new_dirs,
                    reason=reason,
                    conversation_id=auth_info.get("conversation_id"),
                    tab_id=auth_info.get("tab_id"),
                    workspace_dir=str(active_ws),
                )
                return text_result(json.dumps({
                    "ok": True,
                    "queued": True,
                    **sug,
                    "config_path": str(self.config_path),
                    "instruction": (
                        "已向油猴端推送目录屏蔽建议。由于 config.json 受本地安全边界保护（禁止模型直接改写），"
                        "请在正文中写明建议屏蔽的目录及原因后立即停止当前回合；待你停笔后，油猴插件会弹出确认框，由用户一键保存到 config.json 永久生效。"
                    ),
                }, ensure_ascii=False, indent=2))

            if name == "task_plan":
                act = str(args.get("action") or "get").strip().lower()
                cid = auth_info.get("conversation_id")
                tab_id = auth_info.get("tab_id")
                if act == "get":
                    res = self.task_plans.get_plan(cid=cid, tab_id=tab_id)
                    return text_result(json.dumps(res, ensure_ascii=False, indent=2))
                if act == "set":
                    plan = self.task_plans.set_plan(
                        cid=cid,
                        tab_id=tab_id,
                        goal=str(args.get("goal") or ""),
                        steps=args.get("steps") or [],
                        max_auto_turns=args.get("max_auto_turns"),
                    )
                    return text_result(json.dumps({"ok": True, "plan": plan}, ensure_ascii=False, indent=2))
                if act == "update":
                    plan = self.task_plans.update_plan(
                        cid=cid,
                        tab_id=tab_id,
                        step_updates=args.get("step_updates"),
                        status=args.get("status"),
                        note=args.get("note"),
                    )
                    return text_result(json.dumps({"ok": True, "plan": plan}, ensure_ascii=False, indent=2))
                if act == "complete":
                    res = self.task_plans.complete_plan(
                        cid=cid, tab_id=tab_id, note=str(args.get("note") or ""),
                    )
                    self.bridge.cancel_continue_tasks(conversation_id=cid, tab_id=tab_id, reason="plan_completed")
                    return text_result(json.dumps(res, ensure_ascii=False, indent=2))
                if act == "stop":
                    res = self.task_plans.stop_auto_continue(
                        cid=cid, tab_id=tab_id,
                        reason=str(args.get("note") or "stopped_by_agent"),
                        bridge_mgr=self.bridge,
                    )
                    return text_result(json.dumps(res, ensure_ascii=False, indent=2))
                if act == "schedule_continue":
                    prep = self.task_plans.prepare_continue(
                        cid=cid,
                        tab_id=tab_id,
                        handoff=str(args.get("handoff") or ""),
                        delay_sec=int(args.get("delay_sec") or 8),
                    )
                    task = self.bridge.enqueue_continue_turn(
                        prompt=prep["prompt"],
                        conversation_id=args.get("conversation_id") or cid,
                        delay_sec=prep["delay_sec"],
                        jitter_max_sec=3,
                        turn_index=prep["turn_index"],
                        max_auto_turns=prep["max_auto_turns"],
                    )
                    updated_plan = self.task_plans.record_pending_task_id(
                        cid=cid, tab_id=tab_id, task_id=task["task_id"], handoff=prep["handoff"],
                    ) or prep["plan"]
                    out = {
                        "ok": True,
                        "scheduled_turn_index": prep["turn_index"],
                        "task": task,
                        "plan": updated_plan,
                        "instruction": (
                            "自唤醒续跑已入队（实际发送成功后计入 auto_turns_used，唤醒提示词已自带当前与下一步进度，无需再调 task_plan(get)）。"
                            "请立即停止当前回合输出，等待油猴插件在停稳冷却后自动唤醒下一回合；后续回调仍须使用极简干练语言，勿复述历史背景。"
                        ),
                    }
                    return text_result(json.dumps(out, ensure_ascii=False, indent=2))
                raise ValueError(f"unsupported task_plan action: {act!r}")

            raise JsonRpcError(-32602, f"Unknown tool: {name}")

    # -- JSON-RPC 批处理包装 -----------------------------------------------
    def process_payload(self, payload, mcp_session_id: str | None = None):
        with self.lock:
            self.stats["requests"] += 1
        if isinstance(payload, list):
            responses = []
            for item in payload:
                resp = self._process_one(item, mcp_session_id=mcp_session_id)
                if resp is not None:
                    responses.append(resp)
            return (200, responses) if responses else (202, None)
        resp = self._process_one(payload, mcp_session_id=mcp_session_id)
        return (200, resp) if resp is not None else (202, None)

    def _process_one(self, msg, mcp_session_id: str | None = None):
        if not isinstance(msg, dict):
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "Invalid Request"}}
        msg_id = msg.get("id")
        method = msg.get("method")
        is_notification = "id" not in msg
        if not isinstance(method, str):
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32600, "message": "Invalid Request: missing method"}}
        try:
            result = self.handle(method, msg.get("params"), mcp_session_id=mcp_session_id)
        except JsonRpcError as exc:
            err = {"code": exc.code, "message": exc.message}
            if exc.data is not None:
                err["data"] = exc.data
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": msg_id, "error": err}
        except Exception as exc:  # noqa: BLE001
            LOG.error("internal error in %s: %s\n%s", method, exc, traceback.format_exc())
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32603, "message": f"Internal error: {exc}"}}
        if is_notification or result is None:
            return None
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}


# ---------------------------------------------------------------------------
# HTTP / OAuth / 文件下载路由层
# ---------------------------------------------------------------------------

class OAuthServer:
    def __init__(self, cfg):
        o = cfg.get("oauth") or {}
        self.cfg = cfg
        self.enabled = bool(o.get("enabled", True))
        self.configured_base = str(o.get("public_base_url") or "").rstrip("/")
        self._password = str(o.get("authorize_password") or "")
        self.access_ttl = max(60, int(o.get("access_token_ttl_sec", 28800)))
        self.refresh_ttl = max(600, int(o.get("refresh_token_ttl_sec", 2592000)))
        log_file = Path((cfg.get("log") or {}).get("file") or (HERE / "logs" / "server.log"))
        self.state_file = Path(o.get("state_file") or (log_file.parent / "oauth_state.json"))
        self.clients = {}
        self.codes = {}
        self.tokens = {}
        self.refresh_tokens = {}
        self.lock = threading.Lock()
        self._load_state()

    def _load_state(self):
        if not self.state_file.is_file():
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            now = time.time()
            self.clients = data.get("clients") or {}
            self.tokens = {k: v for k, v in (data.get("tokens") or {}).items() if v >= now}
            self.refresh_tokens = {
                k: v for k, v in (data.get("refresh_tokens") or {}).items()
                if isinstance(v, dict) and v.get("exp", 0) >= now
            }
        except Exception as exc:
            LOG.warning("failed to load oauth state: %s", exc)

    def _save_state_locked(self):
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            payload = {
                "clients": self.clients,
                "tokens": self.tokens,
                "refresh_tokens": self.refresh_tokens,
            }
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.state_file)
        except Exception as exc:
            LOG.warning("failed to save oauth state: %s", exc)

    def base(self, handler) -> str:
        if self.configured_base:
            return self.configured_base
        fwd_raw = (handler.headers.get("Forwarded") or "").strip()
        fwd_host = ""
        fwd_proto = ""
        if fwd_raw:
            first = fwd_raw.split(",")[0]
            for seg in first.split(";"):
                k, _, v = seg.strip().partition("=")
                k = k.lower()
                v = v.strip().strip('"')
                if k == "host" and v:
                    fwd_host = v
                elif k == "proto" and v:
                    fwd_proto = v
        host = (
            fwd_host
            or (handler.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
            or (handler.headers.get("Host") or "").strip()
        )
        proto = (
            fwd_proto
            or (handler.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
            or "https"
        )
        fwd_port = (handler.headers.get("X-Forwarded-Port") or "").split(",")[0].strip()
        if host and fwd_port and ":" not in host.rsplit("]", 1)[-1] and fwd_port not in ("80", "443"):
            host = f"{host}:{fwd_port}"
        if not host:
            h, p = handler.server.server_address[:2]
            host = f"{h}:{p}"
        return f"{proto}://{host}"

    def password(self) -> str:
        if self._password:
            return self._password
        return str((self.cfg.get("auth") or {}).get("token") or "").strip()

    def protected_resource_metadata(self, handler) -> dict:
        base = self.base(handler)
        return {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        }

    def auth_server_metadata(self, handler) -> dict:
        base = self.base(handler)
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["mcp"],
            "service_documentation": f"{base}/",
        }

    def register(self, payload) -> dict:
        payload = payload if isinstance(payload, dict) else {}
        uris = payload.get("redirect_uris") or []
        if isinstance(uris, str):
            uris = [uris]
        uris = [str(u) for u in uris if u]
        if not uris:
            raise ValueError("redirect_uris is required")
        method = str(payload.get("token_endpoint_auth_method") or "client_secret_post")
        client_id = "client_" + uuid.uuid4().hex[:16]
        secret = secrets.token_urlsafe(32) if method != "none" else ""
        with self.lock:
            if len(self.clients) >= 200:
                oldest = sorted(self.clients.items(), key=lambda kv: kv[1].get("created", 0))[0][0]
                self.clients.pop(oldest, None)
            self.clients[client_id] = {
                "secret": secret,
                "redirect_uris": uris,
                "name": str(payload.get("client_name") or ""),
                "auth_method": method,
                "created": time.time(),
            }
            self._save_state_locked()
        resp = {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": str(payload.get("client_name") or ""),
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if secret:
            resp["client_secret"] = secret
            resp["client_secret_expires_at"] = 0
        return resp

    def new_code(self, client_id, redirect_uri, challenge="", method="", scope="mcp") -> str:
        code = secrets.token_urlsafe(32)
        with self.lock:
            self.codes[code] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "challenge": challenge,
                "method": method or "plain",
                "scope": scope,
                "exp": time.time() + 300,
            }
        return code

    def redeem_code(self, code, client_id, redirect_uri, verifier):
        with self.lock:
            entry = self.codes.pop(code, None)
        if not entry:
            return None, "invalid_grant"
        if entry["exp"] < time.time():
            return None, "code expired"
        if entry["client_id"] != client_id:
            return None, "client mismatch"
        if entry["redirect_uri"] and redirect_uri and entry["redirect_uri"] != redirect_uri:
            return None, "redirect_uri mismatch"
        challenge = entry.get("challenge") or ""
        if challenge:
            if (entry.get("method") or "plain") == "S256":
                calc = base64.urlsafe_b64encode(
                    hashlib.sha256((verifier or "").encode("utf-8")).digest()
                ).decode("ascii").rstrip("=")
            else:
                calc = verifier or ""
            if not hmac.compare_digest(calc, challenge):
                return None, "invalid code_verifier"
        return entry, None

    def issue_tokens(self, client_id):
        access = "at_" + secrets.token_urlsafe(32)
        refresh = "rt_" + secrets.token_urlsafe(32)
        now = time.time()
        with self.lock:
            self._purge_locked(now)
            self.tokens[access] = now + self.access_ttl
            self.refresh_tokens[refresh] = {"client_id": client_id, "exp": now + self.refresh_ttl}
            self._save_state_locked()
        return access, refresh

    def refresh(self, refresh_token):
        now = time.time()
        with self.lock:
            entry = self.refresh_tokens.pop(refresh_token, None)
            if entry is not None:
                self._save_state_locked()
        if not entry or entry["exp"] < now:
            return None
        return self.issue_tokens(entry["client_id"])

    def valid_token(self, token) -> bool:
        if not self.enabled or not token:
            return False
        now = time.time()
        with self.lock:
            exp = self.tokens.get(token)
            if exp is None:
                return False
            if exp < now:
                self.tokens.pop(token, None)
                return False
            return True

    def _purge_locked(self, now):
        for k in [k for k, v in self.tokens.items() if v < now]:
            self.tokens.pop(k, None)
        for k in [k for k, v in self.refresh_tokens.items() if v["exp"] < now]:
            self.refresh_tokens.pop(k, None)
        for k in [k for k, v in self.codes.items() if v["exp"] < now]:
            self.codes.pop(k, None)


class McpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, core, cfg):
        self.cfg = cfg
        super().__init__(addr, handler)
        self.core = core
        self.oauth = OAuthServer(cfg)
        self.sse_sessions = {}
        self.sse_lock = threading.Lock()

    def handle_error(self, request, client_address):  # noqa: ARG002
        exc_type, _, _ = sys.exc_info()
        if exc_type in (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            LOG.debug("client %s disconnected early (%s)", client_address, exc_type.__name__)
            return
        super().handle_error(request, client_address)


class SseSession:
    def __init__(self, sid: str, core):
        self.sid = sid
        self.core = core
        self.inbox = queue.Queue()
        self.outbox = queue.Queue()
        self.closed = False
        self.worker = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.worker.start()

    def _run(self):
        while not self.closed:
            item = self.inbox.get()
            if item is None:
                continue
            try:
                payload = json.loads(item)
            except json.JSONDecodeError:
                self.outbox.put({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32700, "message": "Parse error"}})
                continue
            status, resp = self.core.process_payload(payload, mcp_session_id=self.sid)
            if resp is not None:
                self.outbox.put(resp)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def _client_ip(self):
        return self.client_address[0]

    def _extract_token(self) -> str:
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        token = (self.headers.get("X-Auth-Token") or "").strip()
        if token:
            return token
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        return (query.get("token") or [""])[0].strip()

    def _auth_ok(self) -> bool:
        auth_cfg = self.server.cfg.get("auth") or {}
        if not auth_cfg.get("enabled", True):
            return True
        want = str(auth_cfg.get("token") or "").strip()
        if not want:
            LOG.error("auth enabled but auth.token is empty; rejecting all requests")
            return False
        got = self._extract_token()
        if not got:
            return False
        try:
            if hmac.compare_digest(got, want):
                return True
        except TypeError:
            pass
        return self.server.oauth.valid_token(got)

    def _drain_request_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if length <= 0:
            return
        remaining = length
        while remaining > 0:
            try:
                chunk = self.rfile.read(min(remaining, 65536))
            except (OSError, ValueError):
                break
            if not chunk:
                break
            remaining -= len(chunk)

    def _local_admin_auth_ok(self) -> bool:
        """Strictly require the local auth.token (reject remote OAuth access tokens)."""
        auth_cfg = self.server.cfg.get("auth") or {}
        if not auth_cfg.get("enabled", True):
            return True
        want = str(auth_cfg.get("token") or "").strip()
        if not want:
            return False
        got = self._extract_token()
        if not got:
            return False
        try:
            return hmac.compare_digest(got, want)
        except TypeError:
            return False

    def _guard_local_admin(self) -> bool:
        if self._local_admin_auth_ok():
            return True
        LOG.warning("rejected local-only bridge call from %s %s", self._client_ip(), self.path)
        self._drain_request_body()
        self.close_connection = True
        self._respond_json(
            403 if self._auth_ok() else 401,
            {
                "error": "local_admin_token_required",
                "error_description": "油猴本地桥与按会话权限管理接口仅接受本机派发的 auth.token，不接受远程 OAuth token。",
            },
            {"Connection": "close"},
        )
        return False

    def _guard(self) -> bool:
        if self._auth_ok():
            return True
        LOG.warning("rejected %s %s (bad or missing token)", self._client_ip(), self.path)
        meta = f"{self.server.oauth.base(self)}/.well-known/oauth-protected-resource"
        self._drain_request_body()
        self.close_connection = True
        self._respond_json(401, {"error": "unauthorized", "error_description": "missing or invalid token"},
                           {"WWW-Authenticate": f'Bearer realm="pc-work-mcp", resource_metadata="{meta}"',
                            "Connection": "close"})
        return False

    def _respond_json(self, status: int, obj, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()

    def _respond_text(self, status: int, text: str, content_type="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()

    def _read_body(self) -> bytes:
        transfer = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in transfer:
            return self._read_chunked_body()
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        if length > 50 * 1024 * 1024:
            raise ValueError("body too large")
        return self.rfile.read(length)

    def _read_chunked_body(self) -> bytes:
        chunks = []
        total = 0
        while True:
            line = self.rfile.readline(65536)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                size = int(line.split(b";")[0], 16)
            except ValueError:
                raise ValueError(f"bad chunk size: {line!r}")
            if size == 0:
                while True:
                    trailer = self.rfile.readline(65536)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            total += size
            if total > 50 * 1024 * 1024:
                raise ValueError("body too large")
            data = self.rfile.read(size)
            if len(data) < size:
                raise ValueError("short chunk")
            chunks.append(data)
            self.rfile.read(2)
        return b"".join(chunks)

    def _sse_headers(self, status=200, session_id: str | None = None):
        self.send_response(status)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.flush()

    def _sse_send(self, obj):
        data = json.dumps(obj, ensure_ascii=False)
        self.wfile.write(f"event: message\ndata: {data}\n\n".encode("utf-8"))
        self.wfile.flush()

    def _sse_ping(self):
        self.wfile.write(b": ping\n\n")
        self.wfile.flush()

    @staticmethod
    def _wellknown_kind(path: str):
        for kind in ("oauth-protected-resource", "oauth-authorization-server", "openid-configuration"):
            if f"/.well-known/{kind}" in path:
                return kind
        return None

    def _parse_form(self) -> dict:
        raw = self._read_body().decode("utf-8", "replace")
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                data = json.loads(raw or "{}")
            except json.JSONDecodeError:
                return {}
            return {str(k): v for k, v in data.items()}
        return {k: v[0] if v else "" for k, v in urllib.parse.parse_qs(raw).items()}

    def _check_client_secret(self, client, form) -> bool:
        if client.get("auth_method") == "none" or not client.get("secret"):
            return True
        secret = str(form.get("client_secret") or "")
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8", "replace")
                basic_secret = decoded.partition(":")[2]
                secret = secret or basic_secret
            except Exception:  # noqa: BLE001
                pass
        return bool(secret) and hmac.compare_digest(secret, client["secret"])

    def _require_local_token_issued(self) -> bool:
        if is_local_token_configured(self.server.cfg):
            return True
        self._drain_request_body()
        self.close_connection = True
        self._respond_json(
            403,
            {
                "error": "local_token_not_issued",
                "error_description": "连接 Google / OAuth 服务前，必须先在本地执行 `python server.py --issue-token` 派发鉴权 token。",
            },
            {"Connection": "close"},
        )
        return False

    def _handle_register(self):
        if not self._require_local_token_issued():
            return
        try:
            payload = json.loads(self._read_body() or b"{}")
            resp = self.server.oauth.register(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": "invalid_client_metadata", "error_description": str(exc)})
            return
        LOG.info("oauth register: %s", resp["client_id"])
        self._respond_json(201, resp)

    def _handle_authorize(self):
        if not self._require_local_token_issued():
            return
        params = {k: v[0] for k, v in urllib.parse.parse_qs(
            urllib.parse.urlsplit(self.path).query).items()}
        oauth = self.server.oauth
        client_id = params.get("client_id", "")
        client = oauth.clients.get(client_id)
        if not client:
            self._respond_text(400, "unknown client_id", "text/html; charset=utf-8")
            return
        redirect_uri = params.get("redirect_uri", "") or (client["redirect_uris"][0] if client["redirect_uris"] else "")
        if redirect_uri not in client["redirect_uris"]:
            self._respond_text(400, "redirect_uri not registered", "text/html; charset=utf-8")
            return
        fields = ["response_type", "client_id", "redirect_uri", "state", "code_challenge",
                  "code_challenge_method", "scope", "resource"]
        hidden = "".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(params.get(k, ""))}">'
            for k in fields
        )
        name = client.get("name") or client_id
        page = f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>pc-work-mcp 授权</title>
<style>body{{font-family:system-ui,sans-serif;max-width:520px;margin:3rem auto;line-height:1.6}}
input[type=password]{{width:100%;padding:.5rem;margin:.4rem 0;box-sizing:border-box}}
button{{padding:.5rem 1.2rem;font-size:1rem}}</style></head><body>
<h2>pc-work-mcp 请求授权</h2>
<p>客户端：<code>{html.escape(str(name))}</code></p>
<p>授权后，在未连接浏览器油猴脚本时，将采用默认工作区兜底权限（{html.escape(str(self.server.core.guard.default_dir))} 内允许，工作区外需本机弹窗审批）。</p>
<p style="font-size:.9rem;color:#555">建议在浏览器配合安装本机油猴脚本（<code>/bridge/pc-work-mcp-gemini.user.js</code>）：连接后将自动切换为<b>按每个 Gemini 会话网页链接独立细化权限</b>，且仅由你通过本地桥掌控。</p>
<form method="post" action="/authorize/confirm">{hidden}
<label>本地派发的鉴权 Token（config.json 里的 auth.token）
<input type="password" name="password" autofocus required></label>
<div><button type="submit">授权</button></div>
</form></body></html>"""
        self._respond_text(200, page, "text/html; charset=utf-8")

    def _handle_authorize_confirm(self):
        if not self._require_local_token_issued():
            return
        form = self._parse_form()
        oauth = self.server.oauth
        expected = oauth.password()
        given = str(form.get("password") or "")
        if not expected or not hmac.compare_digest(given, expected):
            LOG.warning("oauth authorize: bad password from %s", self._client_ip())
            self._respond_text(403, "口令错误", "text/html; charset=utf-8")
            return
        client_id = str(form.get("client_id") or "")
        client = oauth.clients.get(client_id)
        if not client:
            self._respond_text(400, "unknown client_id", "text/html; charset=utf-8")
            return
        redirect_uri = str(form.get("redirect_uri") or "") or (client["redirect_uris"][0] if client["redirect_uris"] else "")
        if redirect_uri not in client["redirect_uris"]:
            self._respond_text(400, "redirect_uri not registered", "text/html; charset=utf-8")
            return
        code = oauth.new_code(client_id, redirect_uri,
                              challenge=str(form.get("code_challenge") or ""),
                              method=str(form.get("code_challenge_method") or ""),
                              scope=str(form.get("scope") or "mcp"))
        query = {"code": code}
        state = str(form.get("state") or "")
        if state:
            query["state"] = state
        sep = "&" if "?" in redirect_uri else "?"
        location = redirect_uri + sep + urllib.parse.urlencode(query)
        LOG.info("oauth authorize granted: client=%s", client_id)
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_token(self):
        if not self._require_local_token_issued():
            return
        form = self._parse_form()
        oauth = self.server.oauth
        grant = str(form.get("grant_type") or "")
        if grant == "authorization_code":
            client_id = str(form.get("client_id") or "")
            client = oauth.clients.get(client_id)
            if not client:
                self._respond_json(401, {"error": "invalid_client"})
                return
            if not self._check_client_secret(client, form):
                self._respond_json(401, {"error": "invalid_client", "error_description": "bad client secret"})
                return
            entry, err = oauth.redeem_code(str(form.get("code") or ""), client_id,
                                           str(form.get("redirect_uri") or ""),
                                           str(form.get("code_verifier") or ""))
            if err:
                self._respond_json(400, {"error": "invalid_grant", "error_description": err})
                return
            access, refresh = oauth.issue_tokens(client_id)
            self._respond_json(200, {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": oauth.access_ttl,
                "refresh_token": refresh,
                "scope": entry.get("scope") or "mcp",
            })
            LOG.info("oauth token issued: client=%s", client_id)
            return
        if grant == "refresh_token":
            pair = oauth.refresh(str(form.get("refresh_token") or ""))
            if not pair:
                self._respond_json(400, {"error": "invalid_grant", "error_description": "bad or expired refresh token"})
                return
            access, refresh = pair
            self._respond_json(200, {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": oauth.access_ttl,
                "refresh_token": refresh,
                "scope": "mcp",
            })
            return
        self._respond_json(400, {"error": "unsupported_grant_type"})

    def _handle_file_download(self, path: str):
        parts = [seg for seg in path.split("/") if seg]
        if len(parts) < 2:
            self._respond_json(400, {"error": "bad file url"})
            return
        file_id = parts[1]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        exp_str = (query.get("exp") or [""])[0]
        sig = (query.get("sig") or [""])[0]
        rec = self.server.core.outbox.resolve(file_id, exp_str, sig)
        if not rec:
            self._respond_json(403, {"error": "invalid or expired download link"})
            return
        file_path = rec["path"]
        size = os.path.getsize(file_path)
        self.send_response(200)
        self.send_header("Content-Type", rec["mime"])
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "private, max-age=3600")
        disp = "inline" if rec["mime"].startswith(("image/", "text/", "application/pdf")) else "attachment"
        encoded_name = urllib.parse.quote(rec["name"])
        self.send_header("Content-Disposition", f"{disp}; filename*=UTF-8''{encoded_name}")
        self.end_headers()
        if self.command != "HEAD":
            with open(file_path, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            self.wfile.flush()

    def do_HEAD(self):
        path = self.path.split("?", 1)[0]
        meta = f"{self.server.oauth.base(self)}/.well-known/oauth-protected-resource"
        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/files/"):
            self._handle_file_download(path)
        elif path == "/mcp":
            if self._auth_ok():
                self.send_response(200)
            else:
                self.send_response(401)
                self.send_header("WWW-Authenticate", f'Bearer realm="pc-work-mcp", resource_metadata="{meta}"')
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        kind = self._wellknown_kind(path)
        if kind == "oauth-protected-resource":
            self._respond_json(200, self.server.oauth.protected_resource_metadata(self))
            return
        if kind in ("oauth-authorization-server", "openid-configuration"):
            self._respond_json(200, self.server.oauth.auth_server_metadata(self))
            return
        if path == "/authorize":
            self._handle_authorize()
            return
        if path.startswith("/files/"):
            self._handle_file_download(path)
            return
        if path == "/health":
            core = self.server.core
            body = {
                "ok": True,
                "server": SERVER_NAME,
                "version": SERVER_VERSION,
                "uptime_sec": round(time.time() - core.started),
                "listen": self.server.server_address[:2],
                "workspace": str(core.guard.default_dir),
                "auth_required": bool((self.server.cfg.get("auth") or {}).get("enabled", True)),
                "oauth_enabled": self.server.oauth.enabled,
                "tools": [t["name"] for t in TOOL_DEFS],
                "active_jobs": len(core.jobs.list_active()),
                "engines": {
                    "powershell": core.runner.pwsh_exe,
                    "python": core.runner.python_exe,
                    "bash": core.runner.bash_exe,
                    "pillow": HAS_PIL,
                },
                "stats": core.stats,
            }
            if (self.server.cfg.get("auth") or {}).get("health_requires_auth", False):
                if not self._guard():
                    return
            self._respond_json(200, body)
            return
        if path.startswith("/bridge/"):
            if not self._guard_local_admin():
                return
            if path == "/bridge/status":
                self._respond_json(200, self.server.core.bridge.status_snapshot())
                return
            if path == "/bridge/permissions":
                self._respond_json(200, self.server.core.permissions.snapshot(self.server.core.bridge))
                return
            if path == "/bridge/rules":
                self._respond_json(200, self.server.core.rules.snapshot(self.server.core.bridge))
                return
            if path == "/bridge/workspaces":
                self._respond_json(200, self.server.core.workspaces.snapshot(self.server.core.bridge))
                return
            if path == "/bridge/whitelist":
                self._respond_json(200, {
                    "ok": True,
                    "entries": self.server.core.guard.get_global_whitelist(),
                    "default_workspace": str(self.server.core.guard.default_dir),
                })
                return
            if path == "/bridge/ignored_dirs":
                self._respond_json(200, self.server.core.get_ignored_dirs_snapshot())
                return
            if path == "/bridge/task_plan":
                self._respond_json(200, self.server.core.task_plans.snapshot(self.server.core.bridge))
                return
            if path == "/bridge/public_url":
                oauth_cfg = self.server.core.cfg.get("oauth") or {}
                self._respond_json(200, {
                    "public_base_url": str(oauth_cfg.get("public_base_url") or "").strip(),
                    "startup_tcp_check": bool(oauth_cfg.get("startup_tcp_check", False)),
                    "listen_port": int((self.server.core.cfg.get("listen") or {}).get("port") or 15672),
                })
                return
            if path == "/bridge/tasks":
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                tab_id = (query.get("tab_id") or [""])[0]
                cid = (query.get("conversation_id") or [""])[0] or None
                if not tab_id:
                    self._respond_json(400, {"error": "tab_id is required"})
                    return
                self._respond_json(200, self.server.core.bridge.poll_tasks(tab_id, cid))
                return
            if path.startswith("/bridge/file/"):
                self._handle_bridge_file_download(path)
                return
            if path == "/bridge/pc-work-mcp-gemini.user.js":
                self._handle_bridge_userscript()
                return
            self._respond_json(404, {"error": "not found"})
            return
        if not self._guard():
            return
        if path in ("/", "/index.html"):
            self._respond_text(200, self._index_html(), "text/html; charset=utf-8")
            return
        if path == "/mcp":
            accept = self.headers.get("Accept") or ""
            if "text/event-stream" in accept:
                self._handle_mcp_sse_stream()
                return
            self._respond_json(405, {"error": "GET not supported on /mcp; POST JSON-RPC there"},
                               {"Allow": "POST, DELETE, OPTIONS"})
            return
        if path == "/sse":
            self._handle_sse_stream()
            return
        self._respond_json(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._guard():
            return
        path = self.path.split("?", 1)[0]
        if path == "/mcp":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._respond_json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/register":
            self._handle_register()
            return
        if path == "/token":
            self._handle_token()
            return
        if path == "/authorize/confirm":
            self._handle_authorize_confirm()
            return
        if path.startswith("/bridge/"):
            if not self._guard_local_admin():
                return
            if path == "/bridge/heartbeat":
                self._handle_bridge_heartbeat()
                return
            if path == "/bridge/task_result":
                self._handle_bridge_task_result()
                return
            if path == "/bridge/task_upload":
                self._handle_bridge_task_upload()
                return
            if path == "/bridge/permissions":
                self._handle_bridge_permissions_post()
                return
            if path == "/bridge/permissions/decision":
                self._handle_bridge_permission_decision()
                return
            if path == "/bridge/rules":
                self._handle_bridge_rules_post()
                return
            if path == "/bridge/workspaces":
                self._handle_bridge_workspaces_post()
                return
            if path == "/bridge/whitelist":
                self._handle_bridge_whitelist_post()
                return
            if path == "/bridge/ignored_dirs":
                self._handle_bridge_ignored_dirs_post()
                return
            if path == "/bridge/ignored_dirs/decision":
                self._handle_bridge_ignored_dirs_decision()
                return
            if path == "/bridge/task_plan":
                self._handle_bridge_task_plan_post()
                return
            if path == "/bridge/check_public_url":
                self._handle_bridge_check_public_url_post()
                return
            self._respond_json(404, {"error": "not found"})
            return
        if not self._guard():
            return
        if path == "/mcp":
            self._handle_mcp_post()
            return
        if path == "/messages":
            self._handle_legacy_message()
            return
        self._drain_request_body()
        self._respond_json(404, {"error": "not found"}, {"Connection": "close"})
        self.close_connection = True

    def _handle_mcp_post(self):
        try:
            body = self._read_body()
            payload = json.loads(body or b"{}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700, "message": f"Parse error: {exc}"}})
            return

        accept = self.headers.get("Accept") or ""
        want_sse = "text/event-stream" in accept and "application/json" not in accept
        core = self.server.core
        incoming_sid = (self.headers.get("Mcp-Session-Id") or "").strip() or None
        session_id = incoming_sid or f"mcp-{uuid.uuid4().hex}"
        LOG.info("mcp-post: accept=%r proto=%r sid=%r body=%r",
                 self.headers.get("Accept"), self.headers.get("MCP-Protocol-Version"),
                 session_id[:24], (body or b"")[:300])

        if not want_sse:
            status, resp = core.process_payload(payload, mcp_session_id=incoming_sid)
            if resp is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._respond_json(status, resp, {"Mcp-Session-Id": session_id})
            return

        outcome = queue.Queue()
        result_holder = {"status": 200, "resp": None}

        def work():
            try:
                status, resp = core.process_payload(payload, mcp_session_id=incoming_sid)
                result_holder["status"], result_holder["resp"] = status, resp
            except Exception as exc:  # noqa: BLE001
                LOG.error("mcp worker error: %s\n%s", exc, traceback.format_exc())
                result_holder["resp"] = {"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32603, "message": str(exc)}}
            finally:
                outcome.put(True)

        thread = threading.Thread(target=work, daemon=True)
        thread.start()

        self._sse_headers(200, session_id)
        try:
            while True:
                try:
                    outcome.get(timeout=10)
                    break
                except queue.Empty:
                    self._sse_ping()
            if result_holder["resp"] is not None:
                self._sse_send(result_holder["resp"])
        except (BrokenPipeError, ConnectionResetError):
            LOG.info("client disconnected during SSE response")
        finally:
            self.close_connection = True

    def _handle_mcp_sse_stream(self):
        self._sse_headers(200, self.headers.get("Mcp-Session-Id"))
        deadline = time.time() + 600
        try:
            while time.time() < deadline:
                self._sse_ping()
                time.sleep(15)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.close_connection = True

    def _handle_sse_stream(self):
        sid = f"sse-{uuid.uuid4().hex}"
        session = SseSession(sid, self.server.core)
        with self.server.sse_lock:
            self.server.sse_sessions[sid] = session
        session.start()
        self._sse_headers(200)
        try:
            self.wfile.write(f"event: endpoint\ndata: /messages?sessionId={sid}\n\n".encode("utf-8"))
            self.wfile.flush()
            while not session.closed:
                try:
                    item = session.outbox.get(timeout=15)
                except queue.Empty:
                    self._sse_ping()
                    continue
                if item is None:
                    continue
                self.wfile.write(f"event: message\ndata: {json.dumps(item, ensure_ascii=False)}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            session.closed = True
            session.inbox.put(None)
            with self.server.sse_lock:
                self.server.sse_sessions.pop(sid, None)
            self.close_connection = True

    def _handle_legacy_message(self):
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = {}
        for pair in query.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
        sid = params.get("sessionId")
        session = self.server.sse_sessions.get(sid)
        if not session:
            self._respond_json(404, {"error": "unknown sessionId"})
            return
        body = self._read_body().decode("utf-8", "replace")
        try:
            json.loads(body)
        except json.JSONDecodeError as exc:
            self._respond_json(400, {"error": f"parse error: {exc}"})
            return
        session.inbox.put(body)
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    _QUIET_BRIDGE_PATHS = frozenset({"/bridge/heartbeat", "/bridge/tasks"})

    def log_request(self, code="-", size="-"):
        req_path = (getattr(self, "path", "") or "").split("?", 1)[0]
        try:
            code_num = int(code)
        except (TypeError, ValueError):
            code_num = 0
        if code_num in (200, 204) and (
            req_path in self._QUIET_BRIDGE_PATHS
            or (getattr(self, "command", "") == "OPTIONS" and req_path.startswith("/bridge/"))
        ):
            LOG.debug('%s "%s" %s %s', self._client_ip(), self.requestline, code, size)
            return
        super().log_request(code, size)

    def log_message(self, fmt, *args):
        LOG.info("%s %s", self._client_ip(), fmt % args)

    def _handle_bridge_heartbeat(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            res = self.server.core.bridge.heartbeat(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})
            return
        self._respond_json(200, res)

    def _handle_bridge_task_result(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            res = self.server.core.bridge.report_task_result(payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})
            return
        self._respond_json(200, res)

    def _handle_bridge_permissions_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "set").strip().lower()
            perms = self.server.core.permissions
            if action == "set":
                policy = perms.set_policy(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                    profile=payload.get("profile"),
                    capabilities=payload.get("capabilities"),
                    scope=str(payload.get("scope") or "persistent"),
                    url=str(payload.get("url") or ""),
                    title=str(payload.get("title") or ""),
                )
                self._respond_json(200, {"ok": True, "policy": policy})
                return
            if action == "delete":
                removed = perms.delete_policy(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                )
                self._respond_json(200, {"ok": True, "removed": removed})
                return
            if action == "clear_all":
                cleared = perms.clear_all_policies()
                self._respond_json(200, {"ok": True, "cleared": cleared})
                return
            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_permission_decision(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            res = self.server.core.permissions.resolve_approval(
                approval_id=str(payload.get("approval_id") or ""),
                decision=str(payload.get("decision") or ""),
                profile=payload.get("profile"),
                capability=payload.get("capability"),
                scope=str(payload.get("scope") or "persistent"),
                responder_cid=payload.get("conversation_id"),
                responder_tab_id=payload.get("tab_id"),
            )
            self._respond_json(200, {"ok": True, "approval": res})
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_rules_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "reset_session").strip().lower()
            rules = self.server.core.rules
            if action == "set_rules_dir":
                res = rules.set_conversation_rules_dir(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                    rules_dir=str(payload.get("rules_dir") or ""),
                    scope=str(payload.get("scope") or "persistent"),
                )
                self._respond_json(200, {"ok": True, "result": res})
                return
            if action == "reset_session":
                cleared = rules.force_reset_session(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                    session_key=payload.get("session_key"),
                )
                self._respond_json(200, {"ok": True, "reset": cleared})
                return
            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_workspaces_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "bind").strip().lower()
            mgr = self.server.core.workspaces
            if action == "pick_folder":
                res = mgr.pick_and_save_workspace(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                    bind=bool(payload.get("bind", True)),
                    scope=str(payload.get("scope") or "persistent"),
                    url=str(payload.get("url") or ""),
                    title=str(payload.get("title") or ""),
                    initial_dir=str(payload.get("initial_dir") or ""),
                )
                self._respond_json(200, res)
                return
            if action == "add_saved":
                saved = mgr.add_saved_workspace(
                    str(payload.get("workspace_dir") or ""),
                    label=str(payload.get("label") or ""),
                )
                self._respond_json(200, {"ok": True, "saved": saved})
                return
            if action == "remove_saved":
                removed = mgr.remove_saved_workspace(str(payload.get("workspace_dir") or ""))
                self._respond_json(200, {"ok": True, "removed": removed})
                return
            if action == "bind":
                binding = mgr.bind_workspace(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                    workspace_dir=str(payload.get("workspace_dir") or ""),
                    scope=str(payload.get("scope") or "persistent"),
                    url=str(payload.get("url") or ""),
                    title=str(payload.get("title") or ""),
                    save_to_list=bool(payload.get("save_to_list", True)),
                )
                self._respond_json(200, {"ok": True, "binding": binding})
                return
            if action == "unbind":
                binding = mgr.unbind_workspace(
                    conversation_id=payload.get("conversation_id"),
                    tab_id=payload.get("tab_id"),
                )
                self._respond_json(200, {"ok": True, "binding": binding})
                return
            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_whitelist_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "add").strip().lower()
            core = self.server.core
            guard = core.guard

            if action == "pick_folder":
                if not IS_WINDOWS:
                    raise ValueError("native folder picker is only available on Windows")
                init_dir = guard.default_dir
                raw_init = str(payload.get("initial_dir") or "").strip()
                if raw_init:
                    cand = resolve_path(raw_init, base_dir=guard.default_dir)
                    if cand.is_dir():
                        init_dir = cand
                chosen = _pick_folder_winforms("选择要加入全局白名单的文件夹（所有非禁止会话可免授权访问）", init_dir)
                if chosen is None:
                    self._respond_json(200, {
                        "ok": True,
                        "cancelled": True,
                        "entries": guard.get_global_whitelist(),
                    })
                    return
                entry = guard.add_global_whitelist_dir(
                    str(chosen),
                    mode=str(payload.get("mode") or "readwrite"),
                    allow_exec=bool(payload.get("allow_exec", False)),
                    label=str(payload.get("label") or ""),
                )
                entries = core.persist_global_whitelist()
                self._respond_json(200, {"ok": True, "cancelled": False, "entry": entry, "entries": entries})
                return

            if action == "add":
                raw_path = str(payload.get("path") or "").strip()
                if not raw_path:
                    raise ValueError("path is required")
                entry = guard.add_global_whitelist_dir(
                    raw_path,
                    mode=str(payload.get("mode") or "readwrite"),
                    allow_exec=bool(payload.get("allow_exec", False)),
                    label=str(payload.get("label") or ""),
                )
                entries = core.persist_global_whitelist()
                self._respond_json(200, {"ok": True, "entry": entry, "entries": entries})
                return

            if action == "update":
                raw_path = str(payload.get("path") or "").strip()
                if not raw_path:
                    raise ValueError("path is required")
                entry = guard.update_global_whitelist_dir(
                    raw_path,
                    mode=str(payload["mode"]) if "mode" in payload and payload["mode"] is not None else None,
                    allow_exec=bool(payload["allow_exec"]) if "allow_exec" in payload and payload["allow_exec"] is not None else None,
                    label=str(payload["label"]) if "label" in payload and payload["label"] is not None else None,
                )
                entries = core.persist_global_whitelist()
                self._respond_json(200, {"ok": True, "entry": entry, "entries": entries})
                return

            if action == "remove":
                raw_path = str(payload.get("path") or "").strip()
                if not raw_path:
                    raise ValueError("path is required")
                removed = guard.remove_global_whitelist_dir(raw_path)
                entries = core.persist_global_whitelist()
                self._respond_json(200, {"ok": True, "removed": removed, "entries": entries})
                return

            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_ignored_dirs_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "add").strip().lower()
            core = self.server.core

            if action == "pick_folder":
                if not IS_WINDOWS:
                    raise ValueError("native folder picker is only available on Windows")
                chosen = _pick_folder_winforms("选择要加入忽略检索列表的目录（将按目录名屏蔽）", core.guard.default_dir)
                if chosen is None:
                    self._respond_json(200, {"cancelled": True, **core.get_ignored_dirs_snapshot()})
                    return
                core.add_ignored_dirs([chosen.name])
                self._respond_json(200, {"cancelled": False, "added": [chosen.name], **core.get_ignored_dirs_snapshot()})
                return

            if action == "add":
                raw_list = payload.get("dirs")
                items: list[str] = []
                if isinstance(raw_list, list):
                    items.extend(str(x or "") for x in raw_list)
                if payload.get("dir"):
                    items.append(str(payload["dir"]))
                if not items:
                    raise ValueError("dir or dirs is required")
                core.add_ignored_dirs(items)
                self._respond_json(200, core.get_ignored_dirs_snapshot())
                return

            if action == "remove":
                target = str(payload.get("dir") or "").strip()
                if not target:
                    raise ValueError("dir is required")
                core.remove_ignored_dir(target)
                self._respond_json(200, core.get_ignored_dirs_snapshot())
                return

            if action == "set":
                raw_list = payload.get("dirs")
                if not isinstance(raw_list, list):
                    raise ValueError("dirs array is required")
                core.persist_ignored_dirs([str(x or "") for x in raw_list])
                self._respond_json(200, core.get_ignored_dirs_snapshot())
                return

            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_ignored_dirs_decision(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            core = self.server.core
            res = core.bridge.resolve_ignore_suggestion(
                suggestion_id=str(payload.get("suggestion_id") or ""),
                decision=str(payload.get("decision") or ""),
                dirs=payload.get("dirs") if isinstance(payload.get("dirs"), list) else None,
            )
            if res["decision"] == "approve" and res["dirs"]:
                core.add_ignored_dirs(res["dirs"])
            self._respond_json(200, {**res, **core.get_ignored_dirs_snapshot()})
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_task_plan_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            action = str(payload.get("action") or "stop").strip().lower()
            mgr = self.server.core.task_plans
            cid = payload.get("conversation_id")
            tab_id = payload.get("tab_id")
            if action == "stop":
                res = mgr.stop_auto_continue(
                    cid=cid, tab_id=tab_id,
                    reason=str(payload.get("reason") or "stopped_by_user"),
                    bridge_mgr=self.server.core.bridge,
                )
                self._respond_json(200, res)
                return
            if action == "complete":
                res = mgr.complete_plan(cid=cid, tab_id=tab_id, note=str(payload.get("note") or ""))
                self.server.core.bridge.cancel_continue_tasks(conversation_id=cid, tab_id=tab_id, reason="completed_by_user")
                self._respond_json(200, res)
                return
            if action == "get":
                self._respond_json(200, mgr.get_plan(cid=cid, tab_id=tab_id))
                return
            raise ValueError(f"unsupported action: {action!r}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_check_public_url_post(self):
        try:
            payload = json.loads(self._read_body() or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object expected")
            oauth_cfg = self.server.core.cfg.setdefault("oauth", {})
            raw_url = str(payload.get("public_base_url") or "").strip().rstrip("/")
            target_url = raw_url or str(oauth_cfg.get("public_base_url") or "").strip().rstrip("/")
            save = bool(payload.get("save", False))
            saved = False
            if save:
                if raw_url and not raw_url.startswith(("http://", "https://")):
                    raise ValueError("public_base_url must start with http:// or https://")
                oauth_cfg["public_base_url"] = raw_url
                if getattr(self.server, "oauth", None) is not None:
                    self.server.oauth.configured_base = raw_url
                def set_pub(obj: dict):
                    obj.setdefault("oauth", {})["public_base_url"] = raw_url
                self.server.core.persist_config_mutation(set_pub)
                saved = True
                target_url = raw_url
            if not target_url:
                self._respond_json(200, {
                    "ok": True,
                    "saved": saved,
                    "public_base_url": "",
                    "check": {
                        "status": "empty",
                        "reason": "未填写公网入口 URL；请先填写公网域名与端口（如 https://example.com:14769）再测试。",
                        "reachable_families": [],
                        "families": {},
                    },
                })
                return
            chk = verify_public_tcp_reachability(target_url)
            self._respond_json(200, {
                "ok": True,
                "saved": saved,
                "public_base_url": target_url,
                "check": chk,
            })
        except (ValueError, json.JSONDecodeError) as exc:
            self._respond_json(400, {"error": str(exc)})

    def _handle_bridge_file_download(self, path: str):
        parts = [seg for seg in path.split("/") if seg]
        if len(parts) < 4:
            self._respond_json(400, {"error": "bad bridge file path"})
            return
        task_id = parts[2]
        try:
            idx = int(parts[3])
        except ValueError:
            self._respond_json(400, {"error": "bad file index"})
            return
        spec = self.server.core.bridge.get_upload_file(task_id, idx)
        if not spec or not os.path.isfile(spec["path"]):
            self._respond_json(404, {"error": "bridge file not found"})
            return
        size = os.path.getsize(spec["path"])
        self.send_response(200)
        self.send_header("Content-Type", spec["mime"])
        self.send_header("Content-Length", str(size))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        encoded_name = urllib.parse.quote(spec["name"])
        self.send_header("Content-Disposition", f"inline; filename*=UTF-8''{encoded_name}")
        self.end_headers()
        if self.command != "HEAD":
            with open(spec["path"], "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            self.wfile.flush()

    def _handle_bridge_task_upload(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        task_id = (query.get("task_id") or [""])[0].strip()
        filename = (query.get("filename") or [""])[0].strip()
        mime_type = (query.get("mime") or [self.headers.get("Content-Type") or ""])[0].strip()
        try:
            index = int((query.get("index") or ["0"])[0])
        except ValueError:
            index = 0
        try:
            raw = self._read_body()
            saved = self.server.core.bridge.save_uploaded_artifact(
                task_id=task_id,
                raw_bytes=raw,
                filename=filename,
                mime_type=mime_type,
                index=index,
            )
        except ValueError as exc:
            self._respond_json(400, {"error": str(exc)})
            return
        self._respond_json(200, {"ok": True, "saved": saved})

    def _handle_bridge_userscript(self):
        script_path = HERE / "userscript" / "pc-work-mcp-gemini-bridge.user.js"
        if not script_path.is_file():
            self._respond_json(404, {"error": "userscript template not found"})
            return
        txt = script_path.read_text(encoding="utf-8")
        host = (self.headers.get("Host") or "").strip() or f"127.0.0.1:{self.server.server_address[1]}"
        proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip() or "http"
        base_url = f"{proto}://{host}"
        token = self._extract_token()
        txt = txt.replace('"__PC_WORK_MCP_BASE_URL__"', json.dumps(base_url)).replace(
            '"__PC_WORK_MCP_TOKEN__"', json.dumps(token)
        )
        self._respond_text(200, txt, "application/javascript; charset=utf-8")

    def _index_html(self):
        core = self.server.core
        host, port = self.server.server_address[:2]
        tools = "".join(
            f"<li><code>{t['name']}</code> — {html.escape(t['description'])}</li>" for t in TOOL_DEFS
        )
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>pc-work-mcp {SERVER_VERSION}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;line-height:1.5}}
code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:3px}}</style></head>
<body>
<h1>pc-work-mcp {SERVER_VERSION}</h1>
<p>Status: <strong>running</strong> · uptime {round(time.time()-core.started)}s · listening on
<code>{host}:{port}</code> · workspace: <code>{html.escape(str(core.guard.default_dir))}</code></p>
<h2>Engines</h2>
<ul>
  <li>PowerShell: <code>{html.escape(core.runner.pwsh_exe)}</code></li>
  <li>Python: <code>{html.escape(core.runner.python_exe)}</code> (Pillow={HAS_PIL})</li>
  <li>Git Bash: <code>{html.escape(core.runner.bash_exe)}</code></li>
</ul>
<h2>Tools ({len(TOOL_DEFS)})</h2>
<ul>{tools}</ul>
<h2>Stats</h2>
<pre>{json.dumps(core.stats, ensure_ascii=False)}</pre>
</body></html>"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def make_server(cfg, core):
    host = str(cfg["listen"].get("host") or "0.0.0.0")
    port = int(cfg["listen"].get("port", 15672))
    deadline = time.time() + int(cfg["listen"].get("bind_retry_sec", 120))
    while True:
        try:
            server = McpServer((host, port), Handler, core, cfg)
            LOG.info("listening on %s:%s (auth=%s)",
                     host, port, bool((cfg.get("auth") or {}).get("enabled", True)))
            return server, host, port
        except OSError as exc:
            if time.time() >= deadline:
                raise
            LOG.warning("bind %s:%s failed (%s); retrying in 3s", host, port, exc)
            time.sleep(3)


def _print_issued_token_banner(res: dict, cfg_path: Path):
    cfg_now = load_config(str(cfg_path))
    ws_dir = str((cfg_now.get("workspace") or {}).get("default_dir") or _default_clean_workspace_dir())
    mcp_dir = _resolve_mcp_runtime_dir(Path(ws_dir)) if (cfg_now.get("workspace") or {}).get("default_dir") else HERE
    if not (mcp_dir / "server.py").is_file():
        mcp_dir = Path(ws_dir) if (Path(ws_dir) / "server.py").is_file() else HERE
    port_now = int((cfg_now.get("listen") or {}).get("port") or 15672)
    ws_cfg_path = mcp_dir / "config.json"
    print("\n" + "=" * 72)
    print("【请立即复制并保存你的本地鉴权 Token（仅首次生成/轮换时明文打印）】")
    print(f"  鉴权 Token : {res['token']}")
    print(f"  同步已写入 : {ws_cfg_path}")
    print("  保存提示   : 连接 Google OAuth 授权页、Bearer 鉴权与油猴脚本都需要使用该 Token，请妥善保存切勿泄露。")
    print("=" * 72)
    print("\n已在本地派发鉴权 token。下一步：")
    print(f"1. 后续从安装目录启动服务：python \"{mcp_dir / 'server.py'}\"")
    print("2. 连接 Google / Gemini MCP 时，将该 token 作为 Bearer Token 或 OAuth 授权页口令。")
    print(
        f"3. 【推荐】安装油猴桥接脚本实现按会话链接细化权限（未装时默认兜底）：\n"
        f"   http://127.0.0.1:{port_now}/bridge/pc-work-mcp-gemini.user.js?token={res['token']}"
    )
    print("   （授权规则基于各自会话链接，由本地桥直接掌控，不由会话内 Agent 或 Google 掌管。）")


def _prompt_optional_public_url(cfg_path: Path, explicit_url: str | None = None):
    public_url = (explicit_url or "").strip().rstrip("/")
    if not public_url and sys.stdin.isatty():
        cur_cfg = load_config(str(cfg_path))
        if not str((cur_cfg.get("oauth") or {}).get("public_base_url") or "").strip():
            try:
                entered = input(
                    "[可选] 若已配置公网反代域名连接 Google MCP，请输入公网入口 URL（如 https://example.com:14769，尚无或仅本机请回车）："
                ).strip().rstrip("/")
                if entered:
                    public_url = entered
            except (EOFError, KeyboardInterrupt):
                pass
    if public_url:
        def set_pub(obj: dict):
            obj.setdefault("oauth", {})["public_base_url"] = public_url
        updated = _sync_config_file(cfg_path, set_pub)
        ws_dir_str = str((updated.get("workspace") or {}).get("default_dir") or "").strip()
        for ws_cfg in _resolve_synced_config_paths(cfg_path, ws_dir_str):
            _sync_config_file(ws_cfg, set_pub)


def _run_interactive_token_wizard(cfg_path: Path, effective_cfg_path: Path) -> bool:
    """双击或交互终端直接运行 server.py 且尚未派发 Token 时，引导一键派发并等待确认后继续启动服务。"""
    print("\n[首次启动向导] 检测到尚未在本地派发鉴权 Token（连接 Google 服务前必须先完成本地派发）。")
    try:
        ans = input("是否现在自动生成并保存本机鉴权 Token？[Y/n]（直接回车生成，输入 n 退出）: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans in ("n", "no"):
        return False
    _prompt_optional_public_url(cfg_path)
    res = issue_local_token(cfg_path, rotate=False)
    if effective_cfg_path.resolve(strict=False) != cfg_path.resolve(strict=False) and res.get("issued"):
        def sync_tok(obj: dict):
            a = obj.setdefault("auth", {})
            a["enabled"] = True
            a["token"] = res["token"]
        _sync_config_file(effective_cfg_path, sync_tok)
    if res.get("issued"):
        _print_issued_token_banner(res, effective_cfg_path)
    try:
        go = input("\n请确认已复制保存上述 Token，按回车键立即启动 MCP 服务（输入 q 暂不启动并退出）: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return go not in ("q", "quit", "exit")


def main(argv=None):
    parser = argparse.ArgumentParser(description="pc-work-mcp —— Windows 本机工作台 MCP 服务")
    parser.add_argument("--config", default=None, help="指定配置文件路径（默认读取同目录 config.json）")
    parser.add_argument("--port", type=int, default=None, help="覆盖 listen.port")
    parser.add_argument("--token", default=None, help="覆盖 auth.token")
    parser.add_argument("--public-url", default=None, help="设置或覆盖 oauth.public_base_url（反代/隧道公网地址，如 https://domain:14769）")
    parser.add_argument("--workspace", default=None, help="指定工作区目录（首次运行时跳过交互选择）")
    parser.add_argument("--use-desktop-workspace", action="store_true", help="显式在当前用户桌面创建 pc-work-mcp-workspace 作为首次工作区")
    parser.add_argument("--no-gui", action="store_true", help="首次选择工作区时不弹出 Windows 文件夹选择框")
    parser.add_argument("--issue-token", action="store_true", help="在本地派发并保存鉴权 token（连接 Google 服务前必须执行）")
    parser.add_argument("--rotate-token", action="store_true", help="重新派发新的鉴权 token 并作废旧 OAuth 会话")
    parser.add_argument("--token-status", action="store_true", help="查看当前本地鉴权 token 配置状态")
    parser.add_argument("--check-public-url", nargs="?", const="", default=None, help="手动从外网双栈 TCP 探测公网入口是否可达（默认读取 config.json 的 oauth.public_base_url）")
    parser.add_argument("--skip-tcp-check", action="store_true", help="启动时跳过外网公网地址双栈 TCP 自检锁")
    parser.add_argument("--dry-run", action="store_true", help="打印配置后退出")
    args = parser.parse_args(argv)

    using_default_config = (args.config is None)
    cfg_path = Path(args.config) if args.config else (HERE / "config.json")
    tty_interactive = sys.stdin.isatty()
    effective_cfg_path = cfg_path

    def pause_if_double_clicked():
        if using_default_config and tty_interactive:
            try:
                input("按回车键退出...")
            except (EOFError, KeyboardInterrupt):
                pass

    if not args.dry_run and not args.token_status and args.check_public_url is None:
        try:
            ws_init = ensure_first_run_workspace(
                cfg_path,
                requested_workspace=args.workspace,
                interactive=tty_interactive,
                use_gui=not args.no_gui,
                allow_gui=not args.no_gui,
                use_desktop_workspace=args.use_desktop_workspace,
            )
        except WorkspaceSelectionCancelled as exc:
            print(f"[工作区未初始化] {exc}")
            pause_if_double_clicked()
            return 2
        if ws_init.get("initialized_now"):
            print(
                f"[工作区已初始化] 模式={ws_init['mode']} | 工作区={ws_init['workspace_dir']} "
                f"| MCP 安装目录={ws_init.get('mcp_dir', ws_init['workspace_dir'])} "
                f"| 已一次性复制 {ws_init['copied_count']} 个文件"
            )
            print("\n" + PER_CONVERSATION_GUIDE_NOTICE + "\n")
            if using_default_config and ws_init.get("mcp_dir"):
                cand_cfg = Path(ws_init["mcp_dir"]) / "config.json"
                if cand_cfg.is_file():
                    effective_cfg_path = cand_cfg

    if args.issue_token or args.rotate_token:
        _prompt_optional_public_url(cfg_path, args.public_url)
        res = issue_local_token(cfg_path, rotate=args.rotate_token)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        if res.get("issued"):
            _print_issued_token_banner(res, cfg_path)
        else:
            print("\n已存在本地鉴权 token；如需轮换并作废旧会话，请加 --rotate-token。")
            print("（如忘记完整 token，可打开 Gemini-Windows-Mcp\\config.json 查看 auth.token 字段，或运行 --rotate-token 重新生成。）")
        return 0

    cfg = load_config(str(effective_cfg_path))
    if args.port:
        cfg["listen"]["port"] = args.port
    if args.token:
        cfg["auth"]["token"] = args.token
    if args.public_url:
        cfg.setdefault("oauth", {})["public_base_url"] = args.public_url.strip().rstrip("/")

    if args.token_status:
        tok = str((cfg.get("auth") or {}).get("token") or "").strip()
        print(json.dumps({
            "auth_enabled": bool((cfg.get("auth") or {}).get("enabled", True)),
            "token_issued": bool(tok),
            "masked_token": mask_token(tok),
            "config_path": str(effective_cfg_path),
        }, ensure_ascii=False, indent=2))
        return 0

    if args.check_public_url is not None:
        target_url = (args.check_public_url or "").strip() or str((cfg.get("oauth") or {}).get("public_base_url") or "").strip()
        chk = verify_public_tcp_reachability(target_url)
        print(json.dumps(chk, ensure_ascii=False, indent=2))
        return 2 if chk.get("status") == "unreachable" else 0

    if not is_local_token_configured(cfg):
        if using_default_config and tty_interactive:
            if not _run_interactive_token_wizard(cfg_path, effective_cfg_path):
                print("已退出；待需要连接时可随时双击运行或执行 python server.py --issue-token。")
                return 2
            cfg = load_config(str(effective_cfg_path))
            if args.port:
                cfg["listen"]["port"] = args.port
            if args.public_url:
                cfg.setdefault("oauth", {})["public_base_url"] = args.public_url.strip().rstrip("/")
        else:
            setup_logging(cfg)
            LOG.info("starting %s %s (config=%s)", SERVER_NAME, SERVER_VERSION, effective_cfg_path)
            LOG.error(
                "auth.enabled=true but auth.token is empty —— 拒绝启动。"
                "在连接 Google 服务前，请先在本地运行: python \"%s\" --issue-token --config \"%s\"",
                Path(__file__).name,
                effective_cfg_path,
            )
            return 2

    setup_logging(cfg)
    LOG.info("starting %s %s (config=%s)", SERVER_NAME, SERVER_VERSION, effective_cfg_path)

    if args.dry_run:
        print(json.dumps(cfg, indent=2, ensure_ascii=False))
        return 0

    if (cfg.get("oauth") or {}).get("enabled", True) and not str((cfg.get("oauth") or {}).get("public_base_url") or "").strip():
        LOG.info(
            "oauth.public_base_url 尚未填写（本机/局域网与油猴桥可先正常运行）。"
            "【重要提醒】在设置 Google / Gemini MCP 服务前，请先完成公网反代/端口映射，"
            "并在油猴控制面板内填写域名后点击「测试公网连通性 (双栈 TCP)」确认外网能连入本机。"
        )

    core = McpCore(cfg, config_path=str(effective_cfg_path))
    server, host, port = make_server(cfg, core)

    def shutdown(signum, frame):  # noqa: ARG001
        LOG.info("signal %s received, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, shutdown)
        except (ValueError, OSError):
            pass

    LOG.info("MCP endpoint: http://%s:%s/mcp", host, port)
    srv_thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.5}, daemon=True)
    srv_thread.start()

    oauth_cfg = cfg.get("oauth") or {}
    pub_url = str(oauth_cfg.get("public_base_url") or "").strip()
    if oauth_cfg.get("enabled", True) and pub_url and oauth_cfg.get("startup_tcp_check", False) and not args.skip_tcp_check:
        LOG.info("正在执行公网入口外网双栈 TCP 自检: %s", pub_url)
        chk = verify_public_tcp_reachability(pub_url)
        fam = chk.get("families") or {}
        v6_st = (fam.get("ipv6") or {}).get("state", "-")
        v4_st = (fam.get("ipv4") or {}).get("state", "-")
        st = chk.get("status")
        if st == "reachable":
            LOG.info(
                "[外网自检通过] %s:%s 外网 TCP 可达 (可达栈=%s | IPv6=%s | IPv4=%s)",
                chk.get("host"), chk.get("port"), "/".join(chk.get("reachable_families") or []), v6_st, v4_st,
            )
        elif st == "skipped":
            LOG.info("[外网自检跳过] %s (%s)", pub_url, chk.get("reason"))
        elif st == "unavailable":
            LOG.warning(
                "[外网自检提示] 外部在线 TCP 探测服务暂不可用，无法确认 %s:%s 外网连通性 (IPv6=%s | IPv4=%s)；"
                "已放行启动，请自行确认反代与防火墙。",
                chk.get("host"), chk.get("port"), v6_st, v4_st,
            )
        else:
            LOG.error(
                "[自检锁拦截] 外部在线双栈 TCP 探测显示 %s:%s 无法从外网连通 (IPv6=%s | IPv4=%s)！\n"
                "  此时即使启动服务，Google 也无法连入本机。\n"
                "  请逐项检查：\n"
                "  1) Windows 防火墙是否已以管理员运行 admin\\add-firewall.ps1 放行端口；\n"
                "  2) 路由器端口转发 / lucky 反向代理 / 内网穿透是否开启，且已监听当前最新 IPv6 前缀/域名；\n"
                "  3) oauth.public_base_url 的域名和端口号是否拼写正确。\n"
                "  （若确认只需本机/局域网访问或临时跳过自检，可加 --skip-tcp-check 启动，或在 config.json 将 oauth.startup_tcp_check 设为 false。）",
                chk.get("host"), chk.get("port"), v6_st, v4_st,
            )
            server.shutdown()
            server.server_close()
            return 2
    elif oauth_cfg.get("enabled", True) and pub_url:
        LOG.info(
            "【重要提醒】在设置 Google / Gemini MCP 服务前，请在油猴面板点击「测试公网连通性 (双栈 TCP)」"
            "或运行 python server.py --check-public-url 确认 %s 从外网确实能连入本机。",
            pub_url,
        )

    LOG.info(PER_CONVERSATION_GUIDE_NOTICE)
    try:
        while srv_thread.is_alive():
            srv_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        LOG.info("KeyboardInterrupt, shutting down")
        server.shutdown()
    finally:
        server.server_close()
        LOG.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
