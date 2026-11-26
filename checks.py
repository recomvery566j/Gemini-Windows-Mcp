"""Lightweight post-edit syntax verification and optional structured lint/test feedback."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from output_guard import OutputGuard


def _extract_error_lines(text: str, max_lines: int = 25, max_chars: int = 2000) -> list[str]:
    lines = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    if not lines:
        return []
    # Prefer lines carrying common error/fail markers when log is long
    if len(lines) > max_lines:
        priority = [
            ln for ln in lines
            if any(tok in ln.lower() for tok in ("error", "fail", "exception", "traceback", "syntaxerror", "assert"))
        ]
        chosen = priority[-max_lines:] if priority else lines[-max_lines:]
    else:
        chosen = lines
    out: list[str] = []
    total = 0
    for ln in chosen:
        clipped = ln[:240] + ("..." if len(ln) > 240 else "")
        if total + len(clipped) > max_chars:
            break
        out.append(clipped)
        total += len(clipped) + 1
    return out


class PostEditChecker:
    """Runs fast in-process syntax checks and optional project lint/test commands."""

    def __init__(self, cfg: dict[str, Any], runner):
        ccfg = cfg.get("post_edit_checks") or {}
        self.syntax_enabled = bool(ccfg.get("syntax_check", True))
        self.configured_commands = list(ccfg.get("on_edit_commands") or [])
        self.timeout_sec = max(3, min(int(ccfg.get("command_timeout_sec", 15)), 60))
        self.allow_workspace_file = bool(ccfg.get("allow_workspace_checks_file", True))
        self.runner = runner
        self._node_exe = shutil.which("node") or ""

    def _run_syntax_check(self, file_path: Path) -> dict[str, Any] | None:
        ext = file_path.suffix.lower()
        if ext in (".py", ".pyw"):
            try:
                source = file_path.read_text(encoding="utf-8-sig")
                compile(source, str(file_path), "exec")
                return {"check": "python_syntax", "ok": True}
            except SyntaxError as exc:
                return {
                    "check": "python_syntax",
                    "ok": False,
                    "file": str(file_path),
                    "line": exc.lineno,
                    "col": exc.offset,
                    "message": exc.msg,
                    "line_text": (exc.text or "").rstrip(),
                }
            except Exception as exc:  # noqa: BLE001
                return {"check": "python_syntax", "ok": False, "file": str(file_path), "message": str(exc)}

        if ext == ".json":
            try:
                source = file_path.read_text(encoding="utf-8-sig")
                json.loads(source)
                return {"check": "json_syntax", "ok": True}
            except json.JSONDecodeError as exc:
                return {
                    "check": "json_syntax",
                    "ok": False,
                    "file": str(file_path),
                    "line": exc.lineno,
                    "col": exc.colno,
                    "message": exc.msg,
                }
            except Exception as exc:  # noqa: BLE001
                return {"check": "json_syntax", "ok": False, "file": str(file_path), "message": str(exc)}

        if ext == ".toml" and tomllib is not None:
            try:
                source = file_path.read_text(encoding="utf-8-sig")
                tomllib.loads(source)
                return {"check": "toml_syntax", "ok": True}
            except tomllib.TOMLDecodeError as exc:
                out_err: dict[str, Any] = {
                    "check": "toml_syntax",
                    "ok": False,
                    "file": str(file_path),
                    "message": str(exc),
                }
                if getattr(exc, "lineno", None) is not None:
                    out_err["line"] = exc.lineno
                if getattr(exc, "colno", None) is not None:
                    out_err["col"] = exc.colno
                return out_err
            except Exception as exc:  # noqa: BLE001
                return {"check": "toml_syntax", "ok": False, "file": str(file_path), "message": str(exc)}

        if ext in (".ps1", ".psm1", ".psd1"):
            pwsh = getattr(self.runner, "pwsh_exe", "") or ""
            if not pwsh:
                return None
            try:
                ps_cmd = (
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                    "$p = $env:PCM_CHECK_PS1; "
                    "$c = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8); "
                    "$tok = $null; $err = $null; "
                    "[void][System.Management.Automation.Language.Parser]::ParseInput($c, $p, [ref]$tok, [ref]$err); "
                    "if ($err -and $err.Count -gt 0) { "
                    "  $err | Select-Object -First 8 | ForEach-Object { "
                    "    $ex = $_.Extent; "
                    "    Write-Output ('L{0}:C{1} [{2}] {3}' -f $ex.StartLineNumber, $ex.StartColumnNumber, $_.ErrorId, $_.Message) "
                    "  }; exit 1 "
                    "}; exit 0"
                )
                env = dict(os.environ)
                env["PCM_CHECK_PS1"] = str(file_path)
                proc = subprocess.run(
                    [pwsh, "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if proc.returncode == 0:
                    return {"check": "powershell_syntax", "ok": True}
                err_txt = (proc.stdout or proc.stderr or b"").decode("utf-8", "replace")
                return {
                    "check": "powershell_syntax",
                    "ok": False,
                    "file": str(file_path),
                    "exit_code": proc.returncode,
                    "error_lines": _extract_error_lines(err_txt, max_lines=12, max_chars=1200),
                }
            except Exception:  # noqa: BLE001
                return None

        if ext in (".js", ".mjs", ".cjs") and self._node_exe:
            try:
                proc = subprocess.run(
                    [self._node_exe, "--check", str(file_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if proc.returncode == 0:
                    return {"check": "node_syntax", "ok": True}
                err_txt = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace")
                return {
                    "check": "node_syntax",
                    "ok": False,
                    "file": str(file_path),
                    "exit_code": proc.returncode,
                    "error_lines": _extract_error_lines(err_txt, max_lines=12, max_chars=1200),
                }
            except Exception:  # noqa: BLE001
                return None
        return None

    def _load_workspace_checks(self, active_ws: Path) -> dict[str, Any] | None:
        if not self.allow_workspace_file:
            return None
        cfg_file = active_ws / ".gemini" / "checks.json"
        if not cfg_file.is_file():
            return None
        try:
            data = json.loads(cfg_file.read_text(encoding="utf-8-sig"))
            return data if isinstance(data, dict) else None
        except Exception:  # noqa: BLE001
            return None

    def _run_command_spec(
        self,
        spec: dict[str, Any],
        *,
        active_ws: Path,
        default_timeout: int,
        output_guard: OutputGuard | None,
    ) -> dict[str, Any]:
        name = str(spec.get("name") or "check").strip()
        engine = str(spec.get("engine") or "powershell").strip().lower()
        cmd = str(spec.get("cmd") or spec.get("command") or "").strip()
        timeout = max(3, min(int(spec.get("timeout_sec") or default_timeout), 60))
        if not cmd:
            return {"name": name, "ok": True, "skipped": "empty_command"}

        if engine == "python":
            res = self.runner.run_python(cmd, timeout, str(active_ws))
        elif engine == "bash":
            res = self.runner.run_bash(cmd, timeout, str(active_ws))
        else:
            res = self.runner.run_powershell(cmd, timeout, str(active_ws))

        ok = res.get("exit_code") == 0 and not res.get("timed_out")
        if ok:
            return {
                "name": name,
                "ok": True,
                "exit_code": 0,
                "duration_sec": res.get("duration_sec"),
            }

        combined = "\n".join(part for part in (res.get("stdout"), res.get("stderr"), res.get("error")) if part)
        log_path = None
        if output_guard is not None and len(combined) > 2400:
            _, p = output_guard.format_or_bypass(combined, prefix=f"check_{name}")
            if p is not None:
                log_path = str(p)
        out: dict[str, Any] = {
            "name": name,
            "ok": False,
            "command": cmd,
            "exit_code": res.get("exit_code"),
            "timed_out": bool(res.get("timed_out")),
            "duration_sec": res.get("duration_sec"),
            "error_lines": _extract_error_lines(combined),
        }
        if log_path:
            out["full_log"] = log_path
        return out

    def run_for_file(
        self,
        file_path: Path,
        *,
        active_ws: Path,
        allow_workspace_commands: bool = False,
        run_checks: bool | None = None,
        auto_check: bool = True,
        output_guard: OutputGuard | None = None,
    ) -> dict[str, Any] | None:
        """Verify syntax and optionally run configured project lint/test commands."""
        if not auto_check and run_checks is not True:
            return None

        syntax_res = self._run_syntax_check(file_path) if self.syntax_enabled else None

        cmd_results: list[dict[str, Any]] = []
        skipped_reason: str | None = None
        ext = file_path.suffix.lower()

        def matches_ext(spec: dict[str, Any]) -> bool:
            exts = spec.get("extensions")
            if not exts:
                return True
            norm = {str(e).lower() if str(e).startswith(".") else f".{str(e).lower()}" for e in exts}
            return ext in norm

        # 1) Server config.json commands (trusted by local operator)
        for spec in self.configured_commands:
            if not isinstance(spec, dict):
                continue
            if run_checks is False:
                continue
            if not spec.get("on_edit", True) and run_checks is not True:
                continue
            if run_checks is not True and not matches_ext(spec):
                continue
            cmd_results.append(
                self._run_command_spec(
                    spec, active_ws=active_ws, default_timeout=self.timeout_sec, output_guard=output_guard,
                )
            )

        # 2) Workspace .gemini/checks.json commands (requires exec capability!)
        ws_checks = self._load_workspace_checks(active_ws)
        if ws_checks and ws_checks.get("enabled", True) and run_checks is not False:
            want_ws_run = bool(ws_checks.get("on_edit", False)) or (run_checks is True)
            raw_cmds = [c for c in (ws_checks.get("commands") or []) if isinstance(c, dict)]
            applicable = [c for c in raw_cmds if (run_checks is True or matches_ext(c))]
            if want_ws_run and applicable:
                if not allow_workspace_commands:
                    skipped_reason = "workspace_checks_require_exec_capability"
                else:
                    ws_timeout = max(3, min(int(ws_checks.get("timeout_sec") or self.timeout_sec), 60))
                    for spec in applicable:
                        cmd_results.append(
                            self._run_command_spec(
                                spec, active_ws=active_ws, default_timeout=ws_timeout, output_guard=output_guard,
                            )
                        )

        if syntax_res is None and not cmd_results and not skipped_reason:
            return None

        overall_ok = (syntax_res["ok"] if syntax_res is not None else True) and all(
            c.get("ok", True) for c in cmd_results
        )
        out: dict[str, Any] = {"ok": overall_ok}
        if syntax_res is not None:
            out["syntax"] = f"{syntax_res['check']}: ok" if syntax_res["ok"] else syntax_res
        if cmd_results:
            out["commands"] = cmd_results
        if skipped_reason:
            out["note"] = skipped_reason
        return out
