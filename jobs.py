"""Asynchronous background job manager for long-running tasks."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

from output_guard import OutputGuard

LOG = logging.getLogger("pc-work-mcp.jobs")
IS_WINDOWS = os.name == "nt"


def popen_platform_kwargs() -> dict:
    if IS_WINDOWS:
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if IS_WINDOWS:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def _decode_bytes(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


class JobManager:
    """Manages detached background jobs with log files and process-tree termination."""

    def __init__(self, tmp_outputs_dir: Path, output_guard: OutputGuard):
        self.tmp_outputs_dir = tmp_outputs_dir
        self.output_guard = output_guard
        self.lock = threading.Lock()
        self.jobs: dict[str, dict] = {}

    def start_job(
        self,
        engine: str,
        code: str,
        workdir: str,
        runner,
        *,
        tmp_outputs_dir: Path | None = None,
        output_guard: OutputGuard | None = None,
    ) -> dict:
        engine = engine.strip().lower()
        if engine not in ("powershell", "python", "bash"):
            raise ValueError("engine must be one of: powershell, python, bash")

        out_dir = tmp_outputs_dir or self.tmp_outputs_dir
        out_dir.mkdir(parents=True, exist_ok=True)
        job_id = uuid.uuid4().hex[:12]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = out_dir / f"job_{ts}_{job_id}.log"

        cmd, script_path, env = self._prepare_command(engine, code, runner)
        log_fh = open(log_path, "wb")
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                env=env,
                **popen_platform_kwargs(),
            )
        except Exception:
            log_fh.close()
            try:
                os.unlink(script_path)
            except OSError:
                pass
            raise

        rec = {
            "job_id": job_id,
            "engine": engine,
            "pid": proc.pid,
            "cwd": workdir,
            "log_path": str(log_path),
            "output_guard": output_guard or self.output_guard,
            "started_at": time.time(),
            "ended_at": None,
            "exit_code": None,
            "killed": False,
            "proc": proc,
        }
        with self.lock:
            self.jobs[job_id] = rec

        t = threading.Thread(
            target=self._wait_and_cleanup,
            args=(job_id, proc, log_fh, script_path),
            daemon=True,
        )
        t.start()

        return {
            "job_id": job_id,
            "engine": engine,
            "pid": proc.pid,
            "status": "running",
            "cwd": workdir,
            "log_path": str(log_path),
        }

    def _prepare_command(self, engine: str, code: str, runner) -> tuple[list[str], str, dict]:
        env = os.environ.copy()
        if engine == "powershell":
            preamble = (
                "$ErrorActionPreference = 'Continue'\n"
                "$ProgressPreference = 'SilentlyContinue'\n"
                "if ($null -ne $PSStyle) { $PSStyle.OutputRendering = 'PlainText' }\n"
            )
            tail = "\nif ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } else { exit 0 }\n"
            fd, script_path = tempfile.mkstemp(prefix="pc_job_pwsh_", suffix=".ps1")
            with os.fdopen(fd, "w", encoding="utf-8-sig", newline="\r\n") as fh:
                fh.write(preamble + code + tail)
            cmd = [runner.pwsh_exe, "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-File", script_path]
            return cmd, script_path, env

        if engine == "python":
            fd, script_path = tempfile.mkstemp(prefix="pc_job_py_", suffix=".py")
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(code)
            env["PYTHONIOENCODING"] = "utf-8"
            return [runner.python_exe, "-u", script_path], script_path, env

        if not runner.bash_exe:
            raise ValueError("Git Bash executable not found on this machine")
        fd, script_path = tempfile.mkstemp(prefix="pc_job_sh_", suffix=".sh")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(code)
        git_usr_bin = str(Path(runner.bash_exe).parent)
        cur_path = env.get("PATH", "")
        if git_usr_bin not in cur_path:
            env["PATH"] = f"{git_usr_bin};{cur_path}"
        env["LANG"] = "C.UTF-8"
        return [runner.bash_exe, "--noprofile", "--norc", script_path], script_path, env

    def _wait_and_cleanup(self, job_id: str, proc: subprocess.Popen, log_fh, script_path: str) -> None:
        try:
            rc = proc.wait()
        except Exception:  # noqa: BLE001
            rc = -1
        finally:
            try:
                log_fh.close()
            except OSError:
                pass
            try:
                os.unlink(script_path)
            except OSError:
                pass

        with self.lock:
            rec = self.jobs.get(job_id)
            if rec:
                rec["exit_code"] = rc
                rec["ended_at"] = time.time()

    def get_status(self, job_id: str, tail_lines: int = 50) -> dict:
        with self.lock:
            rec = self.jobs.get(job_id)
            if not rec:
                raise ValueError(f"unknown job_id: {job_id}")
            proc = rec["proc"]
            rc = proc.poll()
            if rc is not None and rec["exit_code"] is None:
                rec["exit_code"] = rc
                rec["ended_at"] = rec["ended_at"] or time.time()
            killed = rec["killed"]
            exit_code = rec["exit_code"]
            started = rec["started_at"]
            ended = rec["ended_at"]
            log_path = Path(rec["log_path"])
            guard = rec.get("output_guard") or self.output_guard
            engine = rec["engine"]
            pid = rec["pid"]
            cwd = rec["cwd"]

        if exit_code is None:
            status = "running"
        elif killed:
            status = "killed"
        elif exit_code == 0:
            status = "completed"
        else:
            status = "failed"

        duration = round((ended or time.time()) - started, 2)
        tail_text = ""
        if log_path.is_file():
            raw = log_path.read_bytes()
            full_text = _decode_bytes(raw)
            lines = full_text.splitlines()
            n = max(1, min(int(tail_lines or 50), 500))
            snippet = "\n".join(lines[-n:])
            tail_text, _ = guard.format_or_bypass(snippet, prefix=f"jobtail_{job_id}")

        return {
            "job_id": job_id,
            "engine": engine,
            "pid": pid,
            "status": status,
            "exit_code": exit_code,
            "duration_sec": duration,
            "cwd": cwd,
            "log_path": str(log_path),
            "tail_output": tail_text,
        }

    def kill_job(self, job_id: str) -> dict:
        with self.lock:
            rec = self.jobs.get(job_id)
            if not rec:
                raise ValueError(f"unknown job_id: {job_id}")
            rec["killed"] = True
            proc = rec["proc"]
        kill_tree(proc)
        return self.get_status(job_id, tail_lines=20)

    def list_active(self) -> list[dict]:
        with self.lock:
            items = list(self.jobs.values())
        active = []
        now = time.time()
        for rec in items:
            if rec["proc"].poll() is None:
                active.append({
                    "job_id": rec["job_id"],
                    "engine": rec["engine"],
                    "pid": rec["pid"],
                    "duration_sec": round(now - rec["started_at"], 2),
                })
        return active
