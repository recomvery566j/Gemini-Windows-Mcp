"""Browser Userscript Bridge manager for pc-work-mcp.

Tracks active browser tabs/conversation IDs (including Turn-1 sessions where
the conversation ID does not exist yet until the first reply completes) and
orchestrates asynchronous media upload/export tasks with Tampermonkey.
"""

from __future__ import annotations

import logging
import mimetypes
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any

LOG = logging.getLogger("pc-work-mcp.bridge")

_CID_SAFE_RE = re.compile(r"^[A-Za-z0-9_-]{4,128}$")


def sanitize_filename(name: str, default: str = "media.bin") -> str:
    clean = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(name or "").strip())
    clean = clean.strip(". ")
    return clean or default


class BridgeManager:
    """Thread-safe coordinator between MCP tool calls and Tampermonkey clients."""

    def __init__(
        self,
        snapshot_mgr=None,
        permission_mgr=None,
        rules_mgr=None,
        workspace_mgr=None,
        task_plan_mgr=None,
        tab_ttl_sec: float = 30.0,
        task_ttl_sec: float = 1800.0,
    ):
        self.snapshot_mgr = snapshot_mgr
        self.permission_mgr = permission_mgr
        self.rules_mgr = rules_mgr
        self.workspace_mgr = workspace_mgr
        self.task_plan_mgr = task_plan_mgr
        self.tab_ttl_sec = max(5.0, float(tab_ttl_sec))
        self.task_ttl_sec = max(60.0, float(task_ttl_sec))
        self.lock = threading.Lock()
        self.tabs: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, dict[str, Any]] = {}
        self.ignore_suggestions: dict[str, dict[str, Any]] = {}
        self.active_tab_id: str | None = None
        self.active_conversation_id: str | None = None

    def _prune_locked(self, now: float) -> None:
        stale_tabs = [tid for tid, rec in self.tabs.items() if (now - rec["updated_at"]) > self.tab_ttl_sec]
        for tid in stale_tabs:
            self.tabs.pop(tid, None)
        if self.active_tab_id and self.active_tab_id not in self.tabs:
            self.active_tab_id = None
            if self.tabs:
                latest = max(self.tabs.values(), key=lambda r: r["updated_at"])
                self.active_tab_id = latest["tab_id"]

        stale_tasks = [
            kid for kid, task in self.tasks.items()
            if task["status"] in ("completed", "failed", "cancelled") and (now - task["updated_at"]) > self.task_ttl_sec
        ]
        for kid in stale_tasks:
            self.tasks.pop(kid, None)

        stale_sugs = [
            sid for sid, s in self.ignore_suggestions.items()
            if (now - s["created_at"]) > 600.0
        ]
        for sid in stale_sugs:
            self.ignore_suggestions.pop(sid, None)

    def heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        tab_id = str(payload.get("tab_id") or "").strip()
        if not tab_id:
            raise ValueError("tab_id is required")

        raw_cid = payload.get("conversation_id")
        cid = str(raw_cid).strip() if raw_cid else None
        if cid and not _CID_SAFE_RE.match(cid):
            cid = None
        url = str(payload.get("url") or "")
        # Ignore internal subframes (e.g., https://gemini.google.com/_/bscframe) that share sessionStorage
        if "/_/" in url:
            return {
                "ok": True,
                "ignored": True,
                "tab_id": tab_id,
                "conversation_id": cid,
                "active_conversation_id": self.active_conversation_id,
                "resolved_tasks": [],
            }

        now = time.time()
        with self.lock:
            self._prune_locked(now)
            prev = self.tabs.get(tab_id)
            rec = {
                "tab_id": tab_id,
                "conversation_id": cid,
                "url": url,
                "title": str(payload.get("title") or ""),
                "is_generating": bool(payload.get("is_generating", False)),
                "focused": bool(payload.get("focused", False)),
                "updated_at": now,
                "first_seen_at": prev["first_seen_at"] if prev else now,
            }
            self.tabs[tab_id] = rec

            # Update active pointers when tab is focused, generating, changed cid, or first seen
            if (
                self.active_tab_id is None
                or self.active_tab_id == tab_id
                or rec["focused"]
                or rec["is_generating"]
                or (prev is None)
                or (prev and prev.get("conversation_id") != cid and cid)
            ):
                self.active_tab_id = tab_id
                if cid:
                    self.active_conversation_id = cid

            if prev is None:
                LOG.info("bridge tab connected: %s cid=%s", tab_id, cid or "(pending)")
            elif prev.get("conversation_id") != cid:
                LOG.info("bridge tab %s cid updated: %s -> %s", tab_id, prev.get("conversation_id") or "(none)", cid or "(none)")

            # Resolve any Turn-1 tasks waiting for this tab (or sole active /app tab) to receive its cid!
            resolved_ids: list[str] = []
            if cid:
                for task in self.tasks.values():
                    if task["status"] == "awaiting_cid":
                        bound_tab = task.get("target_tab_id")
                        if bound_tab == tab_id or not bound_tab or bound_tab not in self.tabs:
                            task["target_conversation_id"] = cid
                            task["target_tab_id"] = tab_id
                            task["status"] = "queued"
                            task["updated_at"] = now
                            resolved_ids.append(task["task_id"])
                for sug in self.ignore_suggestions.values():
                    if not sug.get("conversation_id") and (
                        sug.get("tab_id") == tab_id or not sug.get("tab_id") or sug.get("tab_id") not in self.tabs
                    ):
                        sug["conversation_id"] = cid
                        sug["tab_id"] = tab_id

        effective_policy = None
        pending_approvals: list[dict[str, Any]] = []
        rules_status: dict[str, Any] | None = None
        workspace_binding: dict[str, Any] | None = None
        prev_cid = prev.get("conversation_id") if prev else None
        title_str = str(payload.get("title") or "")
        if self.permission_mgr is not None:
            if cid:
                self.permission_mgr.bind_tab_to_conversation(
                    tab_id, cid, url=url, title=title_str,
                )
            elif prev_cid:
                self.permission_mgr.bind_tab_to_conversation(
                    tab_id, None, url=url, title=title_str,
                )
            effective_policy = self.permission_mgr.get_effective_policy(
                cid=cid, tab_id=tab_id, url=url, title=title_str,
            )
            pending_approvals = self.permission_mgr.list_pending_for_tab(tab_id, cid)

        active_ws_dir: Path | None = None
        if self.workspace_mgr is not None:
            if cid:
                self.workspace_mgr.bind_tab_to_conversation(tab_id, cid, url=url, title=title_str)
            elif prev_cid:
                self.workspace_mgr.bind_tab_to_conversation(tab_id, None, url=url, title=title_str)
            workspace_binding = self.workspace_mgr.get_effective_workspace(cid=cid, tab_id=tab_id)
            active_ws_dir = Path(workspace_binding["workspace_dir"])

        if self.rules_mgr is not None:
            if cid:
                self.rules_mgr.bind_tab_to_conversation(tab_id, cid)
            elif prev_cid:
                self.rules_mgr.bind_tab_to_conversation(tab_id, None)
            skey = f"cid:{cid}" if cid else f"tab:{tab_id}"
            rules_status = self.rules_mgr.peek_status(
                session_key=skey, cid=cid, tab_id=tab_id, default_rules_dir=active_ws_dir,
            )

        task_plan_view: dict[str, Any] | None = None
        if self.task_plan_mgr is not None:
            if cid:
                self.task_plan_mgr.bind_tab_to_conversation(tab_id, cid)
            elif prev_cid:
                self.task_plan_mgr.bind_tab_to_conversation(tab_id, None)
            task_plan_view = self.task_plan_mgr.get_plan(cid=cid, tab_id=tab_id).get("plan")

        return {
            "ok": True,
            "tab_id": tab_id,
            "conversation_id": cid,
            "active_conversation_id": self.active_conversation_id,
            "resolved_tasks": resolved_ids,
            "per_conversation_enabled": bool(self.permission_mgr and self.permission_mgr.enabled),
            "effective_policy": effective_policy,
            "pending_approvals": pending_approvals,
            "pending_ignore_suggestions": self.list_pending_ignore_suggestions(tab_id, cid),
            "rules_status": rules_status,
            "workspace_binding": workspace_binding,
            "task_plan": task_plan_view,
        }

    def resolve_caller_window(self, grace_sec: float = 0.45) -> dict[str, Any]:
        """Identify the calling Gemini browser tab/conversation from live heartbeats."""
        active_ttl = min(self.tab_ttl_sec, 12.0)

        def inspect() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            now = time.time()
            with self.lock:
                self._prune_locked(now)
                live = [
                    dict(r) for r in self.tabs.values()
                    if (now - r["updated_at"]) <= active_ttl
                ]
            gen = [r for r in live if r.get("is_generating")]
            return live, gen

        live, gen = inspect()
        if not live:
            return {"status": "no_bridge"}

        if not gen and grace_sec > 0:
            deadline = time.time() + min(grace_sec, 1.0)
            while time.time() < deadline:
                time.sleep(0.08)
                live, gen = inspect()
                if not live or gen:
                    break

        if not live:
            return {"status": "no_bridge"}
        if len(gen) == 1:
            return {"status": "matched", "confidence": "generating_unique", "tab": gen[0]}
        if len(gen) > 1:
            return {"status": "ambiguous", "reason": "multiple_generating_tabs", "candidates": gen}
        if len(live) == 1:
            return {"status": "matched", "confidence": "single_live_tab", "tab": live[0]}
        return {"status": "ambiguous", "reason": "multiple_idle_tabs", "candidates": live}

    def _pick_target_locked(self, requested_cid: str | None) -> tuple[str | None, str | None, bool]:
        """Returns (target_cid, target_tab_id, awaiting_cid)."""
        cid = str(requested_cid or "").strip() or None
        if cid:
            for tab in self.tabs.values():
                if tab.get("conversation_id") == cid:
                    return cid, tab["tab_id"], False
            return cid, None, False

        if self.active_tab_id and self.active_tab_id in self.tabs:
            tab = self.tabs[self.active_tab_id]
            if tab.get("conversation_id"):
                return tab["conversation_id"], tab["tab_id"], False
            # Turn-1 special case: tab is open on /app before first reply assigns an ID!
            return None, tab["tab_id"], True

        if self.tabs:
            latest = max(self.tabs.values(), key=lambda r: r["updated_at"])
            if latest.get("conversation_id"):
                return latest["conversation_id"], latest["tab_id"], False
            return None, latest["tab_id"], True

        if self.active_conversation_id:
            return self.active_conversation_id, None, False

        # No live tab yet -> keep awaiting_cid so as soon as a tab connects/settles, it can bind
        return None, None, True

    def enqueue_upload(
        self,
        files: list[Path],
        prompt: str = "",
        conversation_id: str | None = None,
        delay_sec: int = 2,
        auto_send: bool = True,
        tool_mode: str = "none",
    ) -> dict[str, Any]:
        if not files:
            raise ValueError("at least one file is required")
        file_specs = []
        for idx, p in enumerate(files):
            resolved = p.resolve()
            if not resolved.is_file():
                raise ValueError(f"file not found: {resolved}")
            mime, _ = mimetypes.guess_type(str(resolved))
            file_specs.append({
                "index": idx,
                "path": str(resolved),
                "name": resolved.name,
                "mime": mime or "application/octet-stream",
                "size_bytes": resolved.stat().st_size,
            })

        now = time.time()
        task_id = "upl_" + uuid.uuid4().hex[:12]
        with self.lock:
            self._prune_locked(now)
            target_cid, target_tab_id, awaiting = self._pick_target_locked(conversation_id)
            task = {
                "task_id": task_id,
                "kind": "upload_media",
                "status": "awaiting_cid" if awaiting else "queued",
                "target_conversation_id": target_cid,
                "target_tab_id": target_tab_id,
                "claimed_by_tab": None,
                "open_dispatched": False,
                "files": file_specs,
                "prompt": str(prompt or ""),
                "delay_sec": max(1, min(int(delay_sec or 2), 30)),
                "auto_send": bool(auto_send),
                "tool_mode": str(tool_mode or "none").lower(),
                "created_at": now,
                "updated_at": now,
                "result": None,
                "error": None,
            }
            self.tasks[task_id] = task
            return self._public_task(task)

    def enqueue_save_media(
        self,
        target_path: Path,
        is_dir: bool,
        media_kind: str = "auto",
        trigger_prompt: str = "",
        conversation_id: str | None = None,
        delay_sec: int = 2,
        timeout_sec: int = 240,
        snapshot_mgr=None,
    ) -> dict[str, Any]:
        now = time.time()
        task_id = "sav_" + uuid.uuid4().hex[:12]
        with self.lock:
            self._prune_locked(now)
            target_cid, target_tab_id, awaiting = self._pick_target_locked(conversation_id)
            task = {
                "task_id": task_id,
                "kind": "save_media",
                "status": "awaiting_cid" if awaiting else "queued",
                "target_conversation_id": target_cid,
                "target_tab_id": target_tab_id,
                "claimed_by_tab": None,
                "open_dispatched": False,
                "target_path": str(target_path),
                "is_dir": bool(is_dir),
                "media_kind": str(media_kind or "auto").lower(),
                "trigger_prompt": str(trigger_prompt or ""),
                "delay_sec": max(1, min(int(delay_sec or 2), 30)),
                "timeout_sec": max(15, min(int(timeout_sec or 240), 600)),
                "saved_files": [],
                "created_at": now,
                "updated_at": now,
                "result": None,
                "error": None,
                "_snapshot_mgr": snapshot_mgr,
            }
            self.tasks[task_id] = task
            return self._public_task(task)

    def enqueue_continue_turn(
        self,
        *,
        prompt: str,
        conversation_id: str | None = None,
        delay_sec: int = 8,
        jitter_max_sec: int = 3,
        turn_index: int = 1,
        max_auto_turns: int = 5,
    ) -> dict[str, Any]:
        clean_prompt = str(prompt or "").strip()
        if not clean_prompt:
            raise ValueError("continue prompt is required")
        now = time.time()
        task_id = "cnt_" + uuid.uuid4().hex[:12]
        with self.lock:
            self._prune_locked(now)
            target_cid, target_tab_id, awaiting = self._pick_target_locked(conversation_id)
            for old in self.tasks.values():
                if old.get("kind") != "continue_turn":
                    continue
                if old.get("status") not in ("awaiting_cid", "queued"):
                    continue
                if (target_cid and old.get("target_conversation_id") == target_cid) or (
                    not target_cid and target_tab_id and old.get("target_tab_id") == target_tab_id
                ):
                    old["status"] = "cancelled"
                    old["error"] = "superseded_by_newer_continue"
                    old["updated_at"] = now

            task = {
                "task_id": task_id,
                "kind": "continue_turn",
                "status": "awaiting_cid" if awaiting else "queued",
                "target_conversation_id": target_cid,
                "target_tab_id": target_tab_id,
                "claimed_by_tab": None,
                "open_dispatched": False,
                "prompt": clean_prompt,
                "delay_sec": max(5, min(int(delay_sec or 8), 60)),
                "jitter_max_sec": max(0, min(int(jitter_max_sec or 3), 10)),
                "turn_index": int(turn_index),
                "max_auto_turns": int(max_auto_turns),
                "created_at": now,
                "updated_at": now,
                "result": None,
                "error": None,
            }
            self.tasks[task_id] = task
            return self._public_task(task)

    def cancel_continue_tasks(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        task_id: str | None = None,
        reason: str = "cancelled",
    ) -> list[str]:
        now = time.time()
        cancelled: list[str] = []
        with self.lock:
            for t in self.tasks.values():
                if t.get("kind") != "continue_turn":
                    continue
                if t.get("status") not in ("awaiting_cid", "queued", "running"):
                    continue
                matched = False
                if task_id and t.get("task_id") == task_id:
                    matched = True
                elif conversation_id and t.get("target_conversation_id") == conversation_id:
                    matched = True
                elif tab_id and (t.get("target_tab_id") == tab_id or t.get("claimed_by_tab") == tab_id):
                    matched = True
                elif not task_id and not conversation_id and not tab_id:
                    matched = True
                if matched:
                    t["status"] = "cancelled"
                    t["error"] = reason
                    t["updated_at"] = now
                    cancelled.append(t["task_id"])
        return cancelled

    def poll_tasks(self, tab_id: str, conversation_id: str | None = None) -> dict[str, Any]:
        tab_id = str(tab_id or "").strip()
        cid = str(conversation_id or "").strip() or None
        now = time.time()
        with self.lock:
            self._prune_locked(now)
            prev_tab_cid = self.tabs[tab_id].get("conversation_id") if tab_id in self.tabs else None
            if tab_id in self.tabs:
                self.tabs[tab_id]["updated_at"] = now
                if cid:
                    self.tabs[tab_id]["conversation_id"] = cid
                    self.active_conversation_id = cid
        if self.permission_mgr is not None and prev_tab_cid != cid and cid:
            self.permission_mgr.bind_tab_to_conversation(tab_id, cid)
        if self.workspace_mgr is not None and prev_tab_cid != cid and cid:
            self.workspace_mgr.bind_tab_to_conversation(tab_id, cid)
        if self.rules_mgr is not None and prev_tab_cid != cid and cid:
            self.rules_mgr.bind_tab_to_conversation(tab_id, cid)
        if self.task_plan_mgr is not None and prev_tab_cid != cid and cid:
            self.task_plan_mgr.bind_tab_to_conversation(tab_id, cid)

        with self.lock:

            leader_tab_id = self.active_tab_id
            if not leader_tab_id and self.tabs:
                leader_tab_id = max(self.tabs.values(), key=lambda r: r["updated_at"])["tab_id"]

            actions: list[dict[str, Any]] = []
            for task in self.tasks.values():
                if task["status"] != "queued":
                    continue
                target_cid = task.get("target_conversation_id")

                # Case 1: Current tab is already on the target conversation ID -> claim and run!
                if target_cid and cid == target_cid:
                    task["status"] = "running"
                    task["claimed_by_tab"] = tab_id
                    task["updated_at"] = now
                    actions.append({"action": task["kind"], "task": self._public_task(task)})
                    break

                # Case 2: Target conversation ID is NOT open in any live tab -> leader tab opens it!
                if target_cid and not task.get("open_dispatched"):
                    cid_open_anywhere = any(t.get("conversation_id") == target_cid for t in self.tabs.values())
                    if not cid_open_anywhere and tab_id == leader_tab_id:
                        task["open_dispatched"] = True
                        task["updated_at"] = now
                        actions.append({
                            "action": "open_conversation",
                            "conversation_id": target_cid,
                            "url": f"https://gemini.google.com/app/{target_cid}",
                            "task_id": task["task_id"],
                        })
                        break

                # Case 3: No target_cid (fallback if bound to this tab without cid)
                if not target_cid and task.get("target_tab_id") == tab_id:
                    task["status"] = "running"
                    task["claimed_by_tab"] = tab_id
                    task["updated_at"] = now
                    actions.append({"action": task["kind"], "task": self._public_task(task)})
                    break

            return {
                "ok": True,
                "tab_id": tab_id,
                "conversation_id": cid,
                "actions": actions,
                "per_conversation_enabled": bool(self.permission_mgr and self.permission_mgr.enabled),
                "effective_policy": (
                    self.permission_mgr.get_effective_policy(cid=cid, tab_id=tab_id)
                    if self.permission_mgr is not None else None
                ),
                "pending_approvals": (
                    self.permission_mgr.list_pending_for_tab(tab_id, cid)
                    if self.permission_mgr is not None else []
                ),
                "pending_ignore_suggestions": self._list_pending_ignore_suggestions_locked(tab_id, cid, now),
            }

    def get_upload_file(self, task_id: str, index: int) -> dict[str, Any] | None:
        with self.lock:
            task = self.tasks.get(task_id)
            if not task or task.get("kind") != "upload_media":
                return None
            files = task.get("files") or []
            if index < 0 or index >= len(files):
                return None
            return dict(files[index])

    def save_uploaded_artifact(
        self,
        task_id: str,
        raw_bytes: bytes,
        filename: str = "",
        mime_type: str = "",
        index: int = 0,
    ) -> dict[str, Any]:
        if not raw_bytes:
            raise ValueError("empty artifact payload")
        with self.lock:
            task = self.tasks.get(task_id)
            if not task or task.get("kind") != "save_media":
                raise ValueError(f"unknown save_media task: {task_id}")
            target_path = Path(task["target_path"])
            is_dir = bool(task["is_dir"])
            existing_count = len(task["saved_files"])
            snap_mgr = task.get("_snapshot_mgr") or self.snapshot_mgr

        ext = mimetypes.guess_extension((mime_type or "").split(";")[0].strip()) or ".bin"
        if ext == ".jpe":
            ext = ".jpg"

        if is_dir:
            target_path.mkdir(parents=True, exist_ok=True)
            if filename:
                safe_name = sanitize_filename(filename, f"gemini_media_{index}{ext}")
                if "." not in safe_name:
                    safe_name += ext
            else:
                ts = time.strftime("%Y%m%d_%H%M%S")
                safe_name = f"gemini_{ts}_{index}{ext}"
            dst = target_path / safe_name
            if dst.exists() and existing_count > 0:
                dst = target_path / f"{dst.stem}_{index}{dst.suffix}"
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if index == 0 and existing_count == 0:
                dst = target_path
            else:
                dst = target_path.with_name(f"{target_path.stem}_{index}{target_path.suffix}")

        if snap_mgr is not None:
            snap_mgr.backup(dst)
        dst.write_bytes(raw_bytes)

        saved_rec = {
            "path": str(dst.resolve()),
            "size_bytes": len(raw_bytes),
            "mime_type": mime_type or "application/octet-stream",
        }
        with self.lock:
            task = self.tasks.get(task_id)
            if task:
                task["saved_files"].append(saved_rec)
                task["updated_at"] = time.time()
        return saved_rec

    def report_task_result(self, payload: dict[str, Any]) -> dict[str, Any]:
        task_id = str(payload.get("task_id") or "").strip()
        status = str(payload.get("status") or "").strip().lower()
        if not task_id or status not in ("running", "completed", "failed", "cancelled"):
            raise ValueError("task_id and valid status (running/completed/failed/cancelled) are required")
        now = time.time()
        task_kind = ""
        task_cid = None
        task_tab = None
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                raise ValueError(f"unknown task_id: {task_id}")
            if task["status"] == "cancelled" and status != "cancelled":
                return self._public_task(task)
            task["status"] = status
            task["updated_at"] = now
            if payload.get("conversation_id"):
                task["target_conversation_id"] = str(payload["conversation_id"]).strip()
            if payload.get("result") is not None:
                task["result"] = payload.get("result")
            if payload.get("error"):
                task["error"] = str(payload.get("error"))
            task_kind = str(task.get("kind") or "")
            task_cid = task.get("target_conversation_id")
            task_tab = task.get("claimed_by_tab") or task.get("target_tab_id")
            pub = self._public_task(task)

        if (
            task_kind == "continue_turn"
            and status in ("completed", "failed", "cancelled")
            and self.task_plan_mgr is not None
        ):
            self.task_plan_mgr.mark_continue_result(
                cid=task_cid, tab_id=task_tab, task_id=task_id, status=status,
            )
        return pub

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            task = self.tasks.get(task_id)
            return self._public_task(task) if task else None

    def status_snapshot(self) -> dict[str, Any]:
        now = time.time()
        with self.lock:
            self._prune_locked(now)
            tabs = []
            for rec in sorted(self.tabs.values(), key=lambda r: r["updated_at"], reverse=True):
                item = {
                    "tab_id": rec["tab_id"],
                    "conversation_id": rec["conversation_id"],
                    "url": rec["url"],
                    "title": rec["title"],
                    "is_generating": rec["is_generating"],
                    "focused": rec.get("focused", False),
                    "age_sec": round(now - rec["updated_at"], 1),
                }
                if self.permission_mgr is not None:
                    pol = self.permission_mgr.get_effective_policy(
                        cid=rec["conversation_id"],
                        tab_id=rec["tab_id"],
                        url=rec["url"],
                        title=rec["title"],
                    )
                    item["permission_profile"] = pol.get("profile")
                    item["permission_capabilities"] = list(pol.get("capabilities") or [])
                if self.workspace_mgr is not None:
                    wb = self.workspace_mgr.get_effective_workspace(
                        cid=rec["conversation_id"],
                        tab_id=rec["tab_id"],
                    )
                    item["workspace_dir"] = wb.get("workspace_dir")
                    item["workspace_is_custom"] = bool(wb.get("is_custom"))
                tabs.append(item)
            recent_tasks = [
                self._public_task(t)
                for t in sorted(self.tasks.values(), key=lambda x: x["updated_at"], reverse=True)[:20]
            ]
            return {
                "connected_tabs": len(tabs),
                "active_tab_id": self.active_tab_id,
                "active_conversation_id": self.active_conversation_id,
                "tabs": tabs,
                "tasks": recent_tasks,
            }

    def enqueue_ignore_suggestion(
        self,
        *,
        dirs: list[str],
        reason: str = "",
        conversation_id: str | None = None,
        tab_id: str | None = None,
        workspace_dir: str = "",
    ) -> dict[str, Any]:
        now = time.time()
        sug_id = "ign_" + uuid.uuid4().hex[:12]
        clean_dirs = [str(d).strip() for d in dirs if str(d).strip()]
        with self.lock:
            self._prune_locked(now)
            target_cid = str(conversation_id or "").strip() or None
            target_tab = str(tab_id or "").strip() or None
            if not target_cid and not target_tab:
                target_cid, target_tab, _ = self._pick_target_locked(None)
            rec = {
                "suggestion_id": sug_id,
                "dirs": clean_dirs,
                "reason": str(reason or "").strip(),
                "workspace_dir": str(workspace_dir or ""),
                "conversation_id": target_cid,
                "tab_id": target_tab,
                "created_at": now,
            }
            self.ignore_suggestions[sug_id] = rec
            return dict(rec)

    def _list_pending_ignore_suggestions_locked(self, tab_id: str, cid: str | None, now: float) -> list[dict[str, Any]]:
        clean_tab = str(tab_id or "").strip()
        clean_cid = str(cid or "").strip() or None
        self._prune_locked(now)
        out: list[dict[str, Any]] = []
        for rec in sorted(self.ignore_suggestions.values(), key=lambda r: r["created_at"]):
            rcid = rec.get("conversation_id")
            rtab = rec.get("tab_id")
            if clean_cid and rcid:
                matched = (rcid == clean_cid)
            elif not rcid:
                matched = (rtab == clean_tab or not rtab or rtab not in self.tabs)
            else:
                matched = False
            if matched:
                out.append(dict(rec))
        return out

    def list_pending_ignore_suggestions(self, tab_id: str, cid: str | None) -> list[dict[str, Any]]:
        now = time.time()
        with self.lock:
            return self._list_pending_ignore_suggestions_locked(tab_id, cid, now)

    def resolve_ignore_suggestion(
        self,
        *,
        suggestion_id: str,
        decision: str,
        dirs: list[str] | None = None,
    ) -> dict[str, Any]:
        sid = str(suggestion_id or "").strip()
        dec = str(decision or "").strip().lower()
        if not sid or dec not in ("approve", "dismiss"):
            raise ValueError("suggestion_id and valid decision ('approve'/'dismiss') are required")
        with self.lock:
            rec = self.ignore_suggestions.pop(sid, None)
        if not rec:
            raise ValueError(f"unknown or expired suggestion_id: {sid}")
        chosen = list(rec.get("dirs") or [])
        if dirs is not None:
            chosen = [str(d).strip() for d in dirs if str(d).strip()]
        return {
            "ok": True,
            "suggestion_id": sid,
            "decision": dec,
            "dirs": chosen if dec == "approve" else [],
        }

    @staticmethod
    def _public_task(task: dict[str, Any]) -> dict[str, Any]:
        out = {
            "task_id": task["task_id"],
            "kind": task["kind"],
            "status": task["status"],
            "target_conversation_id": task.get("target_conversation_id"),
            "target_tab_id": task.get("target_tab_id"),
            "created_at": task["created_at"],
            "updated_at": task["updated_at"],
            "result": task.get("result"),
            "error": task.get("error"),
        }
        if task["kind"] == "upload_media":
            out["files"] = [
                {"index": f["index"], "name": f["name"], "mime": f["mime"], "size_bytes": f["size_bytes"]}
                for f in task.get("files") or []
            ]
            out["prompt"] = task.get("prompt", "")
            out["delay_sec"] = task.get("delay_sec", 2)
            out["auto_send"] = task.get("auto_send", True)
            out["tool_mode"] = task.get("tool_mode", "none")
        elif task["kind"] == "save_media":
            out["target_path"] = task.get("target_path")
            out["is_dir"] = task.get("is_dir")
            out["media_kind"] = task.get("media_kind")
            out["trigger_prompt"] = task.get("trigger_prompt", "")
            out["delay_sec"] = task.get("delay_sec", 2)
            out["timeout_sec"] = task.get("timeout_sec", 240)
            out["saved_files"] = list(task.get("saved_files") or [])
        elif task["kind"] == "continue_turn":
            out["prompt"] = task.get("prompt", "")
            out["delay_sec"] = task.get("delay_sec", 8)
            out["jitter_max_sec"] = task.get("jitter_max_sec", 3)
            out["turn_index"] = task.get("turn_index", 1)
            out["max_auto_turns"] = task.get("max_auto_turns", 5)
        return out
