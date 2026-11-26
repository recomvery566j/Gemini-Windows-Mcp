"""Lightweight persistent task plan & bounded self-wake coordinator."""

from __future__ import annotations

import json
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

VALID_STEP_STATUSES = frozenset({"pending", "in_progress", "done", "failed", "skipped"})
VALID_PLAN_STATUSES = frozenset({"active", "paused", "completed", "stopped"})


def _clip_text(text: str, limit: int) -> str:
    clean = " ".join(str(text or "").strip().split())
    if len(clean) <= limit:
        return clean
    return clean[: max(1, limit - 1)] + "…"


class TaskPlanManager:
    """Stores compact task progress and bounds autonomous self-continue loops."""

    def __init__(self, store_path: Path, cfg: dict[str, Any] | None = None):
        self.store_path = Path(store_path).resolve(strict=False)
        tcfg = (cfg or {}).get("task_plan") or {}
        self.max_allowed_auto_turns = max(1, min(int(tcfg.get("max_allowed_auto_turns", 10)), 20))
        self.default_max_auto_turns = max(
            1, min(int(tcfg.get("default_max_auto_turns", 5)), self.max_allowed_auto_turns)
        )
        self.min_cooldown_sec = max(5, min(int(tcfg.get("min_cooldown_sec", 5)), 30))
        self.max_handoff_chars = max(60, min(int(tcfg.get("max_handoff_chars", 220)), 400))

        self.lock = threading.Lock()
        self.conversations: dict[str, dict[str, Any]] = {}
        self.tab_plans: dict[str, dict[str, Any]] = {}
        self.default_plan: dict[str, Any] | None = None
        self._load_store()

    def _load_store(self) -> None:
        if not self.store_path.is_file():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8-sig"))
        except Exception:  # noqa: BLE001
            return
        convs = data.get("conversations")
        if isinstance(convs, dict):
            self.conversations = {str(k): dict(v) for k, v in convs.items() if isinstance(v, dict)}
        if isinstance(data.get("default_plan"), dict):
            self.default_plan = dict(data["default_plan"])

    def _save_store_locked(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "conversations": self.conversations,
            "default_plan": self.default_plan,
            "updated_at": time.time(),
        }
        raw = json.dumps(payload, ensure_ascii=False, indent=2)
        fd, tmp = tempfile.mkstemp(prefix="task_plan_", suffix=".tmp", dir=str(self.store_path.parent))
        try:
            with open(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(raw)
            Path(tmp).replace(self.store_path)
        except Exception:  # noqa: BLE001
            try:
                Path(tmp).unlink()
            except OSError:
                pass
            raise

    def bind_tab_to_conversation(self, tab_id: str, cid: str | None) -> None:
        tid = str(tab_id or "").strip()
        clean_cid = str(cid or "").strip() or None
        if not tid:
            return
        with self.lock:
            if clean_cid:
                tab_rec = self.tab_plans.pop(tid, None)
                if tab_rec and clean_cid not in self.conversations:
                    tab_rec["conversation_id"] = clean_cid
                    tab_rec["updated_at"] = time.time()
                    self.conversations[clean_cid] = tab_rec
                    self._save_store_locked()
            else:
                self.tab_plans.pop(tid, None)

    def _get_locked(self, cid: str | None, tab_id: str | None) -> dict[str, Any] | None:
        if cid and cid in self.conversations:
            return self.conversations[cid]
        if tab_id and tab_id in self.tab_plans:
            return self.tab_plans[tab_id]
        if not cid and not tab_id:
            return self.default_plan
        return None

    def _put_locked(self, cid: str | None, tab_id: str | None, plan: dict[str, Any]) -> None:
        if cid:
            self.conversations[cid] = plan
            if tab_id:
                self.tab_plans.pop(tab_id, None)
            self._save_store_locked()
        elif tab_id:
            self.tab_plans[tab_id] = plan
        else:
            self.default_plan = plan
            self._save_store_locked()

    @staticmethod
    def _compact_view(plan: dict[str, Any] | None) -> dict[str, Any] | None:
        if not plan:
            return None
        steps = list(plan.get("steps") or [])
        done_cnt = sum(1 for s in steps if s.get("status") == "done")
        return {
            "goal": plan.get("goal", ""),
            "status": plan.get("status", "active"),
            "progress": f"{done_cnt}/{len(steps)}",
            "steps": steps,
            "auto_turns_used": int(plan.get("auto_turns_used", 0)),
            "max_auto_turns": int(plan.get("max_auto_turns", 5)),
            "last_handoff": plan.get("last_handoff", ""),
            "pending_continue_task_id": plan.get("pending_continue_task_id"),
            "updated_at": plan.get("updated_at"),
        }

    def set_plan(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        goal: str,
        steps: list[Any],
        max_auto_turns: int | None = None,
        keep_counters: bool = False,
    ) -> dict[str, Any]:
        clean_goal = _clip_text(goal, 180)
        if not clean_goal:
            raise ValueError("goal is required")
        if not isinstance(steps, list) or not steps:
            raise ValueError("steps must be a non-empty list (max 12)")

        norm_steps: list[dict[str, Any]] = []
        for idx, item in enumerate(steps[:12], start=1):
            if isinstance(item, str):
                title = _clip_text(item, 100)
                st = "pending"
                note = ""
            elif isinstance(item, dict):
                title = _clip_text(item.get("title") or "", 100)
                st = str(item.get("status") or "pending").strip().lower()
                if st not in VALID_STEP_STATUSES:
                    st = "pending"
                note = _clip_text(item.get("note") or "", 100)
            else:
                continue
            if not title:
                continue
            norm_steps.append({"id": idx, "title": title, "status": st, "note": note})
        if not norm_steps:
            raise ValueError("steps must contain at least one valid step title")

        with self.lock:
            prev = self._get_locked(cid, tab_id)
            used = int(prev.get("auto_turns_used", 0)) if (keep_counters and prev) else 0
            cap = (
                max(1, min(int(max_auto_turns), self.max_allowed_auto_turns))
                if max_auto_turns is not None
                else self.default_max_auto_turns
            )
            plan = {
                "conversation_id": cid,
                "goal": clean_goal,
                "status": "active",
                "steps": norm_steps,
                "auto_turns_used": used,
                "max_auto_turns": cap,
                "last_handoff": prev.get("last_handoff", "") if (keep_counters and prev) else "",
                "pending_continue_task_id": None,
                "updated_at": time.time(),
            }
            self._put_locked(cid, tab_id, plan)
            return self._compact_view(plan)  # type: ignore[return-value]

    def update_plan(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        step_updates: list[dict[str, Any]] | None = None,
        status: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                raise ValueError("no active task_plan found for this conversation; call action='set' first")
            steps = list(plan.get("steps") or [])
            by_id = {int(s["id"]): s for s in steps}
            for upd in step_updates or ():
                if not isinstance(upd, dict):
                    continue
                sid = upd.get("id")
                try:
                    sid_int = int(sid)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    continue
                target = by_id.get(sid_int)
                if not target:
                    continue
                if upd.get("status"):
                    st = str(upd["status"]).strip().lower()
                    if st not in VALID_STEP_STATUSES:
                        raise ValueError(f"invalid step status: {st!r}")
                    target["status"] = st
                if "note" in upd and upd["note"] is not None:
                    target["note"] = _clip_text(str(upd["note"]), 100)
                if upd.get("title"):
                    target["title"] = _clip_text(str(upd["title"]), 100)

            if status:
                pst = str(status).strip().lower()
                if pst not in VALID_PLAN_STATUSES:
                    raise ValueError(f"invalid plan status: {pst!r}")
                plan["status"] = pst
            if note:
                plan["last_handoff"] = _clip_text(note, self.max_handoff_chars)
            plan["updated_at"] = time.time()
            self._put_locked(cid, tab_id, plan)
            return self._compact_view(plan)  # type: ignore[return-value]

    def get_plan(self, *, cid: str | None, tab_id: str | None) -> dict[str, Any]:
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                return {"exists": False, "plan": None}
            return {"exists": True, "plan": self._compact_view(plan)}

    def complete_plan(self, *, cid: str | None, tab_id: str | None, note: str = "") -> dict[str, Any]:
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                return {"exists": False, "plan": None}
            plan["status"] = "completed"
            plan["pending_continue_task_id"] = None
            if note:
                plan["last_handoff"] = _clip_text(note, self.max_handoff_chars)
            plan["updated_at"] = time.time()
            self._put_locked(cid, tab_id, plan)
            return {"exists": True, "plan": self._compact_view(plan)}

    def stop_auto_continue(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        reason: str = "stopped_by_user",
        bridge_mgr=None,
    ) -> dict[str, Any]:
        cancelled_ids: list[str] = []
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            pending_id = plan.get("pending_continue_task_id") if plan else None
            if plan:
                plan["status"] = "stopped"
                plan["pending_continue_task_id"] = None
                plan["last_handoff"] = _clip_text(reason, self.max_handoff_chars)
                plan["updated_at"] = time.time()
                self._put_locked(cid, tab_id, plan)
            view = self._compact_view(plan)

        if bridge_mgr is not None:
            cancelled_ids = bridge_mgr.cancel_continue_tasks(
                conversation_id=cid, tab_id=tab_id, task_id=pending_id, reason=reason,
            )
        return {"ok": True, "cancelled_task_ids": cancelled_ids, "plan": view}

    @staticmethod
    def _build_step_context(steps: list[dict[str, Any]]) -> tuple[str, str]:
        done_cnt = sum(1 for s in steps if s.get("status") == "done")
        progress = f"{done_cnt}/{len(steps)}" if steps else "0/0"
        in_prog = [s for s in steps if s.get("status") == "in_progress"]
        pending = [s for s in steps if s.get("status") == "pending"]
        parts: list[str] = []
        if in_prog:
            cur = ", ".join(f"#{s['id']}:{_clip_text(s.get('title') or '', 28)}" for s in in_prog[:2])
            parts.append(f"进行中[{cur}]")
        if pending:
            nxt = pending[0]
            parts.append(f"下步待办[#{nxt['id']}:{_clip_text(nxt.get('title') or '', 28)}]")
        if not parts:
            parts.append("步骤均已收口" if steps else "无预设步骤")
        return progress, " ".join(parts)

    def prepare_continue(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        handoff: str,
        delay_sec: int = 8,
    ) -> dict[str, Any]:
        clean_handoff = _clip_text(handoff, self.max_handoff_chars)
        if not clean_handoff:
            raise ValueError("handoff is required and should concisely describe the next step (<=120 chars)")
        safe_delay = max(self.min_cooldown_sec, min(int(delay_sec or 8), 60))

        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                raise ValueError("cannot schedule_continue without an active task_plan; call action='set' first")
            if plan.get("status") in ("completed", "stopped", "paused"):
                raise ValueError(
                    f"task_plan status is {plan.get('status')!r}; set or resume plan before scheduling continue"
                )
            used = int(plan.get("auto_turns_used", 0))
            max_turns = int(plan.get("max_auto_turns", self.default_max_auto_turns))
            if used >= max_turns:
                raise ValueError(
                    f"auto_turns_used ({used}) reached max_auto_turns ({max_turns}); "
                    "please summarize progress to the user instead of auto-continuing again"
                )

            next_num = used + 1
            goal_short = _clip_text(plan.get("goal", ""), 60)
            progress, step_ctx = self._build_step_context(list(plan.get("steps") or []))
            prompt = (
                f"[续跑 {next_num}/{max_turns} · 进度 {progress}] 目标:{goal_short} | "
                f"{step_ctx} | 下一步:{clean_handoff} "
                f"(无需再调 task_plan(get)，直接继续执行，完成后简短汇报，勿复述历史)"
            )
            return {
                "turn_index": next_num,
                "max_auto_turns": max_turns,
                "delay_sec": safe_delay,
                "handoff": clean_handoff,
                "prompt": prompt,
                "plan": self._compact_view(plan),
            }

    def record_pending_task_id(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        task_id: str | None,
        handoff: str | None = None,
    ) -> dict[str, Any] | None:
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                return None
            plan["pending_continue_task_id"] = task_id
            if handoff:
                plan["last_handoff"] = _clip_text(handoff, self.max_handoff_chars)
            plan["updated_at"] = time.time()
            self._put_locked(cid, tab_id, plan)
            return self._compact_view(plan)

    def mark_continue_result(
        self,
        *,
        cid: str | None,
        tab_id: str | None,
        task_id: str,
        status: str,
    ) -> dict[str, Any] | None:
        """Finalize continue_turn result; count quota only when wake-up actually completed."""
        with self.lock:
            plan = self._get_locked(cid, tab_id)
            if not plan:
                return None
            if plan.get("pending_continue_task_id") == task_id:
                plan["pending_continue_task_id"] = None
            if status == "completed":
                counted = list(plan.get("_counted_task_ids") or [])
                if task_id not in counted:
                    plan["auto_turns_used"] = int(plan.get("auto_turns_used", 0)) + 1
                    counted.append(task_id)
                    plan["_counted_task_ids"] = counted[-20:]
            plan["updated_at"] = time.time()
            self._put_locked(cid, tab_id, plan)
            return self._compact_view(plan)

    def snapshot(self, bridge_mgr=None) -> dict[str, Any]:
        tab_plans: dict[str, Any] = {}
        if bridge_mgr is not None:
            snap = bridge_mgr.status_snapshot()
            for t in snap.get("tabs") or []:
                tid = t.get("tab_id")
                cid = t.get("conversation_id")
                p = self.get_plan(cid=cid, tab_id=tid)
                if p.get("exists"):
                    tab_plans[tid] = p["plan"]
        return {
            "tab_plans": tab_plans,
            "default_max_auto_turns": self.default_max_auto_turns,
            "min_cooldown_sec": self.min_cooldown_sec,
            "max_handoff_chars": self.max_handoff_chars,
        }
