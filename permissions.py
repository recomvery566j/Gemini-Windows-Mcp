"""Per-conversation authorization manager backed by the Tampermonkey local bridge.

When no Tampermonkey bridge client is connected, calls fall back to the
default workstation policy (`WorkspaceBoundaryGuard`). Once at least one
browser bridge tab is online, each tool invocation is attributed to the active
Gemini conversation URL (`/app/<conversation_id>`, with Turn-1 tab-to-cid
promotion) and checked against a local permission store that is strictly
controlled by the user via the local bridge token—never by the in-chat agent
and never by remote OAuth callers.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from security import PermissionDeniedByUser, resolve_path

LOG = logging.getLogger("pc-work-mcp.permissions")

ALL_CAPABILITIES: tuple[str, ...] = (
    "read",
    "write",
    "exec",
    "bridge_read",
    "bridge_save",
)

CAPABILITY_LABELS: dict[str, str] = {
    "read": "读取文件/图片/目录",
    "write": "写入工作区/推送文件",
    "exec": "执行本机命令 (PS/Python/Bash)",
    "bridge_read": "桥接上传本机媒体到会话",
    "bridge_save": "桥接下载网页生成媒体落盘",
}

ALWAYS_ALLOWED_TOOLS: frozenset[str] = frozenset({
    "workspace_status",
    "bridge_status",
    "bridge_get_task",
    "get_job_status",
})

TOOL_CAPABILITY: dict[str, str] = {
    "read_file": "read",
    "read_image": "read",
    "list_dir": "read",
    "find_files": "read",
    "grep_search": "read",
    "write_file": "write",
    "edit_file": "write",
    "push_file": "write",
    "task_plan": "write",
    "powershell": "exec",
    "python": "exec",
    "bash": "exec",
    "start_job": "exec",
    "kill_job": "exec",
    "bridge_upload_media": "bridge_read",
    "bridge_save_generated_media": "bridge_save",
}

PERMISSION_PROFILES: dict[str, tuple[str, ...]] = {
    "ask": (),
    "deny": (),
    "readonly": ("read",),
    "media_only": ("read", "bridge_read", "bridge_save"),
    "workspace": ("read", "write", "bridge_read", "bridge_save"),
    "full": ALL_CAPABILITIES,
}

PROFILE_LABELS: dict[str, str] = {
    "ask": "按需询问",
    "deny": "已禁止",
    "readonly": "仅只读",
    "media_only": "仅媒体桥接",
    "workspace": "工作区读写",
    "full": "完全工作台",
    "custom": "自定义权限",
}


def normalize_capabilities(caps: list[str] | tuple[str, ...] | set[str] | None) -> list[str]:
    valid = set(ALL_CAPABILITIES)
    seen: list[str] = []
    for c in caps or ():
        s = str(c or "").strip().lower()
        if s in valid and s not in seen:
            seen.append(s)
    return [c for c in ALL_CAPABILITIES if c in seen]


def infer_profile_name(profile: str | None, caps: list[str]) -> str:
    p = str(profile or "").strip().lower()
    if p in ("ask", "deny") and not caps:
        return p
    cap_tuple = tuple(normalize_capabilities(caps))
    for name, preset_caps in PERMISSION_PROFILES.items():
        if name in ("ask", "deny"):
            continue
        if cap_tuple == preset_caps:
            return name
    if not cap_tuple:
        return "deny" if p == "deny" else "ask"
    return "custom"


def summarize_tool_args(tool_name: str, args: dict[str, Any]) -> str:
    if tool_name in ("read_file", "read_image", "write_file", "edit_file", "list_dir", "push_file"):
        return str(args.get("path") or "")
    if tool_name == "find_files":
        return f"{args.get('path') or '.'} ({args.get('pattern') or '*'})"
    if tool_name == "grep_search":
        return f"{args.get('path') or '.'} :: {str(args.get('query') or '')[:60]}"
    if tool_name == "task_plan":
        act = str(args.get("action") or "get")
        extra = str(args.get("handoff") or args.get("goal") or "")[:60]
        return f"{act}" + (f": {extra}" if extra else "")
    if tool_name == "bridge_save_generated_media":
        return f"保存到: {args.get('target_path') or ''}"
    if tool_name == "bridge_upload_media":
        files = args.get("files") or []
        if isinstance(files, list):
            return f"上传 {len(files)} 个文件: {', '.join(str(x) for x in files[:2])}"
        return str(files)
    if tool_name in ("powershell", "bash"):
        code = str(args.get("script") or "").strip().splitlines()
        return (code[0][:120] if code else "")
    if tool_name in ("python", "start_job"):
        code = str(args.get("code") or "").strip().splitlines()
        prefix = f"[{args.get('engine')}] " if tool_name == "start_job" else ""
        return prefix + (code[0][:110] if code else "")
    if tool_name == "kill_job":
        return f"job_id={args.get('job_id') or ''}"
    return ""


class ConversationPermissionManager:
    """Enforces per-conversation URL permissions when Tampermonkey bridge is connected."""

    def __init__(self, cfg: dict[str, Any], store_path: Path):
        pcfg = cfg.get("permissions") or {}
        self.enabled = bool(pcfg.get("per_conversation_enabled", True))
        self.default_profile = str(pcfg.get("new_conversation_default_profile") or "ask").strip().lower()
        if self.default_profile not in PERMISSION_PROFILES:
            self.default_profile = "ask"
        self.ambiguous_policy = str(pcfg.get("ambiguous_window_policy") or "ask").strip().lower()
        if self.ambiguous_policy not in ("ask", "deny"):
            self.ambiguous_policy = "ask"
        self.approval_timeout_sec = max(5, min(int(pcfg.get("approval_timeout_sec", 45)), 180))
        self.store_path = Path(store_path).resolve(strict=False)

        self.lock = threading.Lock()
        self.persistent_policies: dict[str, dict[str, Any]] = {}
        self.session_cid_policies: dict[str, dict[str, Any]] = {}
        self.tab_policies: dict[str, dict[str, Any]] = {}
        self.pending_approvals: dict[str, dict[str, Any]] = {}
        self._load_store()

    def _load_store(self) -> None:
        if not self.store_path.is_file():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            raw_map = data.get("conversations") or {}
            loaded: dict[str, dict[str, Any]] = {}
            for cid, entry in raw_map.items():
                if not isinstance(entry, dict):
                    continue
                caps = normalize_capabilities(entry.get("capabilities"))
                prof = infer_profile_name(entry.get("profile"), caps)
                loaded[str(cid)] = {
                    "conversation_id": str(cid),
                    "url": str(entry.get("url") or f"https://gemini.google.com/app/{cid}"),
                    "title": str(entry.get("title") or ""),
                    "profile": prof,
                    "capabilities": list(PERMISSION_PROFILES.get(prof, caps)) if prof in PERMISSION_PROFILES and prof not in ("ask", "deny") else caps,
                    "scope": "persistent",
                    "updated_at": float(entry.get("updated_at") or time.time()),
                }
            self.persistent_policies = loaded
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to load bridge permissions store %s: %s", self.store_path, exc)

    def _save_store_locked(self) -> None:
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.store_path.with_suffix(".tmp")
            payload = {
                "version": 1,
                "updated_at": time.time(),
                "conversations": self.persistent_policies,
            }
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.store_path)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to save bridge permissions store: %s", exc)

    def _build_default_policy(self, cid: str | None, tab_id: str | None, url: str = "", title: str = "") -> dict[str, Any]:
        caps = list(PERMISSION_PROFILES.get(self.default_profile, ()))
        return {
            "conversation_id": cid,
            "tab_id": tab_id,
            "url": url or (f"https://gemini.google.com/app/{cid}" if cid else "https://gemini.google.com/app"),
            "title": title,
            "profile": self.default_profile,
            "profile_label": PROFILE_LABELS.get(self.default_profile, self.default_profile),
            "capabilities": caps,
            "scope": "default",
            "is_default": True,
            "updated_at": 0.0,
        }

    def get_effective_policy(self, cid: str | None = None, tab_id: str | None = None,
                             url: str = "", title: str = "") -> dict[str, Any]:
        with self.lock:
            rec = None
            if cid:
                rec = self.session_cid_policies.get(cid) or self.persistent_policies.get(cid)
            elif tab_id:
                rec = self.tab_policies.get(tab_id)
            if rec is None:
                return self._build_default_policy(cid, tab_id, url=url, title=title)
            out = dict(rec)
            out["profile_label"] = PROFILE_LABELS.get(out.get("profile", "ask"), out.get("profile", "ask"))
            out["is_default"] = False
            return out

    def set_policy(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        profile: str | None = None,
        capabilities: list[str] | None = None,
        scope: str = "persistent",
        url: str = "",
        title: str = "",
    ) -> dict[str, Any]:
        cid = str(conversation_id or "").strip() or None
        tid = str(tab_id or "").strip() or None
        if not cid and not tid:
            raise ValueError("conversation_id or tab_id is required")

        prof_in = str(profile or "").strip().lower()
        if prof_in and prof_in in PERMISSION_PROFILES:
            caps = list(PERMISSION_PROFILES[prof_in])
            final_prof = prof_in
        elif capabilities is not None:
            caps = normalize_capabilities(capabilities)
            final_prof = infer_profile_name(prof_in or "custom", caps)
        else:
            raise ValueError(f"invalid profile or missing capabilities: {profile!r}")

        scope_norm = "session" if str(scope or "").lower() == "session" else "persistent"
        now = time.time()
        entry = {
            "conversation_id": cid,
            "tab_id": tid if not cid else None,
            "url": str(url or (f"https://gemini.google.com/app/{cid}" if cid else "https://gemini.google.com/app")),
            "title": str(title or ""),
            "profile": final_prof,
            "capabilities": caps,
            "scope": scope_norm,
            "updated_at": now,
        }

        with self.lock:
            if cid:
                if scope_norm == "persistent":
                    self.session_cid_policies.pop(cid, None)
                    self.persistent_policies[cid] = entry
                    self._save_store_locked()
                else:
                    self.persistent_policies.pop(cid, None)
                    self.session_cid_policies[cid] = entry
                    self._save_store_locked()
            elif tid:
                self.tab_policies[tid] = entry
            out = dict(entry)
            out["profile_label"] = PROFILE_LABELS.get(final_prof, final_prof)
            out["is_default"] = False
            return out

    def delete_policy(self, conversation_id: str | None = None, tab_id: str | None = None) -> bool:
        cid = str(conversation_id or "").strip() or None
        tid = str(tab_id or "").strip() or None
        removed = False
        with self.lock:
            if cid:
                if self.session_cid_policies.pop(cid, None) is not None:
                    removed = True
                if self.persistent_policies.pop(cid, None) is not None:
                    removed = True
                    self._save_store_locked()
            if tid and self.tab_policies.pop(tid, None) is not None:
                removed = True
        return removed

    def clear_all_policies(self) -> int:
        with self.lock:
            count = len(self.persistent_policies) + len(self.session_cid_policies) + len(self.tab_policies)
            self.persistent_policies.clear()
            self.session_cid_policies.clear()
            self.tab_policies.clear()
            self._save_store_locked()
            return count

    def bind_tab_to_conversation(self, tab_id: str, cid: str | None, url: str = "", title: str = "") -> None:
        """Promote a Turn-1 tab policy once /app/<cid> appears, or drop it if returning to /app."""
        tid = str(tab_id or "").strip()
        if not tid:
            return
        now = time.time()
        with self.lock:
            if not cid:
                # Returning to blank /app (new chat): do not leak prior Turn-1 policy across chats
                self.tab_policies.pop(tid, None)
                return

            tab_rec = self.tab_policies.pop(tid, None)
            if tab_rec is not None:
                # Only promote if this cid doesn't already have an explicit policy
                if cid not in self.persistent_policies and cid not in self.session_cid_policies:
                    promoted = dict(tab_rec)
                    promoted["conversation_id"] = cid
                    promoted["tab_id"] = None
                    promoted["url"] = url or f"https://gemini.google.com/app/{cid}"
                    if title:
                        promoted["title"] = title
                    promoted["updated_at"] = now
                    if promoted.get("scope") == "session":
                        self.session_cid_policies[cid] = promoted
                    else:
                        promoted["scope"] = "persistent"
                        self.persistent_policies[cid] = promoted
                        self._save_store_locked()
            elif cid in self.persistent_policies:
                changed = False
                if title and not self.persistent_policies[cid].get("title"):
                    self.persistent_policies[cid]["title"] = title
                    changed = True
                if url and self.persistent_policies[cid].get("url") != url:
                    self.persistent_policies[cid]["url"] = url
                    changed = True
                if changed:
                    self._save_store_locked()

    def list_pending_for_tab(self, tab_id: str, cid: str | None) -> list[dict[str, Any]]:
        now = time.time()
        out: list[dict[str, Any]] = []
        with self.lock:
            expired = [aid for aid, a in self.pending_approvals.items() if a["status"] == "pending" and a["expires_at"] < now]
            for aid in expired:
                a = self.pending_approvals[aid]
                a["status"] = "timeout"
                a["event"].set()
            # Clean old resolved approvals after 60s
            stale = [aid for aid, a in self.pending_approvals.items() if a["status"] != "pending" and (now - a["created_at"]) > 120]
            for aid in stale:
                self.pending_approvals.pop(aid, None)

            for a in self.pending_approvals.values():
                if a["status"] != "pending":
                    continue
                if a.get("ambiguous"):
                    cand_tabs = {c.get("tab_id") for c in (a.get("candidates") or [])}
                    if tab_id in cand_tabs or not cand_tabs:
                        out.append(self._public_approval(a, now))
                else:
                    target_tab = a.get("tab_id")
                    target_cid = a.get("conversation_id")
                    if (target_tab and target_tab == tab_id) or (target_cid and cid and target_cid == cid):
                        out.append(self._public_approval(a, now))
        return out

    @staticmethod
    def _public_approval(a: dict[str, Any], now: float | None = None) -> dict[str, Any]:
        t = now or time.time()
        return {
            "approval_id": a["approval_id"],
            "status": a["status"],
            "tool_name": a["tool_name"],
            "capability": a["capability"],
            "capability_label": CAPABILITY_LABELS.get(a["capability"], a["capability"]),
            "target_summary": a["target_summary"],
            "conversation_id": a.get("conversation_id"),
            "tab_id": a.get("tab_id"),
            "url": a.get("url") or "",
            "title": a.get("title") or "",
            "ambiguous": bool(a.get("ambiguous")),
            "ambiguous_reason": a.get("ambiguous_reason") or "",
            "candidates": [
                {
                    "tab_id": c.get("tab_id"),
                    "conversation_id": c.get("conversation_id"),
                    "title": c.get("title") or "",
                }
                for c in (a.get("candidates") or [])
            ],
            "remaining_sec": max(0, int(round(a["expires_at"] - t))),
            "timeout_sec": a["timeout_sec"],
        }

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        profile: str | None = None,
        capability: str | None = None,
        scope: str = "persistent",
        responder_cid: str | None = None,
        responder_tab_id: str | None = None,
    ) -> dict[str, Any]:
        aid = str(approval_id or "").strip()
        dec = str(decision or "").strip().lower()
        if dec not in ("allow_once", "allow_capability", "allow_profile", "deny"):
            raise ValueError(f"invalid decision: {decision!r}")

        with self.lock:
            a = self.pending_approvals.get(aid)
            if not a:
                raise ValueError(f"unknown or expired approval_id: {aid}")
            if a["status"] != "pending":
                return self._public_approval(a)

            target_cid = a.get("conversation_id") or (responder_cid if a.get("ambiguous") else None)
            target_tab = a.get("tab_id") or (responder_tab_id if a.get("ambiguous") else None)
            target_url = a.get("url") or (f"https://gemini.google.com/app/{target_cid}" if target_cid else "")
            target_title = a.get("title") or ""

            if dec == "deny":
                a["status"] = "denied"
                a["decision"] = dec
                a["event"].set()
                return self._public_approval(a)

            if dec == "allow_once":
                a["status"] = "approved"
                a["decision"] = dec
                a["event"].set()
                return self._public_approval(a)

            # Persistent or session grant (do not grant broad policy on ambiguous source unless user chose responder? disallow on ambiguous for safety)
            if a.get("ambiguous"):
                raise ValueError("ambiguous multi-window requests only support allow_once or deny")

            if dec == "allow_capability":
                grant_cap = str(capability or a["capability"]).strip().lower()
                if grant_cap not in ALL_CAPABILITIES:
                    raise ValueError(f"invalid capability: {grant_cap}")
                existing = None
                if target_cid:
                    existing = self.session_cid_policies.get(target_cid) or self.persistent_policies.get(target_cid)
                elif target_tab:
                    existing = self.tab_policies.get(target_tab)
                base_caps = list(existing.get("capabilities") or ()) if existing else ["read"]
                if grant_cap not in base_caps:
                    base_caps.append(grant_cap)
                new_caps = normalize_capabilities(base_caps)
                new_prof = infer_profile_name("custom", new_caps)
            else:
                req_prof = str(profile or "").strip().lower()
                if req_prof not in PERMISSION_PROFILES or req_prof in ("ask", "deny"):
                    raise ValueError(f"invalid target profile: {profile!r}")
                new_prof = req_prof
                new_caps = list(PERMISSION_PROFILES[req_prof])

            a["granted_policy"] = {
                "conversation_id": target_cid,
                "tab_id": target_tab,
                "profile": new_prof,
                "capabilities": new_caps,
                "scope": "session" if str(scope or "").lower() == "session" else "persistent",
                "url": target_url,
                "title": target_title,
            }
            a["status"] = "approved"
            a["decision"] = dec
            a["event"].set()
            pub = self._public_approval(a)

        # Persist outside self.lock or inside set_policy cleanly
        if "granted_policy" in a:
            gp = a["granted_policy"]
            self.set_policy(
                conversation_id=gp["conversation_id"],
                tab_id=gp["tab_id"],
                profile=gp["profile"],
                capabilities=gp["capabilities"],
                scope=gp["scope"],
                url=gp["url"],
                title=gp["title"],
            )
        return pub

    def _is_global_whitelist_allowed(
        self,
        tool_name: str,
        args: dict[str, Any],
        guard,
        active_ws: Path | None,
    ) -> bool:
        if guard is None:
            return False
        a = args or {}

        if tool_name in ("read_file", "read_image", "list_dir"):
            raw_path = str(a.get("path") or "").strip()
            return bool(raw_path) and guard.is_whitelisted_for_action(
                raw_path, access="read", active_workspace=active_ws,
            )

        if tool_name in ("find_files", "grep_search"):
            raw_path = str(a.get("path") or "").strip()
            if not raw_path or raw_path == ".":
                return False
            return guard.is_whitelisted_for_action(
                raw_path, access="read", active_workspace=active_ws,
            )

        if tool_name == "bridge_upload_media":
            raw_files = a.get("files") or []
            if isinstance(raw_files, str):
                raw_files = [raw_files]
            if not isinstance(raw_files, list) or not raw_files:
                return False
            cleaned = [str(item).strip() for item in raw_files if isinstance(item, str) and item.strip()]
            if not cleaned:
                return False
            return all(
                guard.is_whitelisted_for_action(p, access="read", active_workspace=active_ws)
                for p in cleaned
            )

        if tool_name in ("write_file", "edit_file", "push_file"):
            raw_path = str(a.get("path") or "").strip()
            return bool(raw_path) and guard.is_whitelisted_for_action(
                raw_path, access="write", active_workspace=active_ws,
            )

        if tool_name == "bridge_save_generated_media":
            raw_target = str(a.get("target_path") or "").strip()
            if not raw_target:
                return False
            norm_target = resolve_path(raw_target, base_dir=active_ws)
            is_dir = raw_target.endswith(("/", "\\")) or norm_target.is_dir() or not norm_target.suffix
            probe_path = str(norm_target / "__artifact__") if is_dir else str(norm_target)
            return guard.is_whitelisted_for_action(
                probe_path, access="write", active_workspace=active_ws,
            )

        if tool_name in ("powershell", "python", "bash", "start_job"):
            raw_cwd = str(a.get("cwd") or "").strip()
            if not raw_cwd:
                return False
            if not guard.is_whitelisted_for_action(raw_cwd, access="exec", active_workspace=active_ws):
                return False
            code = str(a.get("script") if tool_name in ("powershell", "bash") else a.get("code") or "")
            if guard.has_protected_write_reference(code):
                return False
            workdir = resolve_path(raw_cwd, base_dir=active_ws)
            if guard.is_blocked_read(workdir):
                return False
            if guard._detect_external_write_targets(code, workdir, active_workspace=active_ws):
                return False
            return True

        return False

    def authorize_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        bridge_mgr,
        *,
        guard=None,
        workspace_mgr=None,
    ) -> dict[str, Any]:
        """Validate whether the calling conversation is authorized to execute `tool_name`."""
        if not self.enabled:
            return {"mode": "disabled", "allowed": True}

        resolution = bridge_mgr.resolve_caller_window(grace_sec=0.45)
        if resolution["status"] == "no_bridge":
            # User has not configured/opened Tampermonkey bridge -> fallback to default workstation permissions
            return {"mode": "fallback_default", "allowed": True}

        if tool_name in ALWAYS_ALLOWED_TOOLS:
            out: dict[str, Any] = {
                "mode": "per_conversation_bridge",
                "allowed": True,
                "resolution": resolution["status"],
            }
            if resolution["status"] == "matched":
                tab = resolution["tab"]
                out["conversation_id"] = tab.get("conversation_id")
                out["tab_id"] = tab.get("tab_id")
            return out

        cap = TOOL_CAPABILITY.get(tool_name)
        if tool_name == "task_plan" and str((args or {}).get("action") or "get").strip().lower() == "get":
            cap = "read"
        if not cap:
            out = {"mode": "per_conversation_bridge", "allowed": True, "resolution": resolution["status"]}
            if resolution["status"] == "matched":
                tab = resolution["tab"]
                out["conversation_id"] = tab.get("conversation_id")
                out["tab_id"] = tab.get("tab_id")
            return out

        summary = summarize_tool_args(tool_name, args)

        if resolution["status"] == "ambiguous":
            candidates = resolution.get("candidates") or []
            if self.ambiguous_policy == "deny":
                raise PermissionDeniedByUser(
                    f"PermissionDeniedByUser: 当前有多个活跃 Gemini 窗口，无法唯一锁定工具 {tool_name} 的调用来源（需权限: {CAPABILITY_LABELS.get(cap, cap)}）。"
                )
            return self._wait_for_approval(
                tool_name=tool_name,
                cap=cap,
                summary=summary,
                cid=None,
                tab_id=None,
                url="",
                title="多窗口并发来源歧义",
                ambiguous=True,
                ambiguous_reason=resolution.get("reason") or "multiple_active_windows",
                candidates=candidates,
            )

        tab = resolution["tab"]
        cid = tab.get("conversation_id")
        tab_id = tab.get("tab_id")
        url = tab.get("url") or (f"https://gemini.google.com/app/{cid}" if cid else "https://gemini.google.com/app")
        title = tab.get("title") or ""

        policy = self.get_effective_policy(cid=cid, tab_id=tab_id, url=url, title=title)
        profile = policy["profile"]
        caps = set(policy.get("capabilities") or ())

        if cap in caps:
            return {
                "mode": "per_conversation_bridge",
                "allowed": True,
                "conversation_id": cid,
                "tab_id": tab_id,
                "profile": profile,
                "capabilities": sorted(caps),
            }

        win_label = f"会话 {cid}" if cid else f"新会话窗口({tab_id})"
        if profile == "deny":
            raise PermissionDeniedByUser(
                f"PermissionDeniedByUser: {win_label} 当前权限策略为「禁止 (deny)」，已拦截 {tool_name}。"
                "请由用户在浏览器右下角油猴本地桥面板调整该会话链接的权限（不由会话内 Agent 修改）。"
            )

        active_ws = (
            workspace_mgr.resolve_active_dir({"conversation_id": cid, "tab_id": tab_id})
            if workspace_mgr is not None
            else (guard.default_dir if guard is not None else None)
        )
        if self._is_global_whitelist_allowed(tool_name, args, guard, active_ws):
            return {
                "mode": "per_conversation_bridge",
                "allowed": True,
                "bypassed_via": "global_whitelist",
                "conversation_id": cid,
                "tab_id": tab_id,
                "profile": profile,
                "capabilities": sorted(caps),
            }

        # If profile is "ask" OR an existing restricted profile (e.g. "readonly") lacks this capability:
        # request explicit local-bridge user confirmation on that exact tab!
        return self._wait_for_approval(
            tool_name=tool_name,
            cap=cap,
            summary=summary,
            cid=cid,
            tab_id=tab_id,
            url=url,
            title=title,
            ambiguous=False,
            ambiguous_reason="",
            candidates=[],
            current_profile=profile,
        )

    def _wait_for_approval(
        self,
        *,
        tool_name: str,
        cap: str,
        summary: str,
        cid: str | None,
        tab_id: str | None,
        url: str,
        title: str,
        ambiguous: bool,
        ambiguous_reason: str,
        candidates: list[dict[str, Any]],
        current_profile: str = "ask",
    ) -> dict[str, Any]:
        now = time.time()
        aid = "apr_" + uuid.uuid4().hex[:12]
        ev = threading.Event()
        entry = {
            "approval_id": aid,
            "status": "pending",
            "tool_name": tool_name,
            "capability": cap,
            "target_summary": summary,
            "conversation_id": cid,
            "tab_id": tab_id,
            "url": url,
            "title": title,
            "ambiguous": ambiguous,
            "ambiguous_reason": ambiguous_reason,
            "candidates": candidates,
            "timeout_sec": self.approval_timeout_sec,
            "created_at": now,
            "expires_at": now + self.approval_timeout_sec,
            "event": ev,
            "decision": None,
        }
        with self.lock:
            self.pending_approvals[aid] = entry

        LOG.info(
            "awaiting local-bridge permission approval %s: tool=%s cap=%s cid=%s tab=%s ambiguous=%s",
            aid, tool_name, cap, cid or "(pending)", tab_id or "(none)", ambiguous,
        )
        ev.wait(timeout=self.approval_timeout_sec + 0.5)

        with self.lock:
            rec = self.pending_approvals.get(aid)
            status = rec["status"] if rec else "timeout"
            if status == "pending":
                status = "timeout"
                if rec:
                    rec["status"] = "timeout"

        if status == "approved":
            return {
                "mode": "per_conversation_bridge",
                "allowed": True,
                "approved_via": aid,
                "conversation_id": cid,
                "tab_id": tab_id,
            }

        win_desc = f"会话 {cid}" if cid else (f"标签页 {tab_id}" if tab_id else "并发多窗口")
        if status == "timeout":
            raise PermissionDeniedByUser(
                f"PermissionDeniedByUser: {win_desc} 请求 {tool_name}（{CAPABILITY_LABELS.get(cap, cap)}），"
                f"在油猴本地桥等待用户确认超时（{self.approval_timeout_sec}s），已自动拒绝。"
                f"当前策略为「{PROFILE_LABELS.get(current_profile, current_profile)}」，仅用户可在本地桥面板授权。"
            )
        raise PermissionDeniedByUser(
            f"PermissionDeniedByUser: 用户已在油猴本地桥拒绝 {win_desc} 执行 {tool_name}（{CAPABILITY_LABELS.get(cap, cap)}）。"
        )

    def snapshot(self, bridge_mgr=None) -> dict[str, Any]:
        with self.lock:
            saved = [dict(v) for v in sorted(self.persistent_policies.values(), key=lambda x: x.get("updated_at", 0), reverse=True)]
            session_cids = [dict(v) for v in sorted(self.session_cid_policies.values(), key=lambda x: x.get("updated_at", 0), reverse=True)]
            tab_pols = [dict(v) for v in self.tab_policies.values()]
            pending = [self._public_approval(a) for a in self.pending_approvals.values() if a["status"] == "pending"]

        live_tabs = bridge_mgr.status_snapshot()["tabs"] if bridge_mgr is not None else []
        for t in live_tabs:
            pol = self.get_effective_policy(
                cid=t.get("conversation_id"),
                tab_id=t.get("tab_id"),
                url=t.get("url") or "",
                title=t.get("title") or "",
            )
            t["policy"] = pol

        return {
            "per_conversation_enabled": self.enabled,
            "mode": "per_conversation_bridge" if (self.enabled and len(live_tabs) > 0) else "fallback_default",
            "new_conversation_default_profile": self.default_profile,
            "ambiguous_window_policy": self.ambiguous_policy,
            "approval_timeout_sec": self.approval_timeout_sec,
            "store_path": str(self.store_path),
            "profiles": {
                k: {"label": PROFILE_LABELS.get(k, k), "capabilities": list(v)}
                for k, v in PERMISSION_PROFILES.items()
            },
            "capabilities": dict(CAPABILITY_LABELS),
            "live_tabs": live_tabs,
            "persistent_conversations": saved,
            "session_conversations": session_cids,
            "pending_turn1_tabs": tab_pols,
            "pending_approvals": pending,
        }
