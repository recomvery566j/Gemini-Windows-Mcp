"""Dynamic workspace rules discovery, change detection, and per-session injection.

Replaces static MCP instruction caching with dynamic runtime attachment on tool
responses:
1. First tool call in a conversation/session injects active workspace rules;
2. Any content/file change (SHA-256) injects immediately on the next tool call;
3. Long sessions re-anchor periodically after N tool calls (default 20) OR M
   cumulative tool output characters (default 48,000), whichever arrives first,
   counteracting random upstream context compaction and attention decay.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

from security import normalize_path_str, resolve_path

LOG = logging.getLogger("pc-work-mcp.rules")

DEFAULT_RULE_PATTERNS: tuple[str, ...] = (
    "AGENTS.md",
    "GEMINI.md",
    ".gemini/AGENTS.md",
    ".gemini/GEMINI.md",
    ".gemini/rules/*.md",
)

DEFAULT_REINJECT_EVERY_CALLS = 20
DEFAULT_REINJECT_EVERY_OUTPUT_CHARS = 48000
DEFAULT_MAX_TOTAL_CHARS = 24000
DEFAULT_MAX_FILE_BYTES = 524288


def _is_under_prefix(target: Path, prefix: Path) -> bool:
    t = os.path.normcase(str(target.resolve(strict=False)))
    p = os.path.normcase(str(prefix.resolve(strict=False)))
    return t == p or t.startswith(p.rstrip("\\/") + os.sep)


class WorkspaceRulesManager:
    """Discovers workspace instruction files and schedules per-session injection."""

    def __init__(
        self,
        cfg: dict[str, Any],
        default_workspace_dir: Path,
        *,
        store_path: Path | None = None,
        blocked_prefixes: list[Path] | None = None,
    ):
        rcfg = cfg.get("workspace_rules") or {}
        self.enabled = bool(rcfg.get("enabled", True))
        self.reinject_every_calls = max(0, int(rcfg.get("reinject_every_calls", DEFAULT_REINJECT_EVERY_CALLS)))
        self.reinject_every_output_chars = max(
            0, int(rcfg.get("reinject_every_output_chars", DEFAULT_REINJECT_EVERY_OUTPUT_CHARS))
        )
        self.max_total_chars = max(2000, int(rcfg.get("max_total_chars", DEFAULT_MAX_TOTAL_CHARS)))
        self.max_file_bytes = max(4096, int(rcfg.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)))
        raw_patterns = rcfg.get("patterns")
        if isinstance(raw_patterns, list) and raw_patterns:
            self.patterns = tuple(str(p).strip() for p in raw_patterns if str(p).strip())
        else:
            self.patterns = DEFAULT_RULE_PATTERNS

        self.default_dir = Path(default_workspace_dir).resolve(strict=False)
        self.blocked_prefixes = list(blocked_prefixes or ())
        self.store_path = Path(store_path).resolve(strict=False) if store_path else None

        self.lock = threading.Lock()
        self.persistent_dirs: dict[str, dict[str, Any]] = {}
        self.session_cid_dirs: dict[str, dict[str, Any]] = {}
        self.tab_dirs: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self._load_store()

    def _load_store(self) -> None:
        if not self.store_path or not self.store_path.is_file():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            raw = data.get("conversations") or {}
            loaded: dict[str, dict[str, Any]] = {}
            for cid, entry in raw.items():
                if not isinstance(entry, dict):
                    continue
                rdir = str(entry.get("rules_dir") or "").strip()
                if not rdir:
                    continue
                loaded[str(cid)] = {
                    "conversation_id": str(cid),
                    "rules_dir": rdir,
                    "scope": "persistent",
                    "updated_at": float(entry.get("updated_at") or time.time()),
                }
            self.persistent_dirs = loaded
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to load workspace rules store %s: %s", self.store_path, exc)

    def _save_store_locked(self) -> None:
        if not self.store_path:
            return
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.store_path.with_suffix(".tmp")
            payload = {
                "version": 1,
                "updated_at": time.time(),
                "conversations": self.persistent_dirs,
            }
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.store_path)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to save workspace rules store: %s", exc)

    @staticmethod
    def resolve_session_key(auth_info: dict[str, Any] | None = None, mcp_session_id: str | None = None) -> str:
        info = auth_info or {}
        cid = str(info.get("conversation_id") or "").strip()
        if cid:
            return f"cid:{cid}"
        tid = str(info.get("tab_id") or "").strip()
        if tid:
            return f"tab:{tid}"
        if info.get("resolution") == "ambiguous":
            return "ambiguous"
        msid = str(mcp_session_id or "").strip()
        if msid:
            return f"mcp:{msid}"
        return "default"

    def _active_dir_for_locked(
        self,
        cid: str | None = None,
        tab_id: str | None = None,
        fallback_dir: Path | None = None,
    ) -> tuple[Path, bool]:
        rec = None
        if cid:
            rec = self.session_cid_dirs.get(cid) or self.persistent_dirs.get(cid)
        elif tab_id:
            rec = self.tab_dirs.get(tab_id)
        if rec and rec.get("rules_dir"):
            p = Path(rec["rules_dir"]).resolve(strict=False)
            if p.is_dir():
                return p, True
        if fallback_dir is not None:
            fb = Path(fallback_dir).resolve(strict=False)
            if fb.is_dir():
                return fb, False
        return self.default_dir, False

    def set_conversation_rules_dir(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        rules_dir: str = "",
        scope: str = "persistent",
    ) -> dict[str, Any]:
        cid = str(conversation_id or "").strip() or None
        tid = str(tab_id or "").strip() or None
        if not cid and not tid:
            raise ValueError("conversation_id or tab_id is required")

        cleaned = normalize_path_str(rules_dir) if str(rules_dir or "").strip() else ""
        resolved_str = ""
        if cleaned:
            target = resolve_path(cleaned)
            if not target.is_dir():
                raise ValueError(f"rules_dir does not exist or is not a directory: {target}")
            for bp in self.blocked_prefixes:
                if _is_under_prefix(target, bp):
                    raise ValueError(f"rules_dir is inside blocked path: {target}")
            resolved_str = str(target)

        scope_norm = "session" if str(scope or "").lower() == "session" else "persistent"
        now = time.time()
        with self.lock:
            if not resolved_str:
                if cid:
                    self.session_cid_dirs.pop(cid, None)
                    if self.persistent_dirs.pop(cid, None) is not None:
                        self._save_store_locked()
                if tid:
                    self.tab_dirs.pop(tid, None)
                return {
                    "conversation_id": cid,
                    "tab_id": tid,
                    "rules_dir": str(self.default_dir),
                    "is_custom": False,
                    "scope": "default",
                }

            entry = {
                "conversation_id": cid,
                "tab_id": tid if not cid else None,
                "rules_dir": resolved_str,
                "scope": scope_norm,
                "updated_at": now,
            }
            if cid:
                if scope_norm == "persistent":
                    self.session_cid_dirs.pop(cid, None)
                    self.persistent_dirs[cid] = entry
                    self._save_store_locked()
                else:
                    self.persistent_dirs.pop(cid, None)
                    self.session_cid_dirs[cid] = entry
                    self._save_store_locked()
            elif tid:
                self.tab_dirs[tid] = entry

            return {
                "conversation_id": cid,
                "tab_id": tid,
                "rules_dir": resolved_str,
                "is_custom": True,
                "scope": scope_norm,
            }

    def bind_tab_to_conversation(self, tab_id: str, cid: str | None) -> None:
        tid = str(tab_id or "").strip()
        if not tid:
            return
        tab_key = f"tab:{tid}"
        with self.lock:
            if not cid:
                self.sessions.pop(tab_key, None)
                self.tab_dirs.pop(tid, None)
                return

            cid_key = f"cid:{cid}"
            tab_state = self.sessions.pop(tab_key, None)
            if tab_state is not None and cid_key not in self.sessions:
                tab_state["session_key"] = cid_key
                self.sessions[cid_key] = tab_state

            tab_dir = self.tab_dirs.pop(tid, None)
            if tab_dir is not None and cid not in self.persistent_dirs and cid not in self.session_cid_dirs:
                promoted = dict(tab_dir)
                promoted["conversation_id"] = cid
                promoted["tab_id"] = None
                promoted["updated_at"] = time.time()
                if promoted.get("scope") == "session":
                    self.session_cid_dirs[cid] = promoted
                else:
                    promoted["scope"] = "persistent"
                    self.persistent_dirs[cid] = promoted
                    self._save_store_locked()

    def force_reset_session(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        session_key: str | None = None,
    ) -> bool:
        keys: list[str] = []
        if session_key:
            keys.append(str(session_key))
        if conversation_id:
            keys.append(f"cid:{str(conversation_id).strip()}")
        if tab_id:
            keys.append(f"tab:{str(tab_id).strip()}")
        if not keys:
            keys = list(self.sessions.keys())
        cleared = False
        with self.lock:
            for k in keys:
                st = self.sessions.get(k)
                if st is not None:
                    st["last_injected_hash"] = None
                    st["calls_since_inject"] = 0
                    st["output_chars_since_inject"] = 0
                    st["last_reason"] = "manual_reset"
                    cleared = True
        return cleared

    def discover_rules(self, rules_dir: Path) -> dict[str, Any]:
        root = Path(rules_dir).resolve(strict=False)
        if not root.is_dir():
            return {
                "rules_dir": str(root),
                "files": [],
                "rules_hash": "",
                "total_chars": 0,
                "truncated": False,
            }

        candidates: list[Path] = []
        seen_norm: set[str] = set()
        for pat in self.patterns:
            norm_pat = pat.replace("\\", "/").lstrip("/")
            if not norm_pat:
                continue
            if any(ch in norm_pat for ch in "*?["):
                matched = sorted(root.glob(norm_pat), key=lambda p: p.as_posix().lower())
            else:
                matched = [root / norm_pat]
            for path in matched:
                try:
                    resolved = path.resolve(strict=False)
                except OSError:
                    continue
                if not resolved.is_file():
                    continue
                if not _is_under_prefix(resolved, root):
                    continue
                key = os.path.normcase(str(resolved))
                if key in seen_norm:
                    continue
                seen_norm.add(key)
                candidates.append(resolved)

        file_entries: list[dict[str, Any]] = []
        hasher = hashlib.sha256()
        total_chars = 0

        for path in candidates:
            try:
                raw = path.read_bytes()
            except OSError as exc:
                LOG.warning("failed to read workspace rule file %s: %s", path, exc)
                continue
            if len(raw) > self.max_file_bytes:
                raw = raw[: self.max_file_bytes]
                text = raw.decode("utf-8", errors="replace") + "\n\n[truncated: file exceeded max_file_bytes]\n"
            else:
                text = raw.decode("utf-8", errors="replace")
            rel = path.relative_to(root).as_posix()
            f_sha = hashlib.sha256(raw).hexdigest()
            hasher.update(rel.encode("utf-8"))
            hasher.update(b"\x00")
            hasher.update(f_sha.encode("ascii"))
            hasher.update(b"\n")
            file_entries.append({
                "path": rel,
                "abs_path": str(path),
                "size_bytes": len(raw),
                "chars": len(text),
                "sha256": f_sha,
                "sha256_prefix": f_sha[:12],
                "content": text,
            })
            total_chars += len(text)

        rules_hash = hasher.hexdigest() if file_entries else ""
        return {
            "rules_dir": str(root),
            "files": file_entries,
            "rules_hash": rules_hash,
            "total_chars": total_chars,
            "truncated": total_chars > self.max_total_chars,
        }

    def _format_injection_block(
        self,
        discovered: dict[str, Any],
        *,
        reason: str,
        call_step: int,
    ) -> str:
        if reason == "rules_removed":
            return (
                f'<workspace_rules_update reason="rules_removed" workspace="{discovered["rules_dir"]}" '
                f'call_step="{call_step}">\n'
                "工作区内的规则文档（AGENTS.md / GEMINI.md / .gemini/rules/*.md）已被移除；此前注入的旧工作区规则不再适用。\n"
                "</workspace_rules_update>"
            )

        header = (
            f'<workspace_rules reason="{reason}" workspace="{discovered["rules_dir"]}" '
            f'rules_hash="{discovered["rules_hash"][:12]}" call_step="{call_step}" '
            f'reinject_every_calls="{self.reinject_every_calls}" '
            f'reinject_every_output_chars="{self.reinject_every_output_chars}">'
        )
        lines = [
            header,
            "以下为当前工作区实时读取的规则文档（请作为当前工作区权威约束执行）：",
        ]
        budget = self.max_total_chars
        used = 0
        for item in discovered["files"]:
            body = item["content"].strip("\r\n")
            if used >= budget:
                lines.append(f'<rule_file path="{item["path"]}" omitted="max_total_chars_exceeded" />')
                continue
            remaining = budget - used
            truncated_note = ""
            if len(body) > remaining:
                body = body[: max(0, remaining - 64)].rstrip()
                truncated_note = "\n...[truncated by max_total_chars]..."
            used += len(body)
            lines.append(f'<rule_file path="{item["path"]}" sha256="{item["sha256_prefix"]}">')
            lines.append(body + truncated_note)
            lines.append("</rule_file>")
        lines.append("</workspace_rules>")
        return "\n".join(lines)

    def maybe_build_injection(
        self,
        *,
        session_key: str,
        cid: str | None = None,
        tab_id: str | None = None,
        output_chars: int = 0,
        default_rules_dir: Path | None = None,
    ) -> dict[str, Any] | None:
        if not self.enabled:
            return None

        with self.lock:
            active_dir, is_custom_dir = self._active_dir_for_locked(
                cid=cid, tab_id=tab_id, fallback_dir=default_rules_dir,
            )
        discovered = self.discover_rules(active_dir)
        cur_hash = discovered["rules_hash"]
        cur_dir_str = discovered["rules_dir"]
        now = time.time()

        with self.lock:
            st = self.sessions.get(session_key)
            if st is None:
                st = {
                    "session_key": session_key,
                    "last_injected_hash": None,
                    "last_rules_dir": "",
                    "last_injected_at": 0.0,
                    "last_reason": "",
                    "calls_since_inject": 0,
                    "output_chars_since_inject": 0,
                    "total_calls": 0,
                    "total_injections": 0,
                    "rules_dir": cur_dir_str,
                    "is_custom_dir": is_custom_dir,
                }
                self.sessions[session_key] = st

            st["total_calls"] += 1
            st["rules_dir"] = cur_dir_str
            st["is_custom_dir"] = is_custom_dir
            call_step = st["total_calls"]

            prev_hash = st["last_injected_hash"]
            prev_dir = st["last_rules_dir"]

            reason = ""
            if prev_hash is None:
                if cur_hash:
                    reason = "initial"
                else:
                    # No rule files exist yet -> initialize clean baseline without noise
                    st["last_injected_hash"] = ""
                    st["last_rules_dir"] = cur_dir_str
                    return None
            elif cur_hash != prev_hash or cur_dir_str != prev_dir:
                if cur_hash:
                    reason = "rules_changed"
                elif prev_hash:
                    reason = "rules_removed"
                else:
                    st["last_rules_dir"] = cur_dir_str
                    return None
            else:
                if not cur_hash:
                    return None
                st["calls_since_inject"] += 1
                st["output_chars_since_inject"] += max(0, int(output_chars or 0))
                if self.reinject_every_calls > 0 and st["calls_since_inject"] >= self.reinject_every_calls:
                    reason = "periodic_calls"
                elif (
                    self.reinject_every_output_chars > 0
                    and st["output_chars_since_inject"] >= self.reinject_every_output_chars
                ):
                    reason = "output_volume"

            if not reason:
                return None

            st["last_injected_hash"] = cur_hash
            st["last_rules_dir"] = cur_dir_str
            st["last_injected_at"] = now
            st["last_reason"] = reason
            st["calls_since_inject"] = 0
            st["output_chars_since_inject"] = 0
            st["total_injections"] += 1

        text = self._format_injection_block(discovered, reason=reason, call_step=call_step)
        return {
            "reason": reason,
            "text": text,
            "rules_hash": cur_hash,
            "rules_dir": cur_dir_str,
            "call_step": call_step,
            "files": [
                {"path": f["path"], "size_bytes": f["size_bytes"], "sha256_prefix": f["sha256_prefix"]}
                for f in discovered["files"]
            ],
        }

    def peek_status(
        self,
        *,
        session_key: str = "default",
        cid: str | None = None,
        tab_id: str | None = None,
        default_rules_dir: Path | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            active_dir, is_custom = self._active_dir_for_locked(
                cid=cid, tab_id=tab_id, fallback_dir=default_rules_dir,
            )
            st = dict(self.sessions.get(session_key) or {})
        discovered = self.discover_rules(active_dir)
        calls_since = int(st.get("calls_since_inject", 0))
        chars_since = int(st.get("output_chars_since_inject", 0))
        remaining_calls = (
            max(0, self.reinject_every_calls - calls_since) if self.reinject_every_calls > 0 else None
        )
        return {
            "enabled": self.enabled,
            "active_rules_dir": discovered["rules_dir"],
            "is_custom_dir": is_custom,
            "patterns": list(self.patterns),
            "rules_hash": discovered["rules_hash"],
            "rules_hash_prefix": discovered["rules_hash"][:12] if discovered["rules_hash"] else "",
            "detected_files": [
                {
                    "path": f["path"],
                    "size_bytes": f["size_bytes"],
                    "chars": f["chars"],
                    "sha256_prefix": f["sha256_prefix"],
                }
                for f in discovered["files"]
            ],
            "reinject_every_calls": self.reinject_every_calls,
            "reinject_every_output_chars": self.reinject_every_output_chars,
            "max_total_chars": self.max_total_chars,
            "session": {
                "session_key": session_key,
                "total_calls": int(st.get("total_calls", 0)),
                "total_injections": int(st.get("total_injections", 0)),
                "calls_since_inject": calls_since,
                "remaining_calls_until_reinject": remaining_calls,
                "output_chars_since_inject": chars_since,
                "last_reason": st.get("last_reason") or "",
                "last_injected_hash_prefix": (st.get("last_injected_hash") or "")[:12],
            },
        }

    def snapshot(self, bridge_mgr=None) -> dict[str, Any]:
        default_disc = self.discover_rules(self.default_dir)
        with self.lock:
            sessions_copy = [dict(v) for v in self.sessions.values()]
            custom_bindings = {
                "persistent": [dict(v) for v in self.persistent_dirs.values()],
                "session": [dict(v) for v in self.session_cid_dirs.values()],
                "turn1_tabs": [dict(v) for v in self.tab_dirs.values()],
            }
        live_tabs = bridge_mgr.status_snapshot()["tabs"] if bridge_mgr is not None else []
        ws_mgr = getattr(bridge_mgr, "workspace_mgr", None) if bridge_mgr is not None else None
        tab_rules = {}
        for t in live_tabs:
            cid = t.get("conversation_id")
            tid = t.get("tab_id")
            skey = f"cid:{cid}" if cid else f"tab:{tid}"
            fb = ws_mgr.resolve_active_dir({"conversation_id": cid, "tab_id": tid}) if ws_mgr is not None else None
            tab_rules[tid] = self.peek_status(session_key=skey, cid=cid, tab_id=tid, default_rules_dir=fb)
        return {
            "enabled": self.enabled,
            "default_rules_dir": str(self.default_dir),
            "reinject_every_calls": self.reinject_every_calls,
            "reinject_every_output_chars": self.reinject_every_output_chars,
            "max_total_chars": self.max_total_chars,
            "patterns": list(self.patterns),
            "default_detected_files": [
                {
                    "path": f["path"],
                    "size_bytes": f["size_bytes"],
                    "chars": f["chars"],
                    "sha256_prefix": f["sha256_prefix"],
                }
                for f in default_disc["files"]
            ],
            "default_rules_hash_prefix": default_disc["rules_hash"][:12] if default_disc["rules_hash"] else "",
            "custom_bindings": custom_bindings,
            "tab_rules": tab_rules,
            "sessions": sessions_copy,
        }
