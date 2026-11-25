"""Per-conversation workspace directory binding and saved workspace registry.

Allows the user to save frequently used local project folders and bind any
Gemini conversation URL (`/app/<cid>`, including Turn-1 `/app` promotion) to a
switched workspace directory via the Tampermonkey local bridge. Once bound, all
path resolution, three-zone checks, cwd defaults, `.mcp_snapshots`, `.tmp_outputs`,
and workspace rule discovery behave identically to the default workspace.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from security import normalize_path_str, resolve_path

LOG = logging.getLogger("pc-work-mcp.workspaces")


def _is_under_prefix(target: Path, prefix: Path) -> bool:
    t = os.path.normcase(str(target.resolve(strict=False)))
    p = os.path.normcase(str(prefix.resolve(strict=False)))
    try:
        return os.path.commonpath([t, p]) == p
    except ValueError:
        return False


def _same_path(a: Path, b: Path) -> bool:
    return os.path.normcase(str(a.resolve(strict=False))) == os.path.normcase(str(b.resolve(strict=False)))


class WorkspaceBindingManager:
    """Manages saved local workspaces and per-conversation active workspace bindings."""

    def __init__(
        self,
        default_dir: Path,
        *,
        store_path: Path | None = None,
        blocked_prefixes: list[Path] | None = None,
        folder_picker: Callable[[str, Path], Path | None] | None = None,
    ):
        self.default_dir = Path(default_dir).resolve(strict=False)
        self.store_path = Path(store_path).resolve(strict=False) if store_path else None
        self.blocked_prefixes = list(blocked_prefixes or ())
        self.folder_picker = folder_picker

        self.lock = threading.Lock()
        self.saved_workspaces: list[dict[str, Any]] = []
        self.persistent_bindings: dict[str, dict[str, Any]] = {}
        self.session_cid_bindings: dict[str, dict[str, Any]] = {}
        self.tab_bindings: dict[str, dict[str, Any]] = {}
        self._load_store()

    def _validate_dir(self, raw_dir: str) -> Path:
        cleaned = normalize_path_str(raw_dir)
        if not cleaned:
            raise ValueError("workspace_dir is required")
        target = resolve_path(cleaned, base_dir=self.default_dir)
        if not target.is_dir():
            raise ValueError(f"workspace directory does not exist: {target}")
        for bp in self.blocked_prefixes:
            if _is_under_prefix(target, bp):
                raise ValueError(f"workspace directory is inside blocked path: {target}")
        return target

    def _load_store(self) -> None:
        if not self.store_path or not self.store_path.is_file():
            return
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
            saved_raw = data.get("saved_workspaces") or []
            seen_norm: set[str] = set()
            loaded_saved: list[dict[str, Any]] = []
            for item in saved_raw:
                if isinstance(item, str):
                    p_str, label, added = item, "", time.time()
                elif isinstance(item, dict):
                    p_str = str(item.get("path") or "").strip()
                    label = str(item.get("label") or "").strip()
                    added = float(item.get("added_at") or time.time())
                else:
                    continue
                if not p_str:
                    continue
                p_obj = resolve_path(p_str)
                norm = os.path.normcase(str(p_obj))
                if norm in seen_norm or _same_path(p_obj, self.default_dir):
                    continue
                seen_norm.add(norm)
                loaded_saved.append({
                    "path": str(p_obj),
                    "label": label or p_obj.name or str(p_obj),
                    "added_at": added,
                })
            self.saved_workspaces = loaded_saved

            conv_raw = data.get("conversations") or {}
            loaded_conv: dict[str, dict[str, Any]] = {}
            for cid, entry in conv_raw.items():
                if not isinstance(entry, dict):
                    continue
                wdir = str(entry.get("workspace_dir") or "").strip()
                if not wdir:
                    continue
                wobj = resolve_path(wdir)
                loaded_conv[str(cid)] = {
                    "conversation_id": str(cid),
                    "workspace_dir": str(wobj),
                    "label": str(entry.get("label") or wobj.name or str(wobj)),
                    "url": str(entry.get("url") or f"https://gemini.google.com/app/{cid}"),
                    "title": str(entry.get("title") or ""),
                    "scope": "persistent",
                    "updated_at": float(entry.get("updated_at") or time.time()),
                }
            self.persistent_bindings = loaded_conv
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to load workspace bindings store %s: %s", self.store_path, exc)

    def _save_store_locked(self) -> None:
        if not self.store_path:
            return
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.store_path.with_suffix(".tmp")
            payload = {
                "version": 1,
                "updated_at": time.time(),
                "saved_workspaces": self.saved_workspaces,
                "conversations": self.persistent_bindings,
            }
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.store_path)
        except Exception as exc:  # noqa: BLE001
            LOG.warning("failed to save workspace bindings store: %s", exc)

    def _add_saved_locked(self, target: Path, label: str = "") -> dict[str, Any]:
        if _same_path(target, self.default_dir):
            return {
                "path": str(self.default_dir),
                "label": self.default_dir.name or "默认工作区",
                "is_default": True,
                "added_at": 0.0,
            }
        norm = os.path.normcase(str(target))
        for item in self.saved_workspaces:
            if os.path.normcase(item["path"]) == norm:
                if label:
                    item["label"] = label
                    self._save_store_locked()
                return dict(item)
        rec = {
            "path": str(target),
            "label": (label or target.name or str(target)).strip(),
            "added_at": time.time(),
        }
        self.saved_workspaces.append(rec)
        self._save_store_locked()
        return dict(rec)

    def add_saved_workspace(self, workspace_dir: str, label: str = "") -> dict[str, Any]:
        target = self._validate_dir(workspace_dir)
        with self.lock:
            rec = self._add_saved_locked(target, label=label)
        rec["exists"] = target.is_dir()
        return rec

    def remove_saved_workspace(self, workspace_dir: str) -> bool:
        cleaned = normalize_path_str(workspace_dir)
        if not cleaned:
            return False
        target = resolve_path(cleaned)
        norm = os.path.normcase(str(target))
        with self.lock:
            before = len(self.saved_workspaces)
            self.saved_workspaces = [
                item for item in self.saved_workspaces
                if os.path.normcase(item["path"]) != norm
            ]
            removed = len(self.saved_workspaces) != before
            if removed:
                self._save_store_locked()
            return removed

    def pick_and_save_workspace(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        bind: bool = True,
        scope: str = "persistent",
        url: str = "",
        title: str = "",
        initial_dir: str = "",
    ) -> dict[str, Any]:
        if self.folder_picker is None:
            raise ValueError("native folder picker is not available in this server mode")
        init_path = self.default_dir
        if initial_dir:
            cand = resolve_path(normalize_path_str(initial_dir))
            if cand.is_dir():
                init_path = cand
        chosen = self.folder_picker("选择工作区文件夹（保存并可绑定到当前会话）", init_path)
        if chosen is None:
            return {"ok": True, "cancelled": True}
        target = self._validate_dir(str(chosen))
        with self.lock:
            saved_rec = self._add_saved_locked(target)
        binding = None
        if bind and (conversation_id or tab_id):
            binding = self.bind_workspace(
                conversation_id=conversation_id,
                tab_id=tab_id,
                workspace_dir=str(target),
                scope=scope,
                url=url,
                title=title,
                save_to_list=False,
            )
        return {
            "ok": True,
            "cancelled": False,
            "saved": saved_rec,
            "binding": binding,
        }

    def bind_workspace(
        self,
        *,
        conversation_id: str | None = None,
        tab_id: str | None = None,
        workspace_dir: str = "",
        scope: str = "persistent",
        url: str = "",
        title: str = "",
        save_to_list: bool = True,
    ) -> dict[str, Any]:
        cid = str(conversation_id or "").strip() or None
        tid = str(tab_id or "").strip() or None
        if not cid and not tid:
            raise ValueError("conversation_id or tab_id is required")

        cleaned = normalize_path_str(workspace_dir) if str(workspace_dir or "").strip() else ""
        if not cleaned:
            return self.unbind_workspace(conversation_id=cid, tab_id=tid)

        target = self._validate_dir(cleaned)
        if _same_path(target, self.default_dir):
            return self.unbind_workspace(conversation_id=cid, tab_id=tid)

        scope_norm = "session" if str(scope or "").lower() == "session" else "persistent"
        now = time.time()
        entry = {
            "conversation_id": cid,
            "tab_id": tid if not cid else None,
            "workspace_dir": str(target),
            "label": target.name or str(target),
            "url": str(url or (f"https://gemini.google.com/app/{cid}" if cid else "https://gemini.google.com/app")),
            "title": str(title or ""),
            "scope": scope_norm,
            "updated_at": now,
        }
        with self.lock:
            if save_to_list:
                self._add_saved_locked(target)
            if cid:
                if scope_norm == "persistent":
                    self.session_cid_bindings.pop(cid, None)
                    self.persistent_bindings[cid] = entry
                    self._save_store_locked()
                else:
                    self.persistent_bindings.pop(cid, None)
                    self.session_cid_bindings[cid] = entry
                    self._save_store_locked()
            elif tid:
                self.tab_bindings[tid] = entry

        out = dict(entry)
        out["is_custom"] = True
        return out

    def unbind_workspace(self, *, conversation_id: str | None = None, tab_id: str | None = None) -> dict[str, Any]:
        cid = str(conversation_id or "").strip() or None
        tid = str(tab_id or "").strip() or None
        with self.lock:
            if cid:
                self.session_cid_bindings.pop(cid, None)
                if self.persistent_bindings.pop(cid, None) is not None:
                    self._save_store_locked()
            if tid:
                self.tab_bindings.pop(tid, None)
        return {
            "conversation_id": cid,
            "tab_id": tid,
            "workspace_dir": str(self.default_dir),
            "label": self.default_dir.name or str(self.default_dir),
            "scope": "default",
            "is_custom": False,
        }

    def bind_tab_to_conversation(
        self,
        tab_id: str,
        cid: str | None,
        url: str = "",
        title: str = "",
    ) -> None:
        tid = str(tab_id or "").strip()
        if not tid:
            return
        now = time.time()
        with self.lock:
            if not cid:
                self.tab_bindings.pop(tid, None)
                return

            tab_rec = self.tab_bindings.pop(tid, None)
            if tab_rec is not None:
                if cid not in self.persistent_bindings and cid not in self.session_cid_bindings:
                    promoted = dict(tab_rec)
                    promoted["conversation_id"] = cid
                    promoted["tab_id"] = None
                    promoted["url"] = url or f"https://gemini.google.com/app/{cid}"
                    if title:
                        promoted["title"] = title
                    promoted["updated_at"] = now
                    if promoted.get("scope") == "session":
                        self.session_cid_bindings[cid] = promoted
                    else:
                        promoted["scope"] = "persistent"
                        self.persistent_bindings[cid] = promoted
                        self._save_store_locked()
            elif cid in self.persistent_bindings:
                changed = False
                if title and not self.persistent_bindings[cid].get("title"):
                    self.persistent_bindings[cid]["title"] = title
                    changed = True
                if url and self.persistent_bindings[cid].get("url") != url:
                    self.persistent_bindings[cid]["url"] = url
                    changed = True
                if changed:
                    self._save_store_locked()

    def get_effective_workspace(self, *, cid: str | None = None, tab_id: str | None = None) -> dict[str, Any]:
        with self.lock:
            rec = None
            if cid:
                rec = self.session_cid_bindings.get(cid) or self.persistent_bindings.get(cid)
            elif tab_id:
                rec = self.tab_bindings.get(tab_id)
            if rec and rec.get("workspace_dir"):
                p = Path(rec["workspace_dir"]).resolve(strict=False)
                if p.is_dir():
                    out = dict(rec)
                    out["workspace_dir"] = str(p)
                    out["is_custom"] = not _same_path(p, self.default_dir)
                    return out
        return {
            "conversation_id": cid,
            "tab_id": tab_id,
            "workspace_dir": str(self.default_dir),
            "label": self.default_dir.name or str(self.default_dir),
            "scope": "default",
            "is_custom": False,
        }

    def resolve_active_dir(self, auth_info: dict[str, Any] | None = None) -> Path:
        info = auth_info or {}
        eff = self.get_effective_workspace(
            cid=info.get("conversation_id"),
            tab_id=info.get("tab_id"),
        )
        return Path(eff["workspace_dir"]).resolve(strict=False)

    def snapshot(self, bridge_mgr=None) -> dict[str, Any]:
        with self.lock:
            saved = []
            for item in self.saved_workspaces:
                p = Path(item["path"])
                saved.append({
                    "path": item["path"],
                    "label": item.get("label") or p.name or item["path"],
                    "exists": p.is_dir(),
                    "added_at": item.get("added_at", 0.0),
                })
            persistent = [dict(v) for v in sorted(self.persistent_bindings.values(), key=lambda x: x.get("updated_at", 0), reverse=True)]
            session_cids = [dict(v) for v in sorted(self.session_cid_bindings.values(), key=lambda x: x.get("updated_at", 0), reverse=True)]
            turn1 = [dict(v) for v in self.tab_bindings.values()]

        live_tabs = bridge_mgr.status_snapshot()["tabs"] if bridge_mgr is not None else []
        for t in live_tabs:
            t["workspace_binding"] = self.get_effective_workspace(
                cid=t.get("conversation_id"),
                tab_id=t.get("tab_id"),
            )
        return {
            "server_default_workspace": str(self.default_dir),
            "saved_workspaces": saved,
            "live_tabs": live_tabs,
            "persistent_conversations": persistent,
            "session_conversations": session_cids,
            "pending_turn1_tabs": turn1,
        }
