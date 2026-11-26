"""Lightweight native read-only file discovery and content search (stdlib only)."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

DEFAULT_IGNORED_DIRS = frozenset({
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".mcp_snapshots",
    ".tmp_outputs",
    ".pytest_cache",
    ".mypy_cache",
    ".brave-agent-profile",
    ".gemini-profile-backup",
})

MAX_FILE_BYTES = 2 * 1024 * 1024  # Skip >2MB files during grep
MAX_LINE_CHARS = 300


def normalize_ignore_entry(raw: str) -> str:
    """Normalize a user/agent ignore entry to a clean directory name or glob pattern."""
    s = str(raw or "").strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        s = s[1:-1].strip()
    if not s:
        return ""
    norm_sep = s.replace("\\", "/").rstrip("/")
    if not norm_sep:
        return ""
    if "/" in norm_sep:
        norm_sep = norm_sep.rsplit("/", 1)[-1].strip()
    if norm_sep in ("", ".", ".."):
        return ""
    return norm_sep


def is_ignored_dir_name(
    name: str,
    extra_ignored: list[str] | tuple[str, ...] | set[str] | None = None,
) -> bool:
    """Return True if directory `name` matches built-in or configured ignore patterns."""
    if name in DEFAULT_IGNORED_DIRS:
        return True
    for pat in extra_ignored or ():
        p = str(pat or "").strip()
        if not p:
            continue
        if any(ch in p for ch in "*?["):
            if fnmatch.fnmatch(name, p):
                return True
        elif name.lower() == p.lower():
            return True
    return False


def _read_text_for_search(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:2048]:
        return None
    for enc in ("utf-8-sig", "utf-8", "gbk", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _matches_pattern(rel_posix: str, filename: str, pattern: str) -> bool:
    pat = (pattern or "*").strip()
    if not pat or pat == "*":
        return True
    pat_norm = pat.replace("\\", "/").lstrip("./")
    if "/" in pat_norm:
        return fnmatch.fnmatch(rel_posix, pat_norm)
    return fnmatch.fnmatch(filename, pat_norm)


def _iter_files(
    target: Path,
    *,
    include_ignored: bool = False,
    extra_ignored: list[str] | tuple[str, ...] | set[str] | None = None,
):
    if target.is_file():
        yield target
        return
    if not target.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(target):
        if not include_ignored:
            dirnames[:] = sorted(d for d in dirnames if not is_ignored_dir_name(d, extra_ignored))
        else:
            dirnames.sort()
        for fname in sorted(filenames):
            yield Path(dirpath) / fname


def find_files(
    target: Path,
    *,
    base_dir: Path | None = None,
    pattern: str = "*",
    max_results: int = 200,
    include_ignored: bool = False,
    extra_ignored: list[str] | tuple[str, ...] | set[str] | None = None,
) -> dict[str, Any]:
    """Find files matching glob pattern under `target` without invoking a shell."""
    if not target.exists():
        raise ValueError(f"path not found: {target}")
    cap = max(1, min(int(max_results or 200), 1000))
    root = base_dir if base_dir and target.is_dir() else (target if target.is_dir() else target.parent)

    matches: list[str] = []
    truncated = False
    for fpath in _iter_files(target, include_ignored=include_ignored, extra_ignored=extra_ignored):
        try:
            rel_posix = fpath.relative_to(target if target.is_dir() else root).as_posix()
        except ValueError:
            rel_posix = fpath.name
        if not _matches_pattern(rel_posix, fpath.name, pattern):
            continue
        if len(matches) >= cap:
            truncated = True
            break
        try:
            disp = fpath.relative_to(root).as_posix()
        except ValueError:
            disp = str(fpath)
        matches.append(disp)

    lines = [f"[root: {target} | pattern: {pattern or '*'} | count: {len(matches)}{' (truncated)' if truncated else ''}]"]
    if matches:
        lines.extend(matches)
    else:
        lines.append("(no matching files)")
    if truncated:
        lines.append(f"... [truncated at {cap} results; narrow path or pattern]")
    return {
        "matches": matches,
        "count": len(matches),
        "truncated": truncated,
        "text": "\n".join(lines),
    }


def grep_search(
    target: Path,
    query: str,
    *,
    base_dir: Path | None = None,
    is_regex: bool = False,
    case_sensitive: bool = True,
    include: str = "",
    max_matches: int = 60,
    context_lines: int = 0,
    include_ignored: bool = False,
    extra_ignored: list[str] | tuple[str, ...] | set[str] | None = None,
) -> dict[str, Any]:
    """Search file contents inside `target` using literal substring or regex."""
    if not target.exists():
        raise ValueError(f"path not found: {target}")
    if not isinstance(query, str) or not query:
        raise ValueError("query must be a non-empty string")

    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(query if is_regex else re.escape(query), flags)
    except re.error as exc:
        raise ValueError(f"invalid regex: {exc}") from exc

    cap = max(1, min(int(max_matches or 60), 300))
    ctx = max(0, min(int(context_lines or 0), 3))
    root = base_dir if base_dir and target.is_dir() else (target if target.is_dir() else target.parent)

    files_scanned = 0
    matched_count = 0
    truncated = False
    out_lines: list[str] = []

    for fpath in _iter_files(target, include_ignored=include_ignored, extra_ignored=extra_ignored):
        try:
            rel_posix = fpath.relative_to(target if target.is_dir() else root).as_posix()
        except ValueError:
            rel_posix = fpath.name
        if include and not _matches_pattern(rel_posix, fpath.name, include):
            continue

        text = _read_text_for_search(fpath)
        if text is None:
            continue
        files_scanned += 1
        lines = text.splitlines()

        try:
            disp = fpath.relative_to(root).as_posix()
        except ValueError:
            disp = str(fpath)

        for idx, line in enumerate(lines):
            if not regex.search(line):
                continue
            if matched_count >= cap:
                truncated = True
                break
            matched_count += 1
            if ctx > 0:
                start = max(0, idx - ctx)
                end = min(len(lines), idx + ctx + 1)
                for j in range(start, end):
                    marker = ":" if j == idx else "-"
                    snippet = lines[j]
                    if len(snippet) > MAX_LINE_CHARS:
                        snippet = snippet[:MAX_LINE_CHARS] + f" ...(+{len(snippet) - MAX_LINE_CHARS} chars)"
                    out_lines.append(f"{disp}:{j + 1}{marker} {snippet}")
                if end - start > 1:
                    out_lines.append("--")
            else:
                snippet = line
                if len(snippet) > MAX_LINE_CHARS:
                    snippet = snippet[:MAX_LINE_CHARS] + f" ...(+{len(snippet) - MAX_LINE_CHARS} chars)"
                out_lines.append(f"{disp}:{idx + 1}: {snippet}")

        if truncated:
            break

    header = (
        f"[query: {query!r} | matches: {matched_count} | files_scanned: {files_scanned}"
        f"{' | truncated' if truncated else ''}]"
    )
    body = "\n".join([header] + (out_lines if out_lines else ["(no matches)"]))
    if truncated:
        body += f"\n... [truncated at {cap} matches; narrow path or include filter]"
    return {
        "matches": matched_count,
        "files_scanned": files_scanned,
        "truncated": truncated,
        "text": body,
    }
