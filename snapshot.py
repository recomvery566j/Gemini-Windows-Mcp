"""Pre-write snapshot and automatic retention pruning."""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime
from pathlib import Path


class SnapshotManager:
    """Creates timestamped .bak copies before overwriting or editing existing files."""

    def __init__(self, snapshot_root: Path, enabled: bool = True, max_versions: int = 20):
        self.snapshot_root = snapshot_root
        self.enabled = enabled
        self.max_versions = max(1, int(max_versions))

    def backup(self, target: Path) -> Path | None:
        if not self.enabled or not target.is_file():
            return None

        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        path_hash = hashlib.sha1(str(target).lower().encode("utf-8")).hexdigest()[:8]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:19]
        prefix = f"{target.name}.{path_hash}."
        snap_path = self.snapshot_root / f"{prefix}{ts}.bak"
        shutil.copy2(target, snap_path)

        # Prune older versions beyond max_versions
        siblings = sorted(
            self.snapshot_root.glob(f"{prefix}*.bak"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in siblings[self.max_versions:]:
            try:
                old.unlink()
            except OSError:
                pass
        return snap_path
