"""Data-preserving uninstall path validation (SEC-035)."""

from __future__ import annotations

import os
from pathlib import Path


class UnsafePurgePath(ValueError):
    """Purge targets outside an owned data root or through a symlink."""


def validate_purge_path(target: Path, *, owned_roots: tuple[Path, ...]) -> Path:
    """Resolve a purge target without following a symlink escape; reject roots and parents."""
    raw = Path(os.path.abspath(target))
    # Reject any symlink component before resolving, including a symlink target itself.
    cursor = Path(raw.anchor)
    for part in raw.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise UnsafePurgePath("Purge target contains a symlink component.")
    resolved = raw.resolve(strict=False)
    for root in owned_roots:
        root_resolved = root.resolve(strict=False)
        if resolved == root_resolved or resolved.is_relative_to(root_resolved):
            if (
                resolved == Path(resolved.anchor)
                or resolved == Path.home()
                or resolved in Path.home().parents
            ):
                raise UnsafePurgePath("Purge target may not be a filesystem or home root.")
            return resolved
    raise UnsafePurgePath("Purge target is outside configured Red2PR data directories.")
