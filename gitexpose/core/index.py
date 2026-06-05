"""Parse .git/index to discover blob SHAs (incl. deleted-but-staged files)."""
from __future__ import annotations

from pathlib import Path

from dulwich.index import Index  # type: ignore[import-not-found]

from ..logger import get_logger


def parse_index(index_path: Path) -> dict[str, str]:
    """Return mapping {path: sha} of every entry in the index."""
    log = get_logger()
    mapping: dict[str, str] = {}
    if not index_path.exists():
        return mapping
    try:
        idx = Index(str(index_path))
    except Exception as e:
        log.warning(f"index parse failed: {e}")
        return mapping
    for path, entry in idx.items():
        try:
            sha = entry.sha.decode() if isinstance(entry.sha, bytes) else entry.sha
            decoded = path.decode("utf-8", "replace") if isinstance(path, bytes) else path
            mapping[decoded] = sha
        except Exception:
            continue
    log.debug(f"index contains {len(mapping)} entries")
    return mapping
