"""Restore working tree from a downloaded .git/ directory.

We rely on dulwich to walk trees and write blobs. We also recover orphan blobs
(those not reachable from HEAD) — git-dumper skips these.
"""
from __future__ import annotations

import os
import stat
import zlib
from pathlib import Path

from dulwich.objects import Blob, Commit, ShaFile, Tree  # type: ignore[import-not-found]
from dulwich.repo import Repo  # type: ignore[import-not-found]

from ..logger import get_logger


def _iter_loose(objects_dir: Path):
    for sub in objects_dir.iterdir():
        if not sub.is_dir() or len(sub.name) != 2:
            continue
        for f in sub.iterdir():
            if len(f.name) == 38:
                yield sub.name + f.name, f


def _load_object(path: Path) -> ShaFile | None:
    try:
        data = zlib.decompress(path.read_bytes())
    except Exception:
        return None
    header, _, content = data.partition(b"\0")
    if b" " not in header:
        return None
    type_name, size_b = header.split(b" ", 1)
    try:
        return ShaFile.from_raw_string(_TYPE_MAP[type_name], content)
    except Exception:
        return None


_TYPE_MAP = {b"blob": 3, b"commit": 1, b"tree": 2, b"tag": 4}


def _write_tree(repo_root: Path, tree: Tree, current: Path, store) -> int:
    """Recursively write blobs of a tree under current path."""
    count = 0
    for entry in tree.items():
        path_name = entry.path.decode("utf-8", "replace") if isinstance(entry.path, bytes) else entry.path
        target = current / path_name
        try:
            obj = store[entry.sha]
        except KeyError:
            continue
        if isinstance(obj, Tree):
            target.mkdir(parents=True, exist_ok=True)
            count += _write_tree(repo_root, obj, target, store)
        elif isinstance(obj, Blob):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(obj.data)
            count += 1
            # Preserve exec bit when mode == 100755
            mode = entry.mode if isinstance(entry.mode, int) else int(entry.mode, 8)
            if mode & 0o111:
                st = target.stat()
                os.chmod(target, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return count


def restore_worktree(git_root: Path, out_dir: Path) -> dict:
    """Walk HEAD->tree and write files. Also dump orphan blobs."""
    log = get_logger()
    out_dir.mkdir(parents=True, exist_ok=True)

    repo = Repo(str(git_root.parent))  # parent dir hosts .git/
    head_files = 0
    head_sha = None
    try:
        head_sha = repo.head().decode()
        commit = repo[repo.head()]
        if isinstance(commit, Commit):
            tree = repo[commit.tree]
            if isinstance(tree, Tree):
                head_files = _write_tree(out_dir, tree, out_dir, repo.object_store)
                log.success(f"restored {head_files} files from HEAD {head_sha[:10]}")
    except Exception as e:
        log.warning(f"HEAD restoration failed: {e}")

    # Reachable-blob bookkeeping (cheap pass; not used to filter)
    seen: set[str] = set()
    try:
        # collect reachable shas first
        for entry in repo.object_store:
            obj = repo[entry]
            if isinstance(obj, Blob):
                sha = entry.decode() if isinstance(entry, bytes) else entry
                if sha not in seen:
                    seen.add(sha)
    except Exception:
        pass

    # We can't easily compute reachability fast; instead, dump every blob's
    # bytes side-by-side with HEAD restoration so analysts can grep both.
    blobs_dir = out_dir / ".gitexpose_all_blobs"
    blobs_dir.mkdir(parents=True, exist_ok=True)
    blob_count = 0
    for entry in repo.object_store:
        try:
            obj = repo[entry]
        except Exception:
            continue
        if isinstance(obj, Blob):
            sha = entry.decode() if isinstance(entry, bytes) else entry
            (blobs_dir / f"{sha}.blob").write_bytes(obj.data)
            blob_count += 1
    log.success(f"dumped {blob_count} blobs to {blobs_dir.relative_to(out_dir.parent)}")

    return {
        "head_sha": head_sha,
        "head_files": head_files,
        "total_blobs": blob_count,
    }
