"""Walk every commit + dangling object + reflog and scan for secrets."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable

from .patterns import Finding, dedupe, scan_text


def _git(args: list[str], cwd: Path, timeout: int = 120) -> str:
    try:
        proc = subprocess.run(
            ["git"] + args, cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ""


def _git_bytes(args: list[str], cwd: Path, timeout: int = 120) -> bytes:
    try:
        proc = subprocess.run(
            ["git"] + args, cwd=str(cwd), capture_output=True, timeout=timeout,
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        return b""


def walk_repository(repo_dir: Path, commits: list, dangling_commits: list[str],
                    dangling_blobs: list[str]) -> list[Finding]:
    """Aggregate findings across the working tree, all commits' diffs,
    and dangling git objects."""
    out: list[Finding] = []

    # 1. Current working tree files
    for f in _git(["ls-files"], repo_dir).splitlines():
        f = f.strip()
        if not f:
            continue
        p = repo_dir / f
        if p.is_file() and p.stat().st_size < 2_000_000:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            out.extend(scan_text(text, file_path=f, source="working-tree"))

    # 2. Every commit's diff (focus on -/+ lines to catch removed secrets)
    seen_commits: set[str] = set()
    for c in commits:
        sha = c.sha
        if sha in seen_commits:
            continue
        seen_commits.add(sha)
        diff = _git(["show", "--no-color", "--unified=0", sha], repo_dir, timeout=60)
        if not diff:
            continue
        # Track current "+++ b/path" so each finding has a path
        current_file = f"commit:{sha[:12]}"
        diff_lines: list[str] = []
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                # Flush previous file
                if diff_lines:
                    out.extend(scan_text("\n".join(diff_lines),
                                          file_path=current_file, commit_sha=sha,
                                          source="diff"))
                    diff_lines = []
                current_file = line[6:]
            elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                diff_lines.append(line[1:])
        if diff_lines:
            out.extend(scan_text("\n".join(diff_lines), file_path=current_file,
                                  commit_sha=sha, source="diff"))

    # 3. Dangling blobs (might contain raw secrets)
    for blob_sha in dangling_blobs:
        raw = _git_bytes(["cat-file", "-p", blob_sha], repo_dir)
        if not raw or len(raw) > 2_000_000:
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue
        out.extend(scan_text(text, file_path=f"dangling-blob:{blob_sha[:12]}",
                              source="dangling"))

    # 4. Dangling commits
    for c_sha in dangling_commits:
        diff = _git(["show", "--no-color", "--unified=0", c_sha], repo_dir, timeout=60)
        if diff:
            out.extend(scan_text(diff, file_path=f"dangling-commit:{c_sha[:12]}",
                                  commit_sha=c_sha, source="dangling"))

    return dedupe(out)
