"""Repository reconstruction: turn a freshly-downloaded .git into a valid repo,
recover dangling commits/blobs and extract the full commit timeline."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Commit:
    sha: str
    parents: list[str]
    author: str
    date: str
    message: str
    files_changed: list[str] = field(default_factory=list)


@dataclass
class RebuildResult:
    repo_dir: Path
    head_branch: Optional[str] = None
    branches: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    commits: list[Commit] = field(default_factory=list)
    dangling_commits: list[str] = field(default_factory=list)
    dangling_blobs: list[str] = field(default_factory=list)
    fsck_errors: list[str] = field(default_factory=list)
    files_on_head: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _run(args: list[str], cwd: Path, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError as e:
        return -1, "", str(e)


def reconstruct(git_dir: Path) -> RebuildResult:
    """Given a populated .git directory, attempt full reconstruction.

    Steps
    -----
    1. `git fsck --full` to check integrity (collect errors, dangling refs)
    2. `git log --all` to enumerate every reachable commit
    3. Try `git checkout` for each branch we know about
    4. Use `git fsck --lost-found` to surface dangling commits/blobs
    """
    repo_dir = git_dir.parent
    result = RebuildResult(repo_dir=repo_dir)

    # 1. fsck integrity report — keep reflog ghosts (the "dangling" goldmine).
    #    --reflogs makes git consider every SHA in .git/logs/* when computing
    #    reachability, so force-pushed / rebased commits show up as dangling
    #    instead of being silently dropped.
    code, out, err = _run(
        ["git", "fsck", "--full", "--reflogs", "--dangling", "--lost-found"],
        repo_dir,
    )
    fsck_output = (out + "\n" + err).strip()
    for line in fsck_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("dangling commit"):
            result.dangling_commits.append(line.split()[-1])
        elif line.startswith("dangling blob"):
            result.dangling_blobs.append(line.split()[-1])
        else:
            result.fsck_errors.append(line)

    # 2. Discover branches and tags actually present
    code, out, _ = _run(["git", "branch", "-a"], repo_dir)
    for line in out.splitlines():
        b = line.strip().lstrip("* ").strip()
        if b and not b.startswith("("):
            result.branches.append(b)

    code, out, _ = _run(["git", "tag"], repo_dir)
    for t in out.splitlines():
        if t.strip():
            result.tags.append(t.strip())

    # 3. HEAD branch
    code, out, _ = _run(["git", "symbolic-ref", "HEAD"], repo_dir)
    if code == 0 and out.strip():
        result.head_branch = out.strip().replace("refs/heads/", "")

    # 4. Enumerate commits across all refs (and dangling)
    fmt = "%H%x1f%P%x1f%an <%ae>%x1f%aI%x1f%s"
    code, out, _ = _run(
        ["git", "log", "--all", "--reflog", f"--pretty=format:{fmt}", "--no-color"],
        repo_dir,
        timeout=120,
    )
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 5:
            sha, parents, author, date, msg = parts
            result.commits.append(
                Commit(
                    sha=sha,
                    parents=parents.split() if parents else [],
                    author=author,
                    date=date,
                    message=msg,
                )
            )

    # Also include dangling commits explicitly
    for sha in list(result.dangling_commits):
        if any(c.sha == sha for c in result.commits):
            continue
        code, out, _ = _run(
            ["git", "show", "--no-patch", f"--pretty=format:{fmt}", sha],
            repo_dir,
        )
        if code == 0 and out.strip():
            parts = out.strip().split("\x1f")
            if len(parts) == 5:
                sha2, parents, author, date, msg = parts
                result.commits.append(
                    Commit(
                        sha=sha2,
                        parents=parents.split() if parents else [],
                        author=author,
                        date=date,
                        message=msg + "  [DANGLING]",
                    )
                )

    # 5. Per-commit file lists (cheap: name-only)
    for c in result.commits:
        _, out, _ = _run(
            ["git", "show", "--name-only", "--pretty=format:", c.sha], repo_dir
        )
        c.files_changed = [f for f in out.splitlines() if f.strip()]

    # 6. Try a worktree checkout of HEAD (best-effort, safe to fail)
    if result.head_branch:
        _run(["git", "checkout", "--force", result.head_branch], repo_dir)
        _, out, _ = _run(["git", "ls-files"], repo_dir)
        result.files_on_head = [f for f in out.splitlines() if f.strip()]
    else:
        _, out, _ = _run(["git", "ls-tree", "-r", "--name-only", "HEAD"], repo_dir)
        result.files_on_head = [f for f in out.splitlines() if f.strip()]

    if result.fsck_errors:
        result.notes.append(f"{len(result.fsck_errors)} fsck errors (objects may be missing)")
    return result


def init_repo(target_dir: Path, git_dir: Path) -> None:
    """Ensure the .git directory is in the right place for git to work."""
    expected_git = target_dir / ".git"
    if expected_git.resolve() != git_dir.resolve():
        if expected_git.exists():
            shutil.rmtree(expected_git, ignore_errors=True)
        shutil.move(str(git_dir), str(expected_git))
    # Initialize if missing core files
    if not (expected_git / "HEAD").exists():
        (expected_git / "HEAD").write_text("ref: refs/heads/master\n")
