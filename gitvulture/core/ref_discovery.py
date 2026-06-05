"""Comprehensive reference discovery from 12 sources.

Reads HEAD, packed-refs, info/refs, FETCH_HEAD, ORIG_HEAD, MERGE_HEAD,
logs/HEAD, logs/refs/heads/*, logs/refs/remotes/*, refs/heads/*, refs/tags/*,
refs/remotes/*, refs/stash, config and extracts every SHA-1 it can find.

Extra: reflog mining recovers OLD hashes that are no longer in current history
but whose objects are still present on the server (force-push / rebase artifacts).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..config import COMMON_BRANCHES, REF_PATHS, SHA1_RE
from ..logger import get_logger
from .http_client import HttpClient

_SHA = re.compile(SHA1_RE)
_REF_LINE = re.compile(r"ref:\s+(\S+)")
# packed-refs lines: "<sha> refs/heads/branch"
_PACKED = re.compile(rf"({SHA1_RE})\s+(\S+)")
# config branches/remotes
_CONFIG_BRANCH = re.compile(r'\[branch\s+"([^"]+)"\]')
_CONFIG_REMOTE = re.compile(r'\[remote\s+"([^"]+)"\]')
# reflog lines: "<old> <new> author <ts> <tz>\t<msg>"
_REFLOG = re.compile(rf"({SHA1_RE})\s+({SHA1_RE})")


@dataclass
class RefSet:
    commits: set[str] = field(default_factory=set)   # all SHA-1s found anywhere
    branches: dict[str, str] = field(default_factory=dict)  # ref_name -> sha
    tags: dict[str, str] = field(default_factory=dict)
    stash: dict[str, str] = field(default_factory=dict)
    reflog_old_commits: set[str] = field(default_factory=set)  # ghost commits
    discovered_files: set[str] = field(default_factory=set)
    raw_files: dict[str, bytes] = field(default_factory=dict)

    def absorb_sha(self, sha: str) -> None:
        if sha and len(sha) == 40 and sha != "0" * 40:
            self.commits.add(sha)


async def discover_refs(client: HttpClient) -> RefSet:
    log = get_logger()
    refs = RefSet()

    # Phase A: known files
    static_files = [
        "HEAD", "packed-refs", "info/refs", "info/packs",
        "objects/info/packs", "objects/info/alternates",
        "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD",
        "REVERT_HEAD", "config", "description",
        "logs/HEAD", "refs/stash", "logs/refs/stash",
        "COMMIT_EDITMSG", "index", "info/exclude",
    ]
    log.info(f"fetching {len(static_files)} well-known git metadata files")
    results = await client.fetch_paths(static_files)
    for r in results:
        if r.ok:
            name = r.url.split("/.git/", 1)[-1] or "/"
            refs.discovered_files.add(name)
            refs.raw_files[name] = r.content
            _parse_into(name, r.content, refs)
            log.success(f"recovered  {name}  ({len(r.content)}B)")

    # Phase B: brute-force common branch/tag refs (loose refs)
    candidate_paths: list[str] = []
    branch_pool = list(COMMON_BRANCHES)
    # Add anything we already learned from HEAD / config / packed-refs
    for b in list(refs.branches.keys()):
        for prefix in ("refs/heads/", "refs/remotes/origin/", "refs/tags/"):
            if b.startswith(prefix):
                branch_pool.append(b[len(prefix):])

    seen_paths: set[str] = set()
    for branch in branch_pool:
        for tmpl in REF_PATHS:
            path = tmpl.format(branch=branch)
            if path not in seen_paths:
                seen_paths.add(path)
                candidate_paths.append(path)

    if candidate_paths:
        log.info(f"brute-forcing {len(candidate_paths)} candidate ref paths")
        ref_results = await client.fetch_paths(candidate_paths)
        new_refs = 0
        for r in ref_results:
            if r.ok:
                name = r.url.split("/.git/", 1)[-1]
                refs.discovered_files.add(name)
                refs.raw_files[name] = r.content
                _parse_into(name, r.content, refs)
                new_refs += 1
                log.success(f"discovered ref  {name}")
        log.info(
            f"ref discovery summary: {len(refs.commits)} sha-1s, "
            f"{len(refs.branches)} branches, {len(refs.tags)} tags, "
            f"{len(refs.reflog_old_commits)} reflog ghosts"
        )

    return refs


def _parse_into(name: str, data: bytes, refs: RefSet) -> None:
    """Parse a single git metadata file and absorb hashes/refs into RefSet."""
    # Binary index file: skip text parsing (will be handled by index_parser)
    if name == "index" or name.endswith(".pack") or name.endswith(".idx"):
        return
    text = data.decode("utf-8", errors="replace")

    # All SHA-1s anywhere become candidate commits/objects
    for m in _SHA.findall(text):
        refs.absorb_sha(m)

    # HEAD-like files: "ref: refs/heads/X" or raw SHA
    m = _REF_LINE.search(text)
    if m:
        target = m.group(1)
        # If we already learned the SHA of that target via packed-refs, link it
        if target in refs.branches:
            pass

    # packed-refs: many SHA <ref> pairs
    if name.endswith("packed-refs"):
        for sha, ref in _PACKED.findall(text):
            if ref.startswith("refs/heads/") or ref.startswith("refs/remotes/"):
                refs.branches[ref] = sha
            elif ref.startswith("refs/tags/"):
                refs.tags[ref] = sha
            elif ref.startswith("refs/stash"):
                refs.stash[ref] = sha
            refs.absorb_sha(sha)

    # Loose ref file: refs/heads/X => content is a single SHA
    if name.startswith("refs/heads/") or name.startswith("refs/remotes/"):
        for m in _SHA.findall(text):
            refs.branches[name] = m
            break
    if name.startswith("refs/tags/"):
        for m in _SHA.findall(text):
            refs.tags[name] = m
            break
    if name.startswith("refs/stash") or name.endswith("stash"):
        for m in _SHA.findall(text):
            refs.stash[name] = m
            break

    # reflog files: capture BOTH old and new hashes
    if "logs/" in name:
        for old, new in _REFLOG.findall(text):
            if old != "0" * 40:
                refs.reflog_old_commits.add(old)
            refs.absorb_sha(new)

    # config: discover branch names + remote URLs to enrich the brute-force list
    if name == "config":
        for branch_name in _CONFIG_BRANCH.findall(text):
            refs.branches.setdefault(f"refs/heads/{branch_name}", "")
        # remotes are noted but not actionable for download
        _ = _CONFIG_REMOTE.findall(text)
