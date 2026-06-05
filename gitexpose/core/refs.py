"""Ref discovery: HEAD, packed-refs, refs/{heads,tags,remotes}, reflog."""
from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..logger import get_logger
from ..settings import COMMON_BRANCHES, COMMON_REMOTES, COMMON_TAGS

SHA1_RE = re.compile(rb"\b[0-9a-f]{40}\b")
REF_RE = re.compile(rb"ref:\s*(refs/\S+)")
PACKED_LINE_RE = re.compile(rb"^([0-9a-f]{40})\s+(refs/\S+)\s*$", re.M)
INFO_REFS_LINE_RE = re.compile(rb"^([0-9a-f]{40})\s+(refs/\S+)\s*$", re.M)
REFLOG_LINE_RE = re.compile(
    rb"^([0-9a-f]{40})\s+([0-9a-f]{40})\s", re.M
)


async def fetch_text(client: HttpClient, url: str) -> bytes:
    r = await client.get(url)
    return r.body if r.ok else b""


async def discover_refs(client: HttpClient, git_root: str) -> dict[str, str]:
    """Return mapping {ref_path: sha} discovered from multiple sources."""
    log = get_logger()
    refs: dict[str, str] = {}

    # 1) HEAD
    head = await fetch_text(client, urljoin(git_root, "HEAD"))
    if head:
        m = REF_RE.search(head)
        if m:
            refs.setdefault("HEAD->", m.group(1).decode())
            log.debug(f"HEAD points to {m.group(1).decode()}")
        else:
            m2 = SHA1_RE.search(head)
            if m2:
                refs["HEAD"] = m2.group(0).decode()

    # 2) packed-refs
    packed = await fetch_text(client, urljoin(git_root, "packed-refs"))
    if packed:
        for m in PACKED_LINE_RE.finditer(packed):
            sha, ref = m.group(1).decode(), m.group(2).decode()
            refs[ref] = sha
        log.debug(f"packed-refs: {sum(1 for _ in PACKED_LINE_RE.finditer(packed))} refs")

    # 3) info/refs (smart-HTTP fallback)
    info = await fetch_text(client, urljoin(git_root, "info/refs"))
    if info:
        for m in INFO_REFS_LINE_RE.finditer(info):
            sha, ref = m.group(1).decode(), m.group(2).decode()
            refs[ref] = sha
        log.debug(f"info/refs added {sum(1 for _ in INFO_REFS_LINE_RE.finditer(info))} refs")

    # 4) Special refs (FETCH_HEAD/ORIG_HEAD/MERGE_HEAD/COMMIT_EDITMSG)
    for name in ("ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD"):
        body = await fetch_text(client, urljoin(git_root, name))
        if body:
            m = SHA1_RE.search(body)
            if m:
                refs[name] = m.group(0).decode()

    # 5) Brute-force common branches/tags when listing is disabled
    candidates = (
        [f"refs/heads/{b}" for b in COMMON_BRANCHES]
        + [f"refs/tags/{t}" for t in COMMON_TAGS]
        + [
            f"refs/remotes/{r}/{b}"
            for r in COMMON_REMOTES
            for b in COMMON_BRANCHES[:6]
        ]
        + ["refs/stash"]
    )
    for ref in candidates:
        if ref in refs:
            continue
        body = await fetch_text(client, urljoin(git_root, ref))
        if body:
            m = SHA1_RE.search(body)
            if m:
                refs[ref] = m.group(0).decode()
                log.debug(f"discovered ref {ref}")

    # 6) reflog (logs/HEAD + logs/refs/...)
    reflog = await fetch_text(client, urljoin(git_root, "logs/HEAD"))
    if reflog:
        for m in REFLOG_LINE_RE.finditer(reflog):
            refs.setdefault("reflog:HEAD:from", m.group(1).decode())
            refs["reflog:HEAD"] = m.group(2).decode()
        log.debug("parsed logs/HEAD reflog")

    return refs


def shas_from_refs(refs: dict[str, str]) -> set[str]:
    out: set[str] = set()
    for k, v in refs.items():
        if k.endswith("->"):
            continue
        if re.fullmatch(r"[0-9a-f]{40}", v):
            out.add(v)
    return out


def resolve_head_sha(refs: dict[str, str]) -> str | None:
    """Return the SHA pointed to by HEAD, following one indirection."""
    if "HEAD" in refs and re.fullmatch(r"[0-9a-f]{40}", refs["HEAD"]):
        return refs["HEAD"]
    pointer = refs.get("HEAD->")
    if pointer and pointer in refs:
        return refs[pointer]
    # fallback: any branch we know
    for branch in ("refs/heads/main", "refs/heads/master"):
        if branch in refs:
            return refs[branch]
    for k, v in refs.items():
        if k.startswith("refs/heads/"):
            return v
    return None
