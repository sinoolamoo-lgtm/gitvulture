"""Hybrid object acquisition engine: pack files + loose objects + BFS traversal.

Strategy
--------
1. **Pack engine**: download `objects/info/packs`, parse the list of `pack-*.pack`
   names, fetch their `.idx` files, stream-parse the index to extract every
   object SHA inside that pack, then download the `.pack` itself.
2. **Loose engine**: for each known SHA, download `objects/xx/yyyy...` (where
   xx = first 2 chars of sha, yyyy = remaining 38 chars).
3. **BFS walker**: after writing objects to disk we can use git itself (via
   dulwich) to parse a commit and discover all referenced trees/blobs/parents,
   which yields new SHAs to download. Repeat until convergence.
"""
from __future__ import annotations

import asyncio
import os
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from .http_client import FetchResult, HttpClient
from ..logger import get_logger

_PACK_LINE = re.compile(rb"^P\s+(pack-[0-9a-f]{40}\.pack)\s*$", re.MULTILINE)
_PACK_NAME = re.compile(rb"pack-([0-9a-f]{40})\.pack")


@dataclass
class AcquisitionStats:
    pack_count: int = 0
    pack_objects: int = 0
    loose_objects: int = 0
    failed: int = 0
    discovered_new: int = 0
    notes: list[str] = field(default_factory=list)


class ObjectEngine:
    def __init__(self, client: HttpClient, git_dir: Path, log=None):
        self.client = client
        self.git_dir = git_dir
        self.objects_dir = git_dir / "objects"
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self._log = log or (lambda *a, **kw: None)
        self.log = get_logger()
        self._packed_shas: set[str] = set()  # SHAs known to live in a pack file

    # ------------------------------------------------------------------ #
    # Pack engine
    # ------------------------------------------------------------------ #
    async def fetch_packs(self) -> tuple[list[str], list[str]]:
        """Return (downloaded_pack_names, parsed_object_shas)."""
        idx_packs: list[str] = []
        all_object_shas: list[str] = []

        # Strategy 1: read the official index file
        r = await self.client.fetch_path("objects/info/packs")
        if r.ok and r.content:
            for m in _PACK_LINE.finditer(r.content):
                idx_packs.append(m.group(1).decode())
            # Fallback: any pack-<sha>.pack mentions
            for m in _PACK_NAME.finditer(r.content):
                pn = f"pack-{m.group(1).decode()}.pack"
                if pn not in idx_packs:
                    idx_packs.append(pn)

        for pack_name in idx_packs:
            sha = pack_name.replace("pack-", "").replace(".pack", "")
            idx_path = f"objects/pack/pack-{sha}.idx"
            pack_path = f"objects/pack/pack-{sha}.pack"
            idx_res = await self.client.fetch_path(idx_path)
            pack_res = await self.client.fetch_path(pack_path)
            if idx_res.ok:
                local_idx = self.objects_dir / "pack" / f"pack-{sha}.idx"
                local_idx.parent.mkdir(parents=True, exist_ok=True)
                local_idx.write_bytes(idx_res.content)
                try:
                    shas = parse_idx_v2(idx_res.content)
                    all_object_shas.extend(shas)
                    self._packed_shas.update(shas)
                    self.log.success(
                        f"pack idx  pack-{sha[:10]}…  →  {len(shas)} object SHAs"
                    )
                    self._log(f"[pack] {sha[:8]} -> {len(shas)} objects")
                except Exception as e:
                    self.log.warning(f"pack idx parse failed for {sha[:10]}: {e}")
            if pack_res.ok:
                local_pack = self.objects_dir / "pack" / f"pack-{sha}.pack"
                local_pack.parent.mkdir(parents=True, exist_ok=True)
                local_pack.write_bytes(pack_res.content)
                self.log.success(
                    f"pack data pack-{sha[:10]}…  →  {len(pack_res.content)}B"
                )

        return idx_packs, all_object_shas

    # ------------------------------------------------------------------ #
    # Loose engine
    # ------------------------------------------------------------------ #
    async def fetch_loose(self, shas: set[str]) -> AcquisitionStats:
        stats = AcquisitionStats()
        # Already-on-disk shas are skipped; SHAs known to live in a pack
        # cannot be retrieved as loose — skip them too to avoid 404 storms.
        to_fetch = [
            s for s in shas
            if not self._object_path(s).exists() and s not in self._packed_shas
        ]
        if not to_fetch:
            return stats
        self.log.info(f"downloading {len(to_fetch)} loose object(s)")
        self._log(f"[loose] fetching {len(to_fetch)} new objects")

        async def one(sha: str) -> tuple[str, FetchResult]:
            path = f"objects/{sha[:2]}/{sha[2:]}"
            return sha, await self.client.fetch_path(path)

        # Chunk to avoid spawning thousands of tasks at once
        CHUNK = 100
        for i in range(0, len(to_fetch), CHUNK):
            chunk = to_fetch[i : i + CHUNK]
            results = await asyncio.gather(*(one(s) for s in chunk))
            for sha, r in results:
                if r.ok and self._looks_like_object(r.content):
                    p = self._object_path(sha)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(r.content)
                    stats.loose_objects += 1
                    self.log.stats["objects"] = self.log.stats.get("objects", 0) + 1
                    self.log.trace(f"object  {sha[:10]}…  saved ({len(r.content)}B)")
                else:
                    stats.failed += 1
        self.log.success(
            f"loose batch:  {stats.loose_objects} saved, {stats.failed} failed"
        )
        return stats

    # ------------------------------------------------------------------ #
    # BFS walker (uses dulwich to parse stored objects and find more SHAs)
    # ------------------------------------------------------------------ #
    async def bfs_expand(self, seed: set[str], max_rounds: int = 8) -> set[str]:
        """From a set of known SHAs, repeatedly download and parse objects
        to discover new referenced SHAs (parents, trees, blobs). Returns all
        SHAs discovered/downloaded along the way."""
        discovered: set[str] = set(seed)
        frontier: set[str] = set(seed)
        self.log.info(f"BFS object walk: {len(seed)} seed sha(s), max {max_rounds} rounds")

        for rnd in range(max_rounds):
            await self.fetch_loose(frontier)
            new_shas = self._extract_shas_from_local(frontier)
            new = new_shas - discovered
            self.log.debug(f"BFS round {rnd+1}: +{len(new)} new sha references")
            if not new:
                break
            discovered.update(new)
            frontier = new
        self.log.success(f"BFS converged: {len(discovered)} total objects known")
        return discovered

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _object_path(self, sha: str) -> Path:
        return self.objects_dir / sha[:2] / sha[2:]

    @staticmethod
    def _looks_like_object(data: bytes) -> bool:
        # Loose objects are zlib-deflated; first byte is usually 0x78
        if not data or len(data) < 4:
            return False
        try:
            head = zlib.decompress(data, bufsize=64)
            return head[:6] in (b"commit", b"tree\x20", b"blob\x20", b"tag\x20\x20") or \
                head.startswith((b"commit ", b"tree ", b"blob ", b"tag "))
        except Exception:
            return False

    def _extract_shas_from_local(self, sha_list: set[str]) -> set[str]:
        """Parse already-downloaded loose objects and collect referenced SHAs."""
        found: set[str] = set()
        sha_re = re.compile(rb"\b[0-9a-f]{40}\b")
        for sha in sha_list:
            p = self._object_path(sha)
            if not p.exists():
                continue
            try:
                raw = zlib.decompress(p.read_bytes())
            except Exception:
                continue
            # commit/tag objects expose parents/trees in plaintext
            if raw.startswith(b"commit ") or raw.startswith(b"tag "):
                for m in sha_re.findall(raw):
                    found.add(m.decode())
            elif raw.startswith(b"tree "):
                # Tree entries are binary: "<mode> <name>\0<20-byte-sha>"
                _, _, body = raw.partition(b"\x00")
                idx = 0
                while idx < len(body):
                    nul = body.find(b"\x00", idx)
                    if nul < 0 or nul + 20 >= len(body):
                        break
                    sha_bin = body[nul + 1 : nul + 21]
                    if len(sha_bin) == 20:
                        found.add(sha_bin.hex())
                    idx = nul + 21
        return found


# ---------------------------------------------------------------------- #
# pack index v2 streaming parser
# ---------------------------------------------------------------------- #
def parse_idx_v2(data: bytes) -> list[str]:
    """Parse a pack-*.idx (v2) file and return the list of object SHA1 hex strings.

    Format (v2):
        4 bytes magic = 0xff744f63
        4 bytes version = 2
        256 * 4 bytes fanout table
        N * 20 bytes object names (sha1)
        N * 4 bytes crc32
        N * 4 bytes offsets
        ...
    Where N = fanout[255].
    """
    if len(data) < 8 or data[0:4] != b"\xfft" + b"Oc":
        # Could be v1 -- fall back
        return _parse_idx_v1(data)
    if struct.unpack(">I", data[4:8])[0] != 2:
        return _parse_idx_v1(data)

    fanout = struct.unpack(">256I", data[8 : 8 + 256 * 4])
    n = fanout[255]
    names_start = 8 + 256 * 4
    out: list[str] = []
    for i in range(n):
        s = data[names_start + i * 20 : names_start + (i + 1) * 20]
        if len(s) == 20:
            out.append(s.hex())
    return out


def _parse_idx_v1(data: bytes) -> list[str]:
    """Pack idx v1: 256*4 fanout, then N * (4 bytes offset + 20 bytes sha)."""
    try:
        fanout = struct.unpack(">256I", data[0 : 256 * 4])
        n = fanout[255]
        out = []
        start = 256 * 4
        for i in range(n):
            entry = data[start + i * 24 : start + (i + 1) * 24]
            if len(entry) == 24:
                out.append(entry[4:24].hex())
        return out
    except Exception:
        return []
