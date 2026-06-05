"""Detect exposed .git/ on target."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..logger import get_logger

HEAD_SIGNATURE_RE = re.compile(rb"^(ref: refs/|[0-9a-f]{40}\b)")
GIT_CONFIG_MARKERS = (b"[core]", b"repositoryformatversion", b"[remote ")


@dataclass
class DetectionResult:
    base_url: str          # e.g. https://target/path/.git/
    method: str            # "head", "config", "indexed", "alternates"
    listing_enabled: bool  # whether autoindex / directory listing is on
    fingerprint: dict


class GitDetector:
    """Critique-driven: most tools only check HEAD. We also check config,
    index, HEAD content sniffing, and listing detection."""

    def __init__(self, client: HttpClient) -> None:
        self.client = client
        self.log = get_logger()

    async def detect(self, base_url: str) -> Optional[DetectionResult]:
        base_url = base_url.rstrip("/") + "/"
        git_root = urljoin(base_url, ".git/")
        self.log.info(f"probing {git_root}")

        # 1) HEAD — fastest definitive check
        head_url = urljoin(git_root, "HEAD")
        r = await self.client.get(head_url)
        if r.ok and HEAD_SIGNATURE_RE.match(r.body[:64]):
            self.log.success(f"exposed .git/ detected via HEAD signature: {git_root}")
            return await self._finalize(git_root, "head", r.body)

        # 2) config — sometimes HEAD is hidden but config is not
        cfg = await self.client.get(urljoin(git_root, "config"))
        if cfg.ok and any(m in cfg.body for m in GIT_CONFIG_MARKERS):
            self.log.success(f"exposed .git/ detected via config: {git_root}")
            return await self._finalize(git_root, "config", cfg.body)

        # 3) Directory listing
        listing = await self.client.get(git_root)
        if listing.ok and b"Index of" in listing.body[:512]:
            self.log.success(f"directory listing enabled: {git_root}")
            return await self._finalize(git_root, "indexed", listing.body, listing=True)

        # 4) alternates (sometimes only this is exposed)
        alt = await self.client.get(urljoin(git_root, "objects/info/alternates"))
        if alt.ok and alt.body.strip():
            self.log.success(f"alternates file exposed: {git_root}")
            return await self._finalize(git_root, "alternates", alt.body)

        self.log.warning(f".git/ not detected at {git_root}")
        return None

    async def _finalize(
        self,
        git_root: str,
        method: str,
        sample: bytes,
        listing: bool = False,
    ) -> DetectionResult:
        # Try to fingerprint git version / server software
        fp: dict = {"method": method}
        # Detect autoindex if we haven't already
        if not listing:
            r = await self.client.get(git_root)
            if r.ok and (b"Index of" in r.body[:512] or b"<a href=\"HEAD\"" in r.body):
                listing = True
                self.log.info("directory listing seems enabled on .git/")
        # Sniff for pack listing
        packs = await self.client.get(urljoin(git_root, "objects/info/packs"))
        if packs.ok:
            fp["packs_index"] = True
            self.log.debug("objects/info/packs available")
        return DetectionResult(
            base_url=git_root,
            method=method,
            listing_enabled=listing,
            fingerprint=fp,
        )
