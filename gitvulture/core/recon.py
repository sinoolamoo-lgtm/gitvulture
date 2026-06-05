"""Lightweight reconnaissance — verifies .git exposure and profiles the target."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..logger import get_logger
from .http_client import HttpClient

_HEAD_RE = re.compile(rb"^(ref:\s+refs/|[0-9a-f]{40})", re.I)
_CONFIG_MARKERS = (b"[core]", b"repositoryformatversion", b"[remote ", b"[branch ")


@dataclass
class ReconResult:
    exposed: bool = False
    head_ref: Optional[str] = None
    has_dir_listing: bool = False
    server: Optional[str] = None
    waf: Optional[str] = None
    config_text: Optional[str] = None
    description: Optional[str] = None
    detection_method: Optional[str] = None  # head | config | listing | alternates
    notes: list[str] = field(default_factory=list)


async def run_recon(client: HttpClient) -> ReconResult:
    """Probe a handful of well-known .git files to confirm exposure."""
    log = get_logger()
    result = ReconResult()

    log.info(f"probing target  {client.base_url}/.git/  for exposure")

    # 1) HEAD signature
    head_r = await client.fetch_path("HEAD")
    if head_r.ok and _HEAD_RE.match(head_r.content[:64]):
        result.exposed = True
        text = head_r.content.decode("utf-8", errors="replace").strip()
        result.head_ref = text
        result.detection_method = "head"
        result.notes.append(f"HEAD: {text}")
        result.server = head_r.headers.get("server")
        log.success(f"exposed .git/ detected via HEAD  →  {text}")

    # 2) config marker (run anyway — it's informative)
    config_r = await client.fetch_path("config")
    if config_r.ok and any(m in config_r.content for m in _CONFIG_MARKERS):
        try:
            result.config_text = config_r.content.decode("utf-8", errors="replace")
            result.notes.append("config exposed")
            log.success("config file readable")
        except Exception:
            pass
        if not result.exposed:
            result.exposed = True
            result.detection_method = "config"
            log.success("exposed .git/ detected via config marker")

    # 3) description
    desc_r = await client.fetch_path("description")
    if desc_r.ok:
        try:
            result.description = desc_r.content.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

    # 4) directory listing
    listing_r = await client.fetch_path("")
    if listing_r.ok and (b"Index of" in listing_r.content[:1024]
                         or b'<a href="HEAD"' in listing_r.content):
        result.has_dir_listing = True
        result.notes.append("directory listing enabled")
        log.success("directory listing on .git/ is enabled — full mirror possible")
        if not result.exposed:
            result.exposed = True
            result.detection_method = "listing"

    # 5) alternates fallback (some hosts only expose this)
    if not result.exposed:
        alt_r = await client.fetch_path("objects/info/alternates")
        if alt_r.ok and alt_r.content.strip():
            result.exposed = True
            result.detection_method = "alternates"
            result.notes.append("alternates file exposed")
            log.success("exposed via objects/info/alternates")

    result.waf = client.waf
    if result.waf:
        result.notes.append(f"WAF: {result.waf}")

    if not result.exposed:
        log.warning(".git/ does not appear to be exposed at this target")
    else:
        if result.server:
            log.kv("server", result.server)
        if result.waf:
            log.kv("WAF", result.waf)
        if result.detection_method:
            log.kv("detection", result.detection_method)
        log.kv("dir listing", "yes" if result.has_dir_listing else "no")
    return result
