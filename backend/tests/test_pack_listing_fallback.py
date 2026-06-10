"""Regression test: discover pack files via Apache mod_autoindex listing
when /.git/objects/info/packs returns 404.

This was the critical bug discovered during the Stage 1 live demo against
the Web Security Academy "Git Directory Exposure" lab — the target's Apache
served `.git/objects/pack/` as a directory listing but did NOT serve the
`objects/info/packs` index file. Without the listing fallback the BFS
fetched 0 objects.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from gitvulture.core.object_engine import ObjectEngine


def _resp(status: int, content: bytes):
    r = MagicMock()
    r.ok = 200 <= status < 300
    r.content = content
    r.status_code = status
    return r


def _mk_engine(tmp_path: Path, responses: dict[str, bytes | None]):
    """`responses` maps relative path → bytes (None means 404)."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True)
    (git_dir / "objects" / "pack").mkdir(parents=True)

    client = MagicMock()
    async def fetch_path(p: str):
        body = responses.get(p)
        if body is None:
            return _resp(404, b"")
        return _resp(200, body)
    client.fetch_path = AsyncMock(side_effect=fetch_path)
    return ObjectEngine(client, git_dir), client


_APACHE_LISTING_HTML = b"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /.git/objects/pack</title></head><body>
<h1>Index of /.git/objects/pack</h1><table>
<tr><th>Name</th></tr>
<tr><td><a href="pack-880f92a73e8f86c6515c89ea7e774ac7c8d48985.idx">pack-880f92a73e8f86c6515c89ea7e774ac7c8d48985.idx</a></td></tr>
<tr><td><a href="pack-880f92a73e8f86c6515c89ea7e774ac7c8d48985.pack">pack-880f92a73e8f86c6515c89ea7e774ac7c8d48985.pack</a></td></tr>
</table></body></html>
"""

_NGINX_LISTING_HTML = b"""<html><head><title>Index of /.git/objects/pack/</title></head>
<body><h1>Index of /.git/objects/pack/</h1><hr><pre>
<a href="../">../</a>
<a href="pack-deadbeefcafebabe1234567890abcdef12345678.idx">pack-deadbeefcafebabe1234567890abcdef12345678.idx</a>
<a href="pack-deadbeefcafebabe1234567890abcdef12345678.pack">pack-deadbeefcafebabe1234567890abcdef12345678.pack</a>
</pre><hr></body></html>
"""


def test_pack_discovery_via_apache_autoindex(tmp_path):
    """When info/packs 404s, fall back to scraping the directory listing."""
    sha = "880f92a73e8f86c6515c89ea7e774ac7c8d48985"
    # Fake idx body — invalid but enough to test discovery; parser will
    # raise but the discovery itself succeeds.
    fake_idx = b"\xff\x74\x4f\x63" + b"\x00\x00\x00\x02"  # v2 magic
    fake_pack = b"PACK" + b"\x00\x00\x00\x02" + b"\x00\x00\x00\x01"
    responses: dict[str, bytes | None] = {
        # info/packs missing
        "objects/info/packs": None,
        # listing HTML available
        "objects/pack/": _APACHE_LISTING_HTML,
        # idx + pack retrievable
        f"objects/pack/pack-{sha}.idx": fake_idx,
        f"objects/pack/pack-{sha}.pack": fake_pack,
    }
    engine, _client = _mk_engine(tmp_path, responses)

    packs, shas = asyncio.run(engine.fetch_packs())

    assert packs == [f"pack-{sha}.pack"], "pack name not discovered from listing"
    # idx parse will fail (it's a stub), but the pack should have been written
    assert (tmp_path / ".git" / "objects" / "pack" / f"pack-{sha}.pack").exists()


def test_pack_discovery_works_with_nginx_listing(tmp_path):
    """nginx <pre>-based listings should also work."""
    sha = "deadbeefcafebabe1234567890abcdef12345678"
    fake_idx = b"\xff\x74\x4f\x63\x00\x00\x00\x02"
    fake_pack = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00"
    responses: dict[str, bytes | None] = {
        "objects/info/packs": None,
        "objects/pack/": _NGINX_LISTING_HTML,
        f"objects/pack/pack-{sha}.idx": fake_idx,
        f"objects/pack/pack-{sha}.pack": fake_pack,
    }
    engine, _client = _mk_engine(tmp_path, responses)
    packs, _ = asyncio.run(engine.fetch_packs())
    assert packs == [f"pack-{sha}.pack"]


def test_official_index_still_wins_over_listing(tmp_path):
    """If info/packs is present, use that — don't double-up via listing."""
    sha = "1111111111111111111111111111111111111111"
    responses: dict[str, bytes | None] = {
        "objects/info/packs": f"P pack-{sha}.pack\n".encode(),
        # Listing offers a different pack — should NOT be merged in
        "objects/pack/": _APACHE_LISTING_HTML,
        f"objects/pack/pack-{sha}.idx": b"\xff\x74\x4f\x63\x00\x00\x00\x02",
        f"objects/pack/pack-{sha}.pack": b"PACK\x00\x00\x00\x02\x00\x00\x00\x00",
    }
    engine, _client = _mk_engine(tmp_path, responses)
    packs, _ = asyncio.run(engine.fetch_packs())
    # Only the index-declared pack is fetched
    assert packs == [f"pack-{sha}.pack"]


def test_no_pack_when_listing_disabled(tmp_path):
    """Both info/packs AND listing return 404 → discover nothing (no crash)."""
    responses: dict[str, bytes | None] = {
        # Everything 404s
    }
    engine, _client = _mk_engine(tmp_path, responses)
    packs, shas = asyncio.run(engine.fetch_packs())
    assert packs == []
    assert shas == []
