"""D2 — origin discovery to defeat CDN/WAF (spec §6.3, D2).

Discovers the real origin IP of a target hidden behind a CDN (Cloudflare,
Akamai, ...) by enumerating:

1. **crt.sh** — every certificate ever issued for the target hostname.
   Cert SANs frequently include staging/dev hostnames pointing at the
   real origin.

2. **DNS history** (basic) — A records via the local resolver, hostname
   permutations (`origin.X`, `direct.X`, `internal.X`, `dev.X`, ...).

3. **Same-app verification** — before treating an IP as the real origin,
   compute SimHash(GET /) on the authorized host and require ≥ 0.85
   similarity with GET / on the candidate IP. This is the hard precheck
   from review refinement #3.

If a candidate passes the SimHash check it is added to the ScopeGuard's
`authorized_hosts` via the public extension API.

Strictly read-only. No DNS-rebinding shenanigans, no port scanning.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import httpx


@dataclass
class OriginCandidate:
    host: str
    port: int = 443
    scheme: str = "https"
    source: str = ""             # "crt.sh" / "permutation" / "cert-san" / ...
    similarity: Optional[float] = None
    verified: bool = False


@dataclass
class OriginDiscoveryReport:
    target_hostname: str
    candidates: list[OriginCandidate] = field(default_factory=list)
    verified: list[OriginCandidate] = field(default_factory=list)


# ---------------------------------------------------------------------------
# crt.sh fetch
# ---------------------------------------------------------------------------
_CRT_TIMEOUT = 15


async def fetch_crt_sh_names(hostname: str) -> set[str]:
    """Return all DNS names ever issued for `hostname` via crt.sh.

    crt.sh provides a JSON endpoint that returns every cert touching the
    requested CN/SAN. We parse the `name_value` field which is a newline-
    delimited list of names.
    """
    url = f"https://crt.sh/?q=%25.{hostname}&output=json"
    out: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=_CRT_TIMEOUT, http2=True) as client:
            resp = await client.get(url, headers={
                "User-Agent": "gitvulture/2.0 (D2-origin-discovery)",
            })
            if resp.status_code != 200:
                return out
            data = resp.json() if resp.content else []
    except Exception:
        return out

    for entry in data:
        name_value = entry.get("name_value", "")
        for line in name_value.split("\n"):
            line = line.strip().lower()
            # crt.sh sometimes prefixes wildcards with `*.`
            if line.startswith("*."):
                line = line[2:]
            if line and "*" not in line:
                out.add(line)
    return out


# ---------------------------------------------------------------------------
# Permutation generator
# ---------------------------------------------------------------------------
_PERMUTATION_PREFIXES = [
    "origin", "direct", "real", "true", "internal", "intern",
    "dev", "development", "stage", "staging", "qa", "test",
    "beta", "alpha", "preview", "demo", "sandbox",
    "old", "legacy", "backup", "bk", "new",
    "admin", "mgmt", "console", "panel",
    "api", "api-dev", "api-stage", "ws", "websocket",
    "cdn", "static", "assets", "media",
    "mail", "smtp", "ftp",
]


def generate_permutations(hostname: str) -> set[str]:
    """`api.target.tld` → `origin.api.target.tld`, `dev.api.target.tld`, ..."""
    out: set[str] = set()
    parts = hostname.split(".")
    if len(parts) < 2:
        return out
    # Replace the leftmost label
    base = ".".join(parts[1:]) if len(parts) > 2 else hostname
    for prefix in _PERMUTATION_PREFIXES:
        out.add(f"{prefix}.{base}")
        out.add(f"{prefix}.{hostname}")
    return out


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------
def _resolve_one(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        return list({i[4][0] for i in infos})
    except (socket.gaierror, OSError):
        return []


async def resolve_batch(hosts: set[str], concurrency: int = 50) -> dict[str, list[str]]:
    """Resolve N hostnames concurrently (synchronous resolver in threadpool)."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(h: str):
        async with sem:
            return h, await asyncio.to_thread(_resolve_one, h)

    results = await asyncio.gather(*(_one(h) for h in hosts))
    return {h: ips for h, ips in results if ips}


# ---------------------------------------------------------------------------
# SimHash same-app verification
# ---------------------------------------------------------------------------
def _simhash(text: str, n: int = 64) -> int:
    """Tiny 64-bit SimHash implementation (token shingles)."""
    import hashlib
    if not text:
        return 0
    tokens = text.lower().split()
    if not tokens:
        return 0
    v = [0] * n
    for tok in tokens:
        h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
        for i in range(n):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(n):
        if v[i] > 0:
            fp |= 1 << i
    return fp


def _simhash_similarity(a: int, b: int, n: int = 64) -> float:
    diff = bin(a ^ b).count("1")
    return 1.0 - (diff / n)


async def _fetch_root(url: str, *, host_header: Optional[str] = None) -> Optional[str]:
    """GET / against a URL, returning the body or None.

    Bypasses cert validation (we're hitting raw IPs whose certs won't match).
    """
    try:
        async with httpx.AsyncClient(
            timeout=10, verify=False, http2=True, follow_redirects=False,
        ) as client:
            headers = {"User-Agent": "gitvulture/2.0"}
            if host_header:
                headers["Host"] = host_header
            resp = await client.get(url, headers=headers)
            return resp.text[:50_000]  # cap
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------
async def discover_origins(
    target_url: str,
    log=None,
    enable_crt_sh: bool = True,
    enable_permutations: bool = True,
    similarity_threshold: float = 0.85,
) -> OriginDiscoveryReport:
    """Discover real-origin IP candidates for the target.

    Returns a report; verified candidates have `verified=True` and may be
    fed to `ScopeGuard.contract.add_host()` by the orchestrator.
    """
    parsed = urlsplit(target_url)
    target_host = (parsed.hostname or "").lower()
    target_scheme = parsed.scheme or "https"
    target_port = parsed.port or (443 if target_scheme == "https" else 80)

    report = OriginDiscoveryReport(target_hostname=target_host)
    if not target_host:
        return report

    if log:
        log.phase(f"PHASE D2 ::  ORIGIN DISCOVERY for {target_host}")

    # 1. Establish baseline: GET / on the authorized host
    baseline_body = await _fetch_root(target_url)
    if not baseline_body:
        if log:
            log.warn("D2: baseline GET / failed — cannot SimHash-verify candidates")
        return report
    baseline_hash = _simhash(baseline_body)

    # 2. Gather candidate hostnames
    candidates: set[str] = set()
    if enable_crt_sh:
        try:
            names = await fetch_crt_sh_names(target_host)
            if log:
                log.info(f"D2 crt.sh: {len(names)} SAN/CN names harvested")
            candidates.update(names)
        except Exception as e:
            if log:
                log.warn(f"D2 crt.sh failed: {e}")
    if enable_permutations:
        candidates.update(generate_permutations(target_host))

    # Drop the original hostname itself
    candidates.discard(target_host)

    if not candidates:
        return report

    # 3. Resolve to IPs (we keep both A records AND the hostname for SNI)
    resolved = await resolve_batch(candidates)
    if log:
        log.info(f"D2: {len(resolved)} hostnames resolved (out of {len(candidates)})")

    # 4. For each unique IP, do SimHash check using the original Host header
    seen_ips: set[str] = set()
    sem = asyncio.Semaphore(20)

    async def _check_ip(host: str, ip: str):
        async with sem:
            if ip in seen_ips:
                return None
            seen_ips.add(ip)
            url = f"{target_scheme}://{ip}:{target_port}/"
            body = await _fetch_root(url, host_header=target_host)
            if not body:
                return None
            sim = _simhash_similarity(baseline_hash, _simhash(body))
            return OriginCandidate(
                host=ip, port=target_port, scheme=target_scheme,
                source=f"resolved-from:{host}",
                similarity=sim,
                verified=sim >= similarity_threshold,
            )

    checks = []
    for host, ips in resolved.items():
        for ip in ips:
            checks.append(_check_ip(host, ip))
    results = await asyncio.gather(*checks)
    report.candidates = [c for c in results if c is not None]
    report.verified = [c for c in report.candidates if c.verified]

    if log:
        log.success(
            f"D2: {len(report.verified)} verified origin candidate(s) "
            f"out of {len(report.candidates)} probed IPs"
        )
        for c in report.verified[:5]:
            log.info(f"  - {c.host}:{c.port}  similarity={c.similarity:.2f}")
    return report


def write_origin_report(report: OriginDiscoveryReport, output_dir) -> None:
    import json
    from pathlib import Path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "origin-discovery.json").write_text(
        json.dumps({
            "target_hostname": report.target_hostname,
            "candidates": [c.__dict__ for c in report.candidates],
            "verified": [c.__dict__ for c in report.verified],
        }, indent=2),
        encoding="utf-8",
    )
