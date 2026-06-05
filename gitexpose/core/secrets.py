"""Built-in secret scanner – runs over every recovered blob.

Critique: git-dumper relies on user piping output to `trufflehog`. We bundle
common high-signal patterns and reduce false positives via entropy filtering.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from ..logger import get_logger

# A set of well-known, high-precision secret patterns.
# Each rule: (id, description, regex, optional min entropy of match group)
RULES: list[tuple[str, str, re.Pattern, float]] = [
    ("aws_access_key", "AWS Access Key ID",
     re.compile(rb"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), 0.0),
    ("aws_secret", "AWS Secret Access Key",
     re.compile(rb"(?i)aws(.{0,20})?(secret|sk)[^=]{0,5}=\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"), 4.0),
    ("github_pat", "GitHub Personal Access Token",
     re.compile(rb"\bghp_[A-Za-z0-9]{36}\b"), 0.0),
    ("github_oauth", "GitHub OAuth token",
     re.compile(rb"\bgho_[A-Za-z0-9]{36}\b"), 0.0),
    ("github_app", "GitHub App token",
     re.compile(rb"\b(ghu|ghs)_[A-Za-z0-9]{36}\b"), 0.0),
    ("gitlab_pat", "GitLab Personal Access Token",
     re.compile(rb"\bglpat-[A-Za-z0-9\-_]{20}\b"), 0.0),
    ("slack_token", "Slack token",
     re.compile(rb"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"), 0.0),
    ("slack_webhook", "Slack webhook",
     re.compile(rb"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), 0.0),
    ("google_api_key", "Google API key",
     re.compile(rb"\bAIza[0-9A-Za-z\-_]{35}\b"), 0.0),
    ("google_oauth", "Google OAuth Client",
     re.compile(rb"[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com"), 0.0),
    ("stripe_secret", "Stripe Secret Key",
     re.compile(rb"\bsk_live_[A-Za-z0-9]{24,}\b"), 0.0),
    ("stripe_restricted", "Stripe Restricted Key",
     re.compile(rb"\brk_live_[A-Za-z0-9]{24,}\b"), 0.0),
    ("twilio", "Twilio Account SID",
     re.compile(rb"\bAC[a-z0-9]{32}\b"), 0.0),
    ("sendgrid", "SendGrid API key",
     re.compile(rb"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), 0.0),
    ("heroku", "Heroku API key",
     re.compile(rb"(?i)heroku[^=]{0,20}=\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"), 0.0),
    ("jwt", "JSON Web Token",
     re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), 0.0),
    ("private_key", "PEM Private Key",
     re.compile(rb"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP|ENCRYPTED)? ?PRIVATE KEY-----"), 0.0),
    ("generic_password", "Generic password assignment",
     re.compile(rb"(?i)(password|passwd|pwd)\s*[=:]\s*[\"']([^\s\"']{8,})[\"']"), 3.5),
    ("generic_apikey", "Generic API key assignment",
     re.compile(rb"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*[\"']([^\s\"']{16,})[\"']"), 3.5),
    ("npm_token", "NPM token",
     re.compile(rb"\bnpm_[A-Za-z0-9]{36}\b"), 0.0),
    ("mongodb_uri", "MongoDB connection string with credentials",
     re.compile(rb"mongodb(\+srv)?://[^\s:@]+:[^\s:@]+@[^\s/]+"), 0.0),
    ("postgres_uri", "Postgres connection string with credentials",
     re.compile(rb"postgres(ql)?://[^\s:@]+:[^\s:@]+@[^\s/]+"), 0.0),
    ("mysql_uri", "MySQL connection string with credentials",
     re.compile(rb"mysql://[^\s:@]+:[^\s:@]+@[^\s/]+"), 0.0),
    ("redis_uri", "Redis URL with credentials",
     re.compile(rb"redis://[^\s:@]+:[^\s:@]+@[^\s/]+"), 0.0),
]


@dataclass
class SecretHit:
    rule_id: str
    description: str
    file: str
    line: int
    match: str  # truncated
    entropy: float


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def scan_bytes(data: bytes, source: str) -> Iterator[SecretHit]:
    """Yield SecretHit for every match in `data`."""
    # Pre-compute line offsets for line numbers
    lines_offsets = [0]
    for i, b in enumerate(data):
        if b == 0x0A:
            lines_offsets.append(i + 1)

    def line_of(offset: int) -> int:
        # Binary search
        lo, hi = 0, len(lines_offsets) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            if lines_offsets[mid] <= offset:
                lo = mid + 1
            else:
                hi = mid - 1
        return hi + 1

    for rule_id, desc, regex, min_entropy in RULES:
        for m in regex.finditer(data):
            # Pick the highest-index group (the secret itself if captured)
            groups = m.groups()
            captured = groups[-1] if groups and groups[-1] else m.group(0)
            ent = shannon_entropy(captured)
            if min_entropy and ent < min_entropy:
                continue
            text = captured.decode("utf-8", "replace")
            text = (text[:80] + "…") if len(text) > 80 else text
            yield SecretHit(
                rule_id=rule_id,
                description=desc,
                file=source,
                line=line_of(m.start()),
                match=text,
                entropy=round(ent, 2),
            )


def scan_directory(root: Path, ignore: Iterable[str] = (".git",)) -> list[SecretHit]:
    """Scan every regular file under root."""
    log = get_logger()
    hits: list[SecretHit] = []
    ignored = set(ignore)
    files_scanned = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in ignored for part in path.relative_to(root).parts):
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        # skip massive binaries
        if len(data) > 4 * 1024 * 1024:
            continue
        for hit in scan_bytes(data, str(path.relative_to(root))):
            hits.append(hit)
            log.success(
                f"[bold red]SECRET[/bold red] {hit.rule_id} in {hit.file}:{hit.line} "
                f"→ {hit.match}"
            )
        files_scanned += 1
    log.info(f"secret scan: {files_scanned} files, {len(hits)} hits")
    return hits
