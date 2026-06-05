"""Secret scanning engine.

Combines the **best of Gitleaks** (regex + entropy) with **TruffleHog-style**
identity/verification logic (opt-in only).

We do NOT vendor either tool's binary. Instead we ship a curated regex DB that
covers the highest-signal patterns from both projects (AWS keys, GitHub PATs,
Stripe, Slack, JWT, generic password assignments, .env files, SSH keys, etc.)
without duplication.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# (id, severity, description, compiled regex, requires_keyword)
SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern, bool]] = []


def _add(rid: str, severity: str, desc: str, pattern: str, requires_keyword: bool = False):
    SECRET_PATTERNS.append((rid, severity, desc, re.compile(pattern), requires_keyword))


# --- High-confidence cloud keys ---------------------------------------- #
_add("aws-access-key-id", "critical", "AWS Access Key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
_add(
    "aws-secret-access-key",
    "critical",
    "AWS Secret Access Key",
    r"(?i)aws_?(?:secret|key)?[_ -]?access[_ -]?key[\"' :=]+\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
    True,
)
_add("gcp-api-key", "high", "Google API Key", r"\bAIza[0-9A-Za-z\-_]{35}\b")
_add("gcp-oauth", "high", "Google OAuth Access Token", r"\bya29\.[0-9A-Za-z\-_]+\b")
_add(
    "azure-client-secret",
    "high",
    "Azure client secret (possible)",
    r"(?i)client_secret[\"' :=]+\s*[\"']([A-Za-z0-9_~\-.]{30,})[\"']",
    True,
)

# --- Source-control tokens ---------------------------------------------- #
_add("github-pat", "critical", "GitHub Personal Access Token", r"\bghp_[A-Za-z0-9]{36,}\b")
_add("github-oauth", "critical", "GitHub OAuth Token", r"\bgho_[A-Za-z0-9]{36,}\b")
_add("github-app", "critical", "GitHub App Token", r"\b(ghu|ghs)_[A-Za-z0-9]{36,}\b")
_add("gitlab-pat", "high", "GitLab PAT", r"\bglpat-[0-9A-Za-z\-_]{20,}\b")
_add("bitbucket-app-pwd", "high", "Bitbucket App Password", r"\bATBB[A-Za-z0-9]{32,}\b")

# --- Payments / SaaS ---------------------------------------------------- #
_add("stripe-live", "critical", "Stripe Live Secret Key", r"\bsk_live_[0-9a-zA-Z]{24,}\b")
_add("stripe-test", "medium", "Stripe Test Secret Key", r"\bsk_test_[0-9a-zA-Z]{24,}\b")
_add("paypal-braintree", "high", "PayPal Braintree Token", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b")
_add("slack-token", "high", "Slack Token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,48}\b")
_add("slack-webhook", "medium", "Slack Webhook", r"https://hooks\.slack\.com/services/[A-Z0-9/]+")
_add("twilio-account-sid", "high", "Twilio Account SID", r"\bAC[a-f0-9]{32}\b")
_add("sendgrid-key", "high", "SendGrid API Key", r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")
_add("mailgun-key", "high", "Mailgun API Key", r"\bkey-[0-9a-zA-Z]{32}\b")

# --- Generic credentials / .env ---------------------------------------- #
_add(
    "env-password",
    "high",
    "Hard-coded password (env-style)",
    r"(?i)(?:ADMIN_PASSWORD|ROOT_PASSWORD|DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD|SMTP_PASSWORD)[\s]*[:=][\s]*[\"']?([^\s\"';#]+)[\"']?",
)
_add(
    "env-secret",
    "high",
    "Hard-coded secret token (env-style)",
    r"(?i)(?:SECRET_KEY|JWT_SECRET|APP_SECRET|API_SECRET|SESSION_SECRET|TOKEN)[\s]*[:=][\s]*[\"']?([A-Za-z0-9_\-\.+/=]{12,})[\"']?",
)
_add(
    "env-apikey",
    "high",
    "Hard-coded API key (env-style)",
    r"(?i)(?:API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN|BEARER_TOKEN)[\s]*[:=][\s]*[\"']?([A-Za-z0-9_\-\.+/=]{12,})[\"']?",
)
_add(
    "db-conn-string",
    "high",
    "Database connection string with credentials",
    r"(?i)(?:mysql|postgres|postgresql|mongodb(?:\+srv)?|redis|amqp|sqlserver|jdbc:[a-z]+)://[^:@/\s]+:[^@/\s]+@[^/\s]+",
)
_add("jwt", "medium", "JSON Web Token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# --- Private keys ------------------------------------------------------- #
_add(
    "private-key-pem",
    "critical",
    "Private key (PEM)",
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
)
_add("ssh-key", "high", "SSH private key reference", r"ssh-(?:rsa|ed25519|dss)\s+AAAA[0-9A-Za-z+/=]{30,}")


@dataclass
class Finding:
    rule_id: str
    severity: str
    description: str
    match: str
    redacted: str
    line: str
    line_no: int
    file_path: str
    commit_sha: Optional[str] = None
    source: str = "working-tree"  # 'working-tree' | 'diff' | 'dangling' | 'reflog'
    extra: dict = field(default_factory=dict)


def _redact(secret: str) -> str:
    if len(secret) <= 6:
        return "*" * len(secret)
    return secret[:3] + "*" * (len(secret) - 6) + secret[-3:]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan_text(
    text: str,
    *,
    file_path: str,
    commit_sha: Optional[str] = None,
    source: str = "working-tree",
) -> list[Finding]:
    """Run every pattern against `text` and return findings."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if len(line) > 4000:
            continue  # skip absurdly long lines (likely binary / minified)
        for rid, sev, desc, rx, _kw in SECRET_PATTERNS:
            for m in rx.finditer(line):
                # Use the highest-index group if it captured, else group(0)
                groups = [g for g in m.groups() if g]
                secret = groups[-1] if groups else m.group(0)
                # Entropy guard for noisy generic patterns
                if rid.startswith("env-") and _shannon(secret) < 2.0:
                    continue
                findings.append(
                    Finding(
                        rule_id=rid,
                        severity=sev,
                        description=desc,
                        match=secret,
                        redacted=_redact(secret),
                        line=line.strip()[:300],
                        line_no=i,
                        file_path=file_path,
                        commit_sha=commit_sha,
                        source=source,
                    )
                )
    return findings


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.match, f.file_path)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
