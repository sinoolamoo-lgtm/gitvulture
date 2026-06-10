"""Tests for C3 / C7 / C9."""
import base64
import hashlib
import hmac
import json
import tempfile
from pathlib import Path

import pytest

from gitvulture.core.git_pivots import (
    parse_gitmodules, parse_sourcemap, extract_hosts_from_text, run_git_pivots,
)
from gitvulture.core.jwt_forge import (
    parse_jwt, forge_alg_none, forge_kid_injection, crack_hs256,
    find_jwts_in_text, _b64url_enc,
)


# ---------------------------------------------------------------------------
# C9
# ---------------------------------------------------------------------------
class TestGitPivots:
    def test_parse_gitmodules(self):
        text = '''
[submodule "lib/vendor-a"]
    path = lib/vendor-a
    url = https://github.com/org/vendor-a.git
    branch = main

[submodule "deps/private-libs"]
    path = deps/private-libs
    url = git@github.com:org/private-libs.git
'''
        out = parse_gitmodules(text)
        assert len(out) == 2
        assert out[0]["name"] == "lib/vendor-a"
        assert out[0]["url"] == "https://github.com/org/vendor-a.git"
        assert out[0]["branch"] == "main"
        assert "private-libs" in out[1]["url"]

    def test_parse_sourcemap(self):
        sm = {
            "version": 3,
            "sources": ["webpack:///./src/index.js",
                        "https://internal.api.corp/lib.js",
                        "./node_modules/react.js"],
            "sourceRoot": "/build/",
        }
        out = parse_sourcemap(json.dumps(sm))
        assert out is not None
        assert out["src_count"] == 3
        assert out["src_root"] == "/build/"
        # webpack:// and node_modules filtered out of hints; only the
        # https://internal.api.corp one survives.
        assert "https://internal.api.corp/lib.js" in out["hint_urls"]

    def test_parse_sourcemap_bad(self):
        assert parse_sourcemap("not json at all") is None
        assert parse_sourcemap('"just a string"') is None

    def test_extract_hosts_internal(self):
        text = '''
        DB_HOST=db.internal.corp
        CDN=https://cdn.cloudfront.net/x
        SOAP_URL=https://staging-api.example.com/api
        '''
        hosts = extract_hosts_from_text(text, primary_host="example.com")
        assert "db.internal.corp" in hosts
        assert "staging-api.example.com" in hosts
        # cloudfront filtered out
        assert "cdn.cloudfront.net" not in hosts

    def test_run_git_pivots_smoke(self):
        tmp = Path(tempfile.mkdtemp(prefix="gv_c9_"))
        (tmp / "recovered_source").mkdir()
        (tmp / "recovered_source" / ".gitmodules").write_text(
            '[submodule "x"]\n    url = https://github.com/org/x.git\n'
        )
        git_dir = tmp / "git"
        git_dir.mkdir()
        (git_dir / "hooks").mkdir()
        (git_dir / "hooks" / "pre-commit").write_text(
            "#!/bin/sh\necho 'hook content'\n"
        )
        out = run_git_pivots(git_dir, tmp / "recovered_source")
        assert len(out.submodules) == 1
        assert len(out.hooks) == 1
        assert out.hooks[0]["name"] == "pre-commit"


# ---------------------------------------------------------------------------
# C7
# ---------------------------------------------------------------------------
def _make_jwt_hs256(payload: dict, key: str) -> str:
    """Mint a real HS256 JWT for the cracking test."""
    h = {"alg": "HS256", "typ": "JWT"}
    h_b = _b64url_enc(json.dumps(h, separators=(",", ":")).encode())
    p_b = _b64url_enc(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b}.{p_b}".encode()
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return f"{h_b}.{p_b}.{_b64url_enc(sig)}"


class TestJwtForge:
    def test_parse_jwt(self):
        t = _make_jwt_hs256({"sub": "alice", "admin": False}, "secret")
        a = parse_jwt(t)
        assert a.alg == "HS256"
        assert a.payload["sub"] == "alice"

    def test_forge_alg_none(self):
        t = _make_jwt_hs256({"sub": "alice"}, "secret")
        forged = forge_alg_none(t)
        assert forged.endswith(".")  # empty signature
        # Decode header → alg must be "none"
        head = json.loads(base64.urlsafe_b64decode(
            forged.split(".")[0] + "=" * (-len(forged.split(".")[0]) % 4)
        ))
        assert head["alg"] == "none"

    def test_forge_kid_injection(self):
        t = _make_jwt_hs256({"sub": "alice"}, "secret")
        forged = forge_kid_injection(t, "../../etc/passwd")
        head = json.loads(base64.urlsafe_b64decode(
            forged.split(".")[0] + "=" * (-len(forged.split(".")[0]) % 4)
        ))
        assert head["kid"] == "../../etc/passwd"

    def test_crack_hs256_success(self):
        t = _make_jwt_hs256({"sub": "alice", "admin": True}, "secret123")
        # Throw in 5 wrong + 1 right candidate
        cands = ["wrong1", "abc", "secret", "secret124", "secret123", "X"]
        assert crack_hs256(t, cands) == "secret123"

    def test_crack_hs256_fail(self):
        t = _make_jwt_hs256({"sub": "alice"}, "ground-truth")
        assert crack_hs256(t, ["wrong1", "wrong2", "wrong3"]) == ""

    def test_find_jwts_in_text(self):
        t = _make_jwt_hs256({"sub": "alice"}, "k")
        text = f"some preamble\nToken: {t}\nmore data"
        out = find_jwts_in_text(text)
        assert t in out

    def test_find_jwts_dedup(self):
        t = _make_jwt_hs256({"sub": "x"}, "k")
        text = f"{t}\n{t}\n{t}"
        out = find_jwts_in_text(text)
        assert len(out) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
