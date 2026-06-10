"""Smoke tests for the new E1 / D1 / C1 modules."""
from __future__ import annotations

import pytest

from gitvulture.core.scope_guard import (
    HostKey,
    ScopeContract,
    ScopeGuard,
    _normalize_path,
)
from gitvulture.core.smart_http import (
    encode_pkt,
    encode_flush,
    decode_pkts,
    SmartHttpResult,
)


class TestScopeGuard:
    def setup_method(self):
        self.contract = ScopeContract(interactive_consent=False)
        self.contract.add_host("https://target.tld:443")
        self.guard = ScopeGuard(self.contract)

    def test_in_scope_get_allowed(self):
        d = self.guard.authorize("GET", "https://target.tld/.git/HEAD")
        assert d.allowed
        assert d.reason == "read-only"

    def test_off_scope_get_denied(self):
        d = self.guard.authorize("GET", "https://attacker.tld/x")
        assert not d.allowed
        assert d.reason == "off-scope-host"

    def test_encoded_path_payload_allowed(self):
        # Bypass library payloads MUST be allowed (spec §2.1 rule 1)
        for path in (
            "/..%2f.git/HEAD",
            "/.git/%2eHEAD",
            "/.git//..;/HEAD",
            "/./.git/HEAD%20",
            "/.git/HEAD::$DATA",
        ):
            d = self.guard.authorize("GET", f"https://target.tld{path}")
            assert d.allowed, f"bypass payload rejected: {path}"

    def test_mutating_unregistered_denied(self):
        d = self.guard.authorize("POST", "https://target.tld/api/x")
        assert not d.allowed
        assert d.reason == "mutating-not-registered"

    def test_mutating_registered_exact_allowed(self):
        self.contract.register_post_exact("https", "target.tld", 443,
                                          "/git-upload-pack")
        d = self.guard.authorize("POST", "https://target.tld/git-upload-pack")
        assert d.allowed
        assert d.reason == "mutating-registered-exact"

    def test_mutating_registered_query_stripped(self):
        # Path normalization strips query string before matching
        self.contract.register_post_exact("https", "target.tld", 443,
                                          "/git-upload-pack")
        d = self.guard.authorize("POST",
                                 "https://target.tld/git-upload-pack?x=y")
        assert d.allowed

    def test_mutating_prefix_does_not_work(self):
        # Per spec hardening: exact match only, NOT prefix
        self.contract.register_post_exact("https", "target.tld", 443,
                                          "/git-upload-pack")
        d = self.guard.authorize("POST",
                                 "https://target.tld/git-upload-pack-evil")
        assert not d.allowed

    def test_scheme_distinct(self):
        # http vs https are distinct origins
        d = self.guard.authorize("GET", "http://target.tld/x")
        assert not d.allowed

    def test_normalize_path(self):
        assert _normalize_path("/a//b/../c") == "/a/c"
        assert _normalize_path("/a/b/./c") == "/a/b/c"
        assert _normalize_path("/git-upload-pack?x=y") == "/git-upload-pack"
        assert _normalize_path("/%2e%2e/etc/passwd") == "/etc/passwd"


class TestPktLine:
    def test_encode_basic(self):
        # "0008foo\n" — 4 payload bytes + 4-byte length header = 8
        assert encode_pkt("foo\n") == b"0008foo\n"

    def test_encode_flush(self):
        assert encode_flush() == b"0000"

    def test_decode_basic(self):
        # "hello\n" is 6 bytes, +4 header = 0x0a
        data = b"000ahello\n0000"
        out = list(decode_pkts(data))
        assert ("data", b"hello\n") in out
        assert ("flush", b"") in out

    def test_decode_truncated_returns_clean(self):
        # Malformed length → iterator stops silently, doesn't crash
        data = b"00zz"
        assert list(decode_pkts(data)) == []

    def test_decode_sentinels(self):
        out = list(decode_pkts(b"0001" + b"0002"))
        kinds = [k for k, _ in out]
        assert "delim" in kinds
        assert "resp_end" in kinds

    def test_decode_rejects_oversized(self):
        # length > MAX_PKT  → stop iteration
        out = list(decode_pkts(b"ffff" + b"x" * 100))
        assert out == []


class TestSmartHttpResult:
    def test_ok_property(self):
        r = SmartHttpResult(protocol="v1")
        assert r.ok
        r.error = "x"
        assert not r.ok
        r2 = SmartHttpResult()  # no protocol
        assert not r2.ok


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
