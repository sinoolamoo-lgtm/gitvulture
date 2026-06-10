"""ScopeGuard — single authority for outbound HTTP authorization (spec §2).

Every HTTP dispatch and every 30x redirect MUST pass through `authorize()` /
`authorize_redirect()` before going on the wire. Mutating verbs require an
EXACT endpoint registration; no prefix freedom.

The contract is intentionally strict:
- Encoded path payloads on in-scope hosts are ALLOWED (they are the bypass
  library — `..%2f`, `;`, `%2e` etc. are valid weapons against WAFs, not
  attacks on us).
- The boundary we protect is `(scheme, host, port)`. Anything that resolves
  outside that set is rejected, regardless of how clean the path looks.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PROPFIND"})
MUTATING_METHODS = frozenset(
    {"POST", "PUT", "PATCH", "DELETE", "MKCOL", "PROPPATCH", "MOVE", "COPY"}
)

DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class HostKey:
    scheme: str
    host: str
    port: int

    @classmethod
    def from_url(cls, url: str) -> "HostKey":
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        port = p.port or DEFAULT_PORTS.get(p.scheme, 0)
        return cls(scheme=p.scheme.lower(), host=host, port=port)


@dataclass
class ScopeContract:
    # authorized origins (scheme,host,port) — exact match
    authorized_hosts: set[HostKey] = field(default_factory=set)

    # Exact (scheme,host,port,path) tuples allowed for mutating verbs.
    # Smart-HTTP registers /info/refs and /git-upload-pack here.
    extra_allowed_post_endpoints: set[tuple[HostKey, str]] = field(default_factory=set)

    allow_mutating: bool = False         # --allow-mutating
    allow_lockout_risk: bool = False     # --allow-lockout-risk (consumed by L5)
    interactive_consent: bool = False    # gated to TTY by caller

    def add_host(self, url_or_host: str) -> HostKey:
        if "://" in url_or_host:
            key = HostKey.from_url(url_or_host)
        else:
            host, _, port = url_or_host.partition(":")
            key = HostKey("https", host.lower(), int(port) if port else 443)
        self.authorized_hosts.add(key)
        return key

    def register_post_exact(self, scheme: str, host: str, port: int, path: str) -> None:
        """Smart-HTTP / WebDAV / etc. call this to whitelist their exact POST endpoints."""
        key = HostKey(scheme.lower(), host.lower(), port)
        self.authorized_hosts.add(key)
        self.extra_allowed_post_endpoints.add((key, _normalize_path(path)))


@dataclass
class Decision:
    allowed: bool
    reason: str
    consent_required: bool = False
    recommended_method: Optional[str] = None


def _normalize_path(path: str) -> str:
    """Strip query, decode %xx, collapse //, resolve segments.

    NOTE: this is for the POST-allowlist EXACT-match lookup, NOT for the
    host-boundary check (the bypass library intentionally sends weird paths).
    """
    if not path:
        return "/"
    # Drop query and fragment
    path = path.split("?", 1)[0].split("#", 1)[0]
    # Percent-decode
    path = unquote(path)
    # Collapse multiple slashes
    while "//" in path:
        path = path.replace("//", "/")
    # Resolve . and .. segments
    out: list[str] = []
    for seg in path.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/" + "/".join(out)


class ScopeGuard:
    """Mediates every outbound HTTP request.

    Wire it into the HttpClient so that every `_request()` call invokes
    `guard.authorize(method, url)` and refuses to dispatch on Decision(allowed=False).
    """

    def __init__(
        self,
        contract: ScopeContract,
        audit_path: Optional[Path] = None,
        log=None,
    ) -> None:
        self.contract = contract
        self._audit_path = audit_path
        self._audit_lock = threading.Lock()
        self._consent_lock = asyncio.Lock()
        self._seq = 0
        self.log = log
        self._audit_fp = None
        if audit_path:
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            self._audit_fp = open(audit_path, "a", encoding="utf-8")

    # ------------------------------------------------------------------ #
    def _next_seq(self) -> int:
        with self._audit_lock:
            self._seq += 1
            return self._seq

    def _audit(
        self,
        decision: Decision,
        method: str,
        url: str,
        *,
        kind: str = "request",
        origin_artifact_id: Optional[str] = None,
        lineage: tuple[str, ...] = (),
    ) -> None:
        record = {
            "seq": self._next_seq(),
            "ts": time.time(),
            "kind": kind,
            "decision": "allow" if decision.allowed else "deny",
            "method": method,
            "url": url,
            "reason": decision.reason,
            "consent_required": decision.consent_required,
            "origin_artifact_id": origin_artifact_id,
            "lineage": list(lineage),
        }
        if self._audit_fp:
            try:
                self._audit_fp.write(json.dumps(record, default=str) + "\n")
                self._audit_fp.flush()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    def _host_in_scope(self, url: str) -> Optional[HostKey]:
        """Return the matching HostKey if `url` resolves to an in-scope origin."""
        try:
            key = HostKey.from_url(url)
        except Exception:
            return None
        return key if key in self.contract.authorized_hosts else None

    def authorize(
        self,
        method: str,
        url: str,
        *,
        origin_artifact_id: Optional[str] = None,
        lineage: tuple[str, ...] = (),
    ) -> Decision:
        """Authorize a single outbound HTTP request.

        Returns a Decision. Callers MUST refuse to dispatch on allowed=False.
        """
        method_u = method.upper()

        host = self._host_in_scope(url)
        if host is None:
            d = Decision(False, "off-scope-host")
            self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
            return d

        # Read-only methods: always allowed once host is in scope.
        if method_u in READ_ONLY_METHODS:
            d = Decision(True, "read-only")
            self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
            return d

        # Mutating: require exact endpoint registration OR explicit consent.
        if method_u in MUTATING_METHODS:
            path = _normalize_path(urlsplit(url).path)
            if (host, path) in self.contract.extra_allowed_post_endpoints:
                d = Decision(True, "mutating-registered-exact")
                self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
                return d
            if self.contract.allow_mutating and self.contract.interactive_consent:
                d = Decision(False, "needs-consent", consent_required=True)
                self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
                return d
            d = Decision(
                False,
                "mutating-not-registered",
                recommended_method="GET",
            )
            self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
            return d

        # Unknown / unusual verb — deny by default.
        d = Decision(False, f"unknown-method:{method_u}")
        self._audit(d, method_u, url, origin_artifact_id=origin_artifact_id, lineage=lineage)
        return d

    def authorize_redirect(
        self,
        from_url: str,
        status: int,
        to_url: str,
        new_method: str,
        *,
        origin_artifact_id: Optional[str] = None,
        lineage: tuple[str, ...] = (),
    ) -> Decision:
        """Re-validate every 30x redirect target.

        Per spec §2.1 rule 4: a whitelisted GET that 302s into a state-changing
        endpoint must NOT be followed blindly. Caller MUST disable auto-follow
        in httpx and pass each Location through this method.
        """
        d = self.authorize(
            new_method, to_url,
            origin_artifact_id=origin_artifact_id, lineage=lineage,
        )
        # Stamp the audit kind for clarity in the JSONL.
        self._audit(d, new_method, to_url, kind=f"redirect-from:{status}",
                    origin_artifact_id=origin_artifact_id, lineage=lineage)
        return d

    async def request_consent(
        self,
        method: str,
        url: str,
        reason: str,
        *,
        origin_artifact_id: Optional[str] = None,
        lineage: tuple[str, ...] = (),
    ) -> Decision:
        """Serialized human-in-the-loop prompt for ad-hoc mutating verbs.

        Returns Decision. Non-TTY environments hard-deny. TTY prompts the
        operator and respects their answer.
        """
        import sys
        if not (self.contract.interactive_consent and sys.stdin.isatty()):
            d = Decision(False, "consent-unavailable-non-tty")
            self._audit(d, method, url, kind="consent",
                        origin_artifact_id=origin_artifact_id, lineage=lineage)
            return d
        async with self._consent_lock:
            print(f"\n[CONSENT] {method} {url}", flush=True)
            print(f"          Reason: {reason}", flush=True)
            if lineage:
                print(f"          Lineage: {' -> '.join(lineage)}", flush=True)
            answer = (await asyncio.to_thread(input, "          Allow? [y/N]: ")).strip().lower()
            allow = answer in ("y", "yes")
            d = Decision(allow, "consent-granted" if allow else "consent-denied")
            self._audit(d, method, url, kind="consent",
                        origin_artifact_id=origin_artifact_id, lineage=lineage)
            return d

    def close(self) -> None:
        if self._audit_fp:
            try:
                self._audit_fp.close()
            except Exception:
                pass
