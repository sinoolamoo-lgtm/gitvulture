"""Smart-HTTP Git protocol implementation (spec §3 / D1).

Implements the `git-upload-pack` smart protocol over HTTP. When the target
exposes the smart endpoint we can enumerate refs and clone in ONE request,
even if dumb-HTTP file enumeration is blocked.

Protocol references:
- https://www.git-scm.com/docs/http-protocol
- https://www.git-scm.com/docs/protocol-v2

This module is intentionally pure-Python (no dulwich). dulwich's pkt-line
internals shift between versions; we want stability.

Public entry: `SmartHttpProbe.probe()` returns `SmartHttpResult` with:
- protocol: "v1" / "v2" / None (= dumb-only target)
- caps: capability list as advertised
- refs: list of (sha, ref_name) — populated for v1 from the advertisement
        and for v2 after a separate ls-refs round-trip
- symref_head: e.g. "refs/heads/main" (free default-branch detection)
- object_format: "sha1" / "sha256"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# pkt-line framing (§3.2)
# ---------------------------------------------------------------------------
FLUSH = b"0000"
DELIM = b"0001"  # v2 section delimiter
RESP_END = b"0002"

MAX_PKT = 0xFFF0


def encode_pkt(payload: bytes | str) -> bytes:
    """Length-prefix a single pkt-line (per git protocol)."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    length = len(payload) + 4
    if length > MAX_PKT:
        raise ValueError(f"pkt-line too long: {length}")
    return f"{length:04x}".encode() + payload


def encode_flush() -> bytes:
    return FLUSH


def encode_delim() -> bytes:
    return DELIM


def decode_pkts(data: bytes):
    """Iterate pkt-lines from a smart-HTTP response stream.

    Yields tuples (kind, payload):
      kind = "data"  → payload is the bytes body of the pkt
      kind = "flush" → end-of-section sentinel (payload = b"")
      kind = "delim" → v2 section delimiter
      kind = "resp_end" → v2 response end

    Bounds-checks every length; rejects > MAX_PKT.
    """
    i = 0
    n = len(data)
    while i < n:
        if n - i < 4:
            return  # truncated; caller decides what to do
        try:
            length = int(data[i:i + 4], 16)
        except ValueError:
            return
        if length == 0:
            yield ("flush", b"")
            i += 4
            continue
        if length == 1:
            yield ("delim", b"")
            i += 4
            continue
        if length == 2:
            yield ("resp_end", b"")
            i += 4
            continue
        if length == 3:
            i += 4
            continue  # reserved sentinel, no payload
        if length > MAX_PKT or length > n - i:
            return
        payload = data[i + 4: i + length]
        yield ("data", payload)
        i += length


# ---------------------------------------------------------------------------
# Smart probe result
# ---------------------------------------------------------------------------
@dataclass
class SmartHttpResult:
    protocol: Optional[str] = None
    caps: list[str] = field(default_factory=list)
    refs: list[tuple[str, str]] = field(default_factory=list)  # (sha, ref_name)
    symref_head: Optional[str] = None
    object_format: str = "sha1"
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.protocol is not None and self.error is None


# ---------------------------------------------------------------------------
# Smart-HTTP probe
# ---------------------------------------------------------------------------
class SmartHttpProbe:
    """Probes a target for smart-HTTP support and enumerates refs.

    Usage:
        contract.register_post_exact(scheme, host, port, "/.git/info/refs")
        contract.register_post_exact(scheme, host, port, "/.git/git-upload-pack")
        contract.register_post_exact(scheme, host, port, "/info/refs")
        contract.register_post_exact(scheme, host, port, "/git-upload-pack")
        probe = SmartHttpProbe(http_client, base_url, log)
        result = await probe.probe()
        if result.refs: ...  # feed into Phase 2
    """

    def __init__(self, http_client, base_url: str, log):
        self.http = http_client
        self.base = base_url.rstrip("/")
        self.log = log

    # ------------------------------------------------------------------ #
    async def probe(self) -> SmartHttpResult:
        """Run the full smart-HTTP discovery. Safe to call on dumb-only targets."""
        # Try both with and without /.git/ prefix — some smart servers mount
        # the service at the repo root (gitea, gitlab), others under /.git/.
        for git_prefix in (".git/", ""):
            info_url = f"{self.base}/{git_prefix}info/refs?service=git-upload-pack"

            # Step 1: smart advertisement — sends Git-Protocol header to opt
            # into v2. Server picks v1 or v2 based on its capability.
            self.log.phase(f"smart-http probe @ /{git_prefix}info/refs")
            res = await self.http._request(
                info_url,
                extra_headers={
                    "Accept": "application/x-git-upload-pack-advertisement",
                    "Git-Protocol": "version=2",
                },
            )
            if res.status != 200 or not res.content:
                continue

            ct = (res.headers.get("content-type")
                  or res.headers.get("Content-Type") or "").lower()
            if "x-git-upload-pack-advertisement" not in ct:
                # Server returned 200 but not the smart MIME — dumb-only.
                self.log.info(f"smart-http not advertised (ct={ct})")
                continue

            # Capture remembered prefix for any subsequent POSTs
            self._git_prefix = git_prefix

            # Step 2: detect protocol version
            pkts = list(decode_pkts(res.content))
            if not pkts:
                continue

            # v2 starts with "version 2"
            first_data = next((p for k, p in pkts if k == "data"), None)
            if first_data and first_data.startswith(b"version 2"):
                return await self._handle_v2(pkts)

            # v1 path
            return self._handle_v1(pkts)

        return SmartHttpResult(error="not-a-smart-server")

    # ------------------------------------------------------------------ #
    def _handle_v1(self, pkts) -> SmartHttpResult:
        """v1: banner + refs (first ref carries NUL-separated capabilities)."""
        result = SmartHttpResult(protocol="v1")
        seen_banner = False

        for kind, payload in pkts:
            if kind == "flush":
                if seen_banner:
                    break  # flush after refs = end of advertisement
                continue
            if kind != "data":
                continue

            # Banner
            if not seen_banner:
                if not payload.startswith(b"# service=git-upload-pack"):
                    return SmartHttpResult(error="missing-smart-banner")
                seen_banner = True
                continue

            # First ref carries caps (NUL-separated per spec §3.3)
            if not result.refs:
                # "<sha> <ref>\0<caps>"
                if b"\0" in payload:
                    ref_part, caps_part = payload.split(b"\0", 1)
                    result.caps = caps_part.decode("utf-8", "replace").strip().split()
                    # Extract symref=HEAD:refs/heads/X from caps
                    for cap in result.caps:
                        if cap.startswith("symref=HEAD:"):
                            result.symref_head = cap.split(":", 1)[1]
                        elif cap.startswith("object-format="):
                            result.object_format = cap.split("=", 1)[1]
                    line = ref_part
                else:
                    line = payload
            else:
                line = payload

            line_s = line.decode("utf-8", "replace").strip()
            m = re.match(r"^([0-9a-f]{40,64})\s+(.+)$", line_s)
            if m:
                sha, ref = m.group(1), m.group(2)
                # Skip the "capabilities^{}" empty-repo sentinel
                if ref != "capabilities^{}":
                    result.refs.append((sha, ref))

        if result.object_format == "sha256":
            return SmartHttpResult(
                error="sha256-repos-not-supported-yet (re-run with --allow-sha256 in v2)",
                protocol="v1",
                caps=result.caps,
                object_format="sha256",
            )

        self.log.success(
            f"smart-http v1 — {len(result.refs)} refs, "
            f"symref-HEAD={result.symref_head}"
        )
        return result

    # ------------------------------------------------------------------ #
    async def _handle_v2(self, advertise_pkts) -> SmartHttpResult:
        """v2: caps in advertisement; refs require a separate ls-refs POST."""
        result = SmartHttpResult(protocol="v2")
        for kind, payload in advertise_pkts:
            if kind != "data":
                continue
            s = payload.rstrip(b"\n").decode("utf-8", "replace")
            if s.startswith("version"):
                continue
            result.caps.append(s)
            if s.startswith("object-format="):
                result.object_format = s.split("=", 1)[1]

        if result.object_format == "sha256":
            return SmartHttpResult(
                error="sha256-repos-not-supported-yet",
                protocol="v2",
                caps=result.caps,
                object_format="sha256",
            )

        # ls-refs round-trip (spec §3.4)
        body = (
            encode_pkt(b"command=ls-refs\n")
            + encode_pkt(b"agent=gitvulture/2.0\n")
            + encode_pkt(b"object-format=sha1\n")
            + encode_delim()
            + encode_pkt(b"peel\n")
            + encode_pkt(b"symrefs\n")
            + encode_pkt(b"ref-prefix refs/\n")
            + encode_pkt(b"ref-prefix HEAD\n")
            + encode_flush()
        )

        ls_url = f"{self.base}/{getattr(self, '_git_prefix', '')}git-upload-pack"
        post_res = await self.http.post(
            ls_url,
            body=body,
            extra_headers={
                "Content-Type": "application/x-git-upload-pack-request",
                "Accept": "application/x-git-upload-pack-result",
                "Git-Protocol": "version=2",
            },
        )
        if post_res.status != 200 or not post_res.content:
            result.error = f"ls-refs failed: status={post_res.status} err={post_res.error}"
            return result

        # Parse "<sha> <ref> [symref-target:X] [peeled:Y]"
        for kind, payload in decode_pkts(post_res.content):
            if kind != "data":
                continue
            line = payload.rstrip(b"\n").decode("utf-8", "replace")
            parts = line.split(" ")
            if len(parts) >= 2 and re.match(r"^[0-9a-f]{40,64}$", parts[0]):
                sha, ref = parts[0], parts[1]
                result.refs.append((sha, ref))
                # Pick up symref-target for HEAD specifically
                for extra in parts[2:]:
                    if extra.startswith("symref-target:") and ref == "HEAD":
                        result.symref_head = extra.split(":", 1)[1]

        self.log.success(
            f"smart-http v2 — {len(result.refs)} refs, "
            f"symref-HEAD={result.symref_head}, caps={len(result.caps)}"
        )
        return result
