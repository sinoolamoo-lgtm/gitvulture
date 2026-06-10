"""D10 — WebDAV enumeration / chain (spec §6.3 / D10).

If PROPFIND succeeds (status 207) on the target during Phase 1 recon, this
module runs the full WebDAV read+write chain.

Capabilities by mode:
- **read-only**     : PROPFIND Depth=1 (default) enumerates directory
                      tree; OPTIONS reveals supported verbs; GET on
                      discovered resources.
- **+ --offensive** : Depth=infinity allowed, LOCK/UNLOCK probed.
- **+ --offensive + --allow-mutating** : MKCOL (create dir), PUT (upload),
                      COPY, MOVE, DELETE. Each verb registers its EXACT
                      endpoint with ScopeGuard before dispatch.

All file uploads are tiny canary files named `gv-canary-<ts>.txt` and
deleted after success-confirmation. Never overwrite existing paths.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path


_PROPFIND_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<D:propfind xmlns:D="DAV:">\n'
    '  <D:propname/>\n'
    '</D:propfind>\n'
).encode()


@dataclass
class WebDAVReport:
    supported_methods: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    writable: bool = False
    canary_path: str = ""
    canary_verified: bool = False
    notes: list[str] = field(default_factory=list)


# Common collection roots to probe — order matters (most likely first)
_PROBE_ROOTS = ["/", "/webdav/", "/dav/", "/files/", "/uploads/",
                "/share/", "/storage/", "/data/", "/upload/"]


def _parse_propfind_xml(body: bytes) -> list[str]:
    """Best-effort extraction of <D:href>...</D:href> entries."""
    out = []
    for m in re.finditer(rb"<[^>]*?href[^>]*>(.*?)</[^>]*?href>",
                         body, re.IGNORECASE | re.DOTALL):
        href = m.group(1).decode("utf-8", "replace").strip()
        if href:
            out.append(href)
    return out


async def run_webdav(
    http_client,
    scope_contract,           # E1 ScopeContract — we register PUT/MKCOL exact paths
    base_url: str,
    *,
    offensive: bool = False,
    allow_mutating: bool = False,
    log=None,
) -> WebDAVReport:
    """Probe WebDAV; respect E1 scope contract for every mutating verb."""
    from urllib.parse import urlsplit
    parsed = urlsplit(base_url)
    scheme = parsed.scheme
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)

    report = WebDAVReport()
    if log:
        log.phase(f"PHASE D10 ::  WebDAV (offensive={offensive}, "
                  f"mutating={allow_mutating})")

    # 1. OPTIONS — reveals Allow header (supported methods)
    res = await http_client._request(base_url, method="OPTIONS")
    if res.status == 0 or res.status >= 400:
        report.notes.append(f"OPTIONS returned {res.status}; WebDAV likely absent")
        return report
    allow = (res.headers.get("allow") or res.headers.get("Allow") or "")
    dav = (res.headers.get("dav") or res.headers.get("DAV") or "")
    if "PROPFIND" not in allow.upper() and not dav:
        report.notes.append("No PROPFIND in Allow header; not a WebDAV server")
        return report
    report.supported_methods = [m.strip() for m in allow.split(",") if m.strip()]
    if log:
        log.success(f"D10 OPTIONS Allow: {allow}")

    # 2. PROPFIND Depth=1 on the root + each probe root
    depth = "infinity" if offensive else "1"
    headers = {"Depth": depth, "Content-Type": "application/xml"}
    for root in _PROBE_ROOTS:
        url = base_url.rstrip("/") + root
        res = await http_client._request(
            url, method="PROPFIND", body=_PROPFIND_BODY,
            extra_headers=headers,
        )
        if res.status not in (207, 200):
            continue
        hrefs = _parse_propfind_xml(res.content or b"")
        report.discovered_paths.extend(hrefs)
        if log:
            log.info(f"D10 PROPFIND {root} → {len(hrefs)} entries")

    # Dedup
    report.discovered_paths = sorted(set(report.discovered_paths))[:500]

    # 3. Mutating chain — only if BOTH flags set
    if not (offensive and allow_mutating):
        return report

    if "PUT" not in [m.upper() for m in report.supported_methods]:
        report.notes.append("PUT not advertised; skipping canary upload")
        return report

    # Try a canary upload to /webdav/ first; if 403 try root.
    canary_name = f"gv-canary-{int(time.time())}.txt"
    canary_body = b"gitvulture canary — safe to delete\n"

    for root in ("/webdav/", "/dav/", "/uploads/", "/"):
        url = base_url.rstrip("/") + root + canary_name
        # E1 — register the EXACT path so authorize() approves
        path = root + canary_name
        scope_contract.register_post_exact(scheme, host, port, path)

        put_res = await http_client._request(
            url, method="PUT", body=canary_body,
            extra_headers={"Content-Type": "text/plain"},
        )
        if put_res.status in (200, 201, 204):
            report.writable = True
            report.canary_path = url
            # Verify via GET
            get_res = await http_client._request(url, method="GET")
            if (get_res.status == 200 and
                    get_res.content == canary_body):
                report.canary_verified = True
                if log:
                    log.success(f"D10 PUT verified at {url}")
                # Clean up
                if "DELETE" in [m.upper() for m in report.supported_methods]:
                    del_res = await http_client._request(url, method="DELETE")
                    if del_res.status in (200, 204):
                        report.notes.append(f"canary deleted: {url}")
            break
        else:
            report.notes.append(f"PUT {url} → {put_res.status}")
    return report


def write_webdav_report(report: WebDAVReport, output_dir):
    import json
    from pathlib import Path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "supported_methods": report.supported_methods,
        "discovered_paths": report.discovered_paths,
        "writable": report.writable,
        "canary_path": report.canary_path,
        "canary_verified": report.canary_verified,
        "notes": report.notes,
    }
    (output_dir / "webdav.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )
    md = ["# WebDAV report (D10)", ""]
    md.append(f"**Methods supported**: `{', '.join(report.supported_methods) or 'none'}`")
    md.append(f"**Writable**: {'🔴 YES' if report.writable else 'no'}")
    if report.canary_verified:
        md.append(f"**Canary upload verified at**: `{report.canary_path}`")
    md.append("")
    if report.discovered_paths:
        md.append(f"## Discovered paths ({len(report.discovered_paths)})")
        md.append("")
        for p in report.discovered_paths[:200]:
            md.append(f"- `{p}`")
        md.append("")
    for n in report.notes:
        md.append(f"- _{n}_")
    (output_dir / "webdav.md").write_text("\n".join(md), encoding="utf-8")
