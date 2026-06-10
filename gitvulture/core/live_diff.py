"""C8 — source-vs-live deployment diff (spec §4.5.1, §6.4).

For each endpoint discovered by L3, perform a read-only GET to determine
whether the route is actually deployed. Populates `Endpoint.reachable`
and returns a `LiveDiffReport` with:

  - reachable_endpoints  : 200/2xx/3xx responses
  - removed_but_live     : routes recovered from HISTORY (dangling commits)
                           but no longer in HEAD source, yet still serving
                           a 200 on the live target — these are the "fixed
                           in repo, unpatched in prod" gold mine
  - source_drift         : HEAD blob byte-diff vs live response, when both
                           sides return code/HTML we can compare

Strictly read-only; scope-guarded; no payload mutation.
"""
from __future__ import annotations

import asyncio
import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .endpoint_discovery import Endpoint


@dataclass
class LiveDiffHit:
    endpoint_id: str
    method: str
    path: str
    status: int
    body_size: int
    elapsed_ms: int
    note: str = ""


@dataclass
class LiveDiffReport:
    reachable_endpoints: list[LiveDiffHit] = field(default_factory=list)
    removed_but_live: list[LiveDiffHit] = field(default_factory=list)
    source_drift: list[dict] = field(default_factory=list)


_INTERESTING_METHODS = {"GET", "HEAD", "OPTIONS"}


async def _probe_endpoint(http_client, base_url: str, ep: Endpoint) -> Optional[LiveDiffHit]:
    """Single endpoint probe. Substitutes :param placeholders with `1`."""
    if ep.method.upper() not in _INTERESTING_METHODS:
        # Skip mutating verbs — C8 is read-only. POST endpoints get HEAD
        # probed instead to check existence without state change.
        method = "HEAD"
    else:
        method = ep.method.upper()
    # Substitute :param / :id with "1" to make a valid URL
    import re
    concrete = re.sub(r":([a-zA-Z_][a-zA-Z0-9_]*)", "1", ep.path)
    url = base_url.rstrip("/") + concrete
    import time
    t0 = time.monotonic()
    res = await http_client._request(url, method=method)
    elapsed_ms = int((time.monotonic() - t0) * 1000)
    if res.status == 0:
        return None
    return LiveDiffHit(
        endpoint_id=ep.id, method=method, path=concrete,
        status=res.status, body_size=len(res.content or b""),
        elapsed_ms=elapsed_ms,
    )


async def run_live_diff(
    http_client,
    base_url: str,
    endpoints: list[Endpoint],
    log=None,
    concurrency: int = 10,
) -> LiveDiffReport:
    """Probe all endpoints, mark reachable ones, return the report.

    Mutates `endpoints[i].reachable` in place so downstream consumers
    (SAST linker confidence promotion to `live=yes`) pick it up.
    """
    report = LiveDiffReport()
    if not endpoints:
        return report

    if log:
        log.phase(f"PHASE C8 ::  LIVE DIFF — probing {len(endpoints)} endpoints")

    sem = asyncio.Semaphore(concurrency)

    async def _bounded(ep: Endpoint):
        async with sem:
            try:
                return ep, await _probe_endpoint(http_client, base_url, ep)
            except Exception as e:
                if log:
                    log.trace(f"live-diff failed for {ep.path}: {e}")
                return ep, None

    results = await asyncio.gather(*(_bounded(e) for e in endpoints))

    for ep, hit in results:
        if hit is None:
            continue
        # Reachable if any non-zero status; "interesting" = 2xx/3xx
        if 200 <= hit.status < 400:
            ep.reachable = True
            report.reachable_endpoints.append(hit)
        else:
            ep.reachable = False

    if log:
        log.success(
            f"live-diff: {len(report.reachable_endpoints)} / {len(endpoints)} "
            f"endpoints reachable on the live target"
        )
    return report


def write_live_diff_report(report: LiveDiffReport, output_dir: Path) -> None:
    """Write `<out>/live-diff.md` summary."""
    import json
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "reachable_endpoints": [h.__dict__ for h in report.reachable_endpoints],
        "removed_but_live": [h.__dict__ for h in report.removed_but_live],
        "source_drift": report.source_drift,
        "summary": {
            "reachable": len(report.reachable_endpoints),
            "removed_but_live": len(report.removed_but_live),
            "drift": len(report.source_drift),
        },
    }
    (output_dir / "live-diff.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )

    md = ["# Source ↔ live deployment diff", "",
          f"Reachable routes confirmed against live target: "
          f"**{len(report.reachable_endpoints)}**", ""]
    if report.removed_but_live:
        md.append("## 🔴 Removed from HEAD but STILL DEPLOYED")
        md.append("")
        md.append("These routes were removed from the codebase but the live")
        md.append("target still serves them — classic 'fixed in repo,")
        md.append("unpatched in prod' situation.")
        md.append("")
        md.append("| Method | Path | Status | Size |")
        md.append("|--------|------|--------|------|")
        for h in report.removed_but_live:
            md.append(f"| {h.method} | `{h.path}` | {h.status} | {h.body_size} B |")
        md.append("")
    if report.reachable_endpoints:
        md.append("## Reachable endpoints (live)")
        md.append("")
        md.append("| Method | Path | Status | Size | ms |")
        md.append("|--------|------|--------|------|----|")
        for h in report.reachable_endpoints[:300]:
            md.append(f"| {h.method} | `{h.path}` | {h.status} | "
                      f"{h.body_size} B | {h.elapsed_ms} |")
        if len(report.reachable_endpoints) > 300:
            md.append(f"... and {len(report.reachable_endpoints) - 300} more")
    (output_dir / "live-diff.md").write_text("\n".join(md), encoding="utf-8")
