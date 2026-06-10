"""Graph mode driver — wires existing pipeline modules as Worklist handlers.

This is the opt-in `--graph` entrypoint. It runs the same scan as the linear
orchestrator but routes work through `Worklist` (§5) so we get:
  - canonical-form artifact identity (dedup across all phases)
  - deterministic priority + audit JSONL (`<out>/graph-audit.jsonl`)
  - terminal handler reserve (report always produced)
  - state-as-kind promotions (key → verified_key → enumerated_key)

The linear orchestrator remains the default; this lets us battle-test the
graph in production runs without risking regressions on the 13 existing
feature modules.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from urllib.parse import urlsplit

from ..logger import get_logger
from ..secrets.git_walker import walk_repository
from ..secrets.exporter import export_secrets
from .http_client import HttpClient
from .recon import run_recon
from .ref_discovery import discover_refs
from .object_engine import ObjectEngine
from .reconstructor import init_repo, reconstruct
from .scope_guard import ScopeContract, ScopeGuard
from .worklist import (
    Artifact,
    Budget,
    Ctx,
    Finding,
    HandlerResult,
    ResourceCost,
    Worklist,
)


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
class ReconHandler:
    """`host` → `endpoint` + `repo_reconstructed` (does the full read path)."""
    handler_id = "ReconHandler"
    handler_class = "recon"
    handles = {"host"}
    requires_consent = False
    estimated_cost = ResourceCost(http=200, wall_clock_s=10.0)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        log = ctx.log
        client: HttpClient = ctx.http_client
        out_dir: Path = ctx.output_dir

        # P1 — recon
        await client.calibrate_soft_404()
        recon = await run_recon(client)
        ctx.extra["recon"] = recon
        if not recon.exposed:
            return HandlerResult(status="skipped", cost=ResourceCost(http=10),
                                 notes="no .git exposure")

        # P2 — refs
        refs = await discover_refs(client)
        ctx.extra["refs"] = refs

        # P3 — objects
        git_dir = out_dir / ".git"
        engine = ObjectEngine(client, git_dir, log=lambda m: log and log.trace(m))
        packs, pack_shas = await engine.fetch_packs()
        seed = (set(refs.commits) | set(refs.reflog_old_commits) | set(pack_shas))
        await engine.bfs_expand(seed, max_rounds=10)

        # P4 — reconstruct
        init_repo(out_dir, git_dir)
        rebuild = reconstruct(out_dir / ".git")
        ctx.extra["rebuild"] = rebuild
        ctx.extra["packs"] = packs

        new_arts: list[Artifact] = [
            Artifact(kind="repo_reconstructed",
                     payload={"repo_dir": str(out_dir)},
                     severity="info"),
        ]
        return HandlerResult(
            status="ok",
            new_artifacts=new_arts,
            cost=ResourceCost(http=100, wall_clock_s=5.0),
            notes=(f"refs={len(refs.commits)} "
                   f"commits={len(rebuild.commits)} "
                   f"branches={len(rebuild.branches)}"),
        )


class SecretHuntHandler:
    """`repo_reconstructed` → `finding[]` + `key[]`."""
    handler_id = "SecretHuntHandler"
    handler_class = "secret_hunt"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=5.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("rebuild") is not None

    async def run(self, art, ctx):
        rebuild = ctx.extra["rebuild"]
        out_dir: Path = ctx.output_dir
        findings = walk_repository(
            out_dir, rebuild.commits, rebuild.dangling_commits, rebuild.dangling_blobs,
        )
        ctx.extra["findings"] = findings
        # Emit `key` artifacts for cred-like findings
        new_arts: list[Artifact] = []
        graph_findings: list[Finding] = []
        for f in findings:
            graph_findings.append(Finding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f"{f.rule_id} @ {f.file_path}:{f.line}",
                detail=f.redacted,
            ))
            if f.match:
                import hashlib
                kh = hashlib.sha256(f.match.encode("utf-8")).hexdigest()
                new_arts.append(Artifact(
                    kind="key",
                    payload={"key_material_hash": kh, "rule_id": f.rule_id},
                    severity=f.severity,
                ))
        return HandlerResult(
            status="ok", new_artifacts=new_arts, findings=graph_findings,
            cost=ResourceCost(wall_clock_s=2.0),
        )


class SecretsExporterHandler:
    """Terminal: writes secrets/ folder (§5.6.1)."""
    handler_id = "SecretsExporterHandler"
    handler_class = "terminal"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=1.0)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        out_dir: Path = ctx.output_dir
        findings = ctx.extra.get("findings", [])
        try:
            sec_dir = export_secrets(out_dir, findings, out_dir / "recovered_source")
            ctx.extra["secrets_dir"] = str(sec_dir)
        except Exception as e:
            return HandlerResult(status="failed", notes=str(e))
        return HandlerResult(status="ok", cost=ResourceCost(wall_clock_s=0.5))


class ReportWriterHandler:
    """Terminal: writes `graph-report.json` + the consolidated HTML report."""
    handler_id = "ReportWriterHandler"
    handler_class = "terminal"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=2.0)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        out_dir: Path = ctx.output_dir
        recon = ctx.extra.get("recon")
        rebuild = ctx.extra.get("rebuild")
        findings = ctx.extra.get("findings", [])
        report = {
            "target_url": ctx.target_url,
            "mode": "graph",
            "exposed": getattr(recon, "exposed", False),
            "commits": len(getattr(rebuild, "commits", []) or []),
            "branches": list(getattr(rebuild, "branches", []) or []),
            "findings": len(findings),
            "secrets_dir": ctx.extra.get("secrets_dir"),
            "generated_at": time.time(),
        }
        (out_dir / "graph-report.json").write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8",
        )
        # Try the consolidated HTML report too (best-effort)
        try:
            from ..report_html import write_html_report
            html_path = write_html_report(
                out_dir,
                scan_meta={"target": ctx.target_url, "mode": "graph"},
            )
            ctx.extra["html_report_path"] = str(html_path)
        except Exception:
            pass
        return HandlerResult(status="ok", cost=ResourceCost(wall_clock_s=1.0))


# ---------------------------------------------------------------------------
# Public entry: run_graph_scan()
# ---------------------------------------------------------------------------
@dataclass
class GraphScanReport:
    target_url: str
    output_dir: str
    seen: int
    handler_calls: int
    findings: int
    artifacts_by_kind: dict[str, int] = field(default_factory=dict)
    duration_s: float = 0.0
    audit_path: Optional[str] = None
    html_report_path: Optional[str] = None


async def run_graph_scan(
    target_url: str,
    output_dir: Path,
    *,
    timeout: float = 15.0,
    concurrency: int = 10,
    insecure_ssl: bool = False,
    allow_mutating: bool = False,
    proxy: Optional[str] = None,
) -> GraphScanReport:
    """Drive a full scan through the Worklist graph (`--graph` mode)."""
    log = get_logger()
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()

    # ScopeGuard setup
    contract = ScopeContract(
        allow_mutating=allow_mutating,
        interactive_consent=False,
    )
    primary = contract.add_host(target_url)
    for path in ("/info/refs", "/git-upload-pack",
                 "/.git/info/refs", "/.git/git-upload-pack"):
        contract.register_post_exact(
            primary.scheme, primary.host, primary.port, path,
        )
    audit_path = output_dir / "scope-audit.jsonl"
    guard = ScopeGuard(contract, audit_path=audit_path, log=log)

    client = HttpClient(
        base_url=target_url,
        timeout=timeout,
        concurrency=concurrency,
        insecure=insecure_ssl,
        proxy=proxy,
        scope_guard=guard,
    )

    ctx = Ctx(
        target_url=target_url,
        output_dir=output_dir,
        log=log,
        http_client=client,
        scope_guard=guard,
    )

    wl = Worklist(
        handlers=[
            ReconHandler(),
            SecretHuntHandler(),
            SecretsExporterHandler(),
            ReportWriterHandler(),
        ],
        ctx=ctx,
        budget=Budget(),
        concurrency=2,   # most handlers are sequential in this thin chain
        audit_path=output_dir / "graph-audit.jsonl",
    )

    # Seed the graph with the target host
    parts = urlsplit(target_url)
    await wl.submit(Artifact(
        kind="host",
        payload={
            "scheme": parts.scheme,
            "host": parts.hostname,
            "port": parts.port or (443 if parts.scheme == "https" else 80),
        },
        severity="info",
    ))

    try:
        result = await wl.run()
    finally:
        await client.close()
        guard.close()

    by_kind: dict[str, int] = {}
    for a in result.artifacts.values():
        by_kind[a.kind] = by_kind.get(a.kind, 0) + 1

    return GraphScanReport(
        target_url=target_url,
        output_dir=str(output_dir),
        seen=result.seen,
        handler_calls=result.handler_calls,
        findings=len(result.findings),
        artifacts_by_kind=by_kind,
        duration_s=time.monotonic() - started,
        audit_path=str(output_dir / "graph-audit.jsonl"),
        html_report_path=ctx.extra.get("html_report_path"),
    )
