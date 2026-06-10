"""Graph-mode handler adapters for the opt-in escalation features
(D2/C3/C6/C7/C8/C9/D10/SAST).

Each adapter wraps an existing module's `run_*()` function and converts its
output into the canonical `Artifact[] + Finding[]` pair the Worklist
scheduler expects. They are registered conditionally based on the same
CLI flags the linear orchestrator uses, so `--graph` mode has full feature
parity (modulo the AI/LLM phases which still require explicit `--ai`).

All adapters consume `repo_reconstructed` (or `host` for D2/D10) as their
trigger artifact. They are NOT terminal — they emit promotable artifacts
(`key`, `host`, `cred`) so downstream handlers like CloudEnumHandler can
chain on `verified_key` → `enumerated_key` per §5.1 Trap 2.
"""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .worklist import Artifact, Finding, HandlerResult, ResourceCost


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _key_artifact_from_secret(
    secret: str, *, rule_id: str, severity: str = "high",
) -> Artifact:
    """Hash-only key artifact (raw material lives in `secrets/files/`)."""
    kh = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()
    return Artifact(
        kind="key",
        payload={"key_material_hash": kh, "rule_id": rule_id},
        severity=severity,  # type: ignore[arg-type]
    )


def _ok_no_op(notes: str = "") -> HandlerResult:
    return HandlerResult(status="skipped", notes=notes, cost=ResourceCost())


# ---------------------------------------------------------------------------
# SAST handler (C1)
# ---------------------------------------------------------------------------
class SastHandler:
    handler_id = "SastHandler"
    handler_class = "sast"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=30.0)

    async def can_handle(self, art, ctx):
        return bool(ctx.extra.get("enable_sast"))

    async def run(self, art, ctx):
        from ..sast import run_sast
        recovered = ctx.output_dir / "recovered_source"
        if not recovered.exists():
            return _ok_no_op("no recovered_source/")
        # SAST is CPU-bound; run in a worker thread
        report = await asyncio.to_thread(
            run_sast, recovered, ctx.output_dir, ctx.log,
        )
        ctx.extra["sast_report"] = report
        sinks = getattr(report, "sinks", []) or []
        findings = [
            Finding(
                rule_id=getattr(s, "rule_id", "sast"),
                severity=getattr(s, "severity", "medium"),
                title=f"SAST {getattr(s, 'rule_id', '?')} @ "
                      f"{getattr(s, 'file', '?')}:{getattr(s, 'line', '?')}",
                detail=getattr(s, "message", ""),
            )
            for s in sinks
        ]
        new_arts: list[Artifact] = []
        for s in sinks:
            new_arts.append(Artifact(
                kind="sast_sink",
                payload={
                    "rule_id": getattr(s, "rule_id", "sast"),
                    "file": getattr(s, "file", ""),
                    "function": getattr(s, "function", ""),
                    "line": getattr(s, "line", 0),
                },
                severity=getattr(s, "severity", "medium"),  # type: ignore[arg-type]
            ))
        return HandlerResult(
            status="ok",
            new_artifacts=new_arts,
            findings=findings,
            cost=ResourceCost(wall_clock_s=15.0),
            notes=f"{len(sinks)} sast sinks",
        )


# ---------------------------------------------------------------------------
# C6: CI/CD secrets handler
# ---------------------------------------------------------------------------
class CicdSecretsHandler:
    handler_id = "CicdSecretsHandler"
    handler_class = "secret_hunt"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=3.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_cicd", True)

    async def run(self, art, ctx):
        from .cicd_secrets import run_cicd_scan, write_cicd_report
        recovered = ctx.output_dir / "recovered_source"
        report = await asyncio.to_thread(run_cicd_scan, recovered, ctx.log)
        await asyncio.to_thread(write_cicd_report, report, ctx.output_dir)
        new_arts: list[Artifact] = []
        findings: list[Finding] = []
        for a in report.artifacts:
            if getattr(a, "kind", "").startswith("env_literal"):
                new_arts.append(_key_artifact_from_secret(
                    a.value, rule_id=f"cicd:{a.platform}", severity=a.severity,
                ))
            findings.append(Finding(
                rule_id=f"cicd:{a.platform}:{a.kind}",
                severity=a.severity,
                title=f"{a.platform} {a.kind} in {a.file}",
                detail=f"{a.name} = {a.value[:60]}",
            ))
        ctx.extra["cicd_report"] = report
        return HandlerResult(
            status="ok", new_artifacts=new_arts, findings=findings,
            cost=ResourceCost(wall_clock_s=1.0),
            notes=f"{report.files_scanned} configs, {len(report.artifacts)} artifacts",
        )


# ---------------------------------------------------------------------------
# C7: JWT forge handler
# ---------------------------------------------------------------------------
class JwtForgeHandler:
    handler_id = "JwtForgeHandler"
    handler_class = "verify"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(wall_clock_s=2.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_jwt_forge", True)

    async def run(self, art, ctx):
        from .jwt_forge import analyze_jwts, find_jwts_in_text
        recovered = ctx.output_dir / "recovered_source"
        if not recovered.exists():
            return _ok_no_op("no recovered_source/")
        # Collect candidate JWTs from text files
        tokens: list[str] = []
        for f in recovered.rglob("*"):
            if not f.is_file() or f.stat().st_size > 1_000_000:
                continue
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
            except (OSError, ValueError):
                continue
            tokens.extend(find_jwts_in_text(txt, max_n=20))
        tokens = list(dict.fromkeys(tokens))[:50]
        if not tokens:
            return _ok_no_op("no JWTs found")
        analyses = await asyncio.to_thread(
            analyze_jwts, tokens, ctx.output_dir,
        )
        new_arts: list[Artifact] = []
        findings: list[Finding] = []
        for a in analyses:
            sev = "critical" if getattr(a, "cracked_secret", None) else "high"
            findings.append(Finding(
                rule_id="jwt-forge",
                severity=sev,
                title=f"JWT alg={getattr(a, 'alg', '?')} "
                      f"{'CRACKED' if getattr(a, 'cracked_secret', None) else 'forgeable'}",
                detail=getattr(a, "raw", "")[:80],
            ))
            if getattr(a, "cracked_secret", None):
                new_arts.append(_key_artifact_from_secret(
                    a.cracked_secret, rule_id="jwt-hs256-cracked", severity="critical",
                ))
        return HandlerResult(
            status="ok", new_artifacts=new_arts, findings=findings,
            cost=ResourceCost(wall_clock_s=1.0),
            notes=f"{len(analyses)} JWTs analyzed",
        )


# ---------------------------------------------------------------------------
# C8: Live diff handler
# ---------------------------------------------------------------------------
class LiveDiffHandler:
    handler_id = "LiveDiffHandler"
    handler_class = "live_diff"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=50, wall_clock_s=10.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_live_diff", True)

    async def run(self, art, ctx):
        from .live_diff import run_live_diff, write_live_diff_report
        endpoints = ctx.extra.get("endpoints", [])
        recovered = ctx.output_dir / "recovered_source"
        if not endpoints or not recovered.exists():
            return _ok_no_op("no endpoints or recovered_source/")
        report = await run_live_diff(
            ctx.http_client, ctx.target_url, endpoints, recovered, log=ctx.log,
        )
        await asyncio.to_thread(write_live_diff_report, report, ctx.output_dir)
        findings = [
            Finding(
                rule_id="live-diff",
                severity=getattr(h, "severity", "medium"),
                title=f"live source diff @ {getattr(h, 'url', '?')}",
                detail=getattr(h, "summary", ""),
            )
            for h in (getattr(report, "hits", []) or [])
        ]
        return HandlerResult(
            status="ok", findings=findings,
            cost=ResourceCost(http=30, wall_clock_s=5.0),
            notes=f"{len(findings)} live-diff hits",
        )


# ---------------------------------------------------------------------------
# C9: Git pivots handler
# ---------------------------------------------------------------------------
class GitPivotsHandler:
    handler_id = "GitPivotsHandler"
    handler_class = "ref_discovery"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=0, wall_clock_s=2.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_git_pivots", True)

    async def run(self, art, ctx):
        from .git_pivots import run_git_pivots, write_pivots_report
        recovered = ctx.output_dir / "recovered_source"
        if not recovered.exists():
            return _ok_no_op("no recovered_source/")
        primary_host = urlsplit(ctx.target_url).hostname or ""
        pivots = await asyncio.to_thread(
            run_git_pivots, recovered, primary_host,
        )
        await asyncio.to_thread(write_pivots_report, pivots, ctx.output_dir)
        new_arts: list[Artifact] = []
        findings: list[Finding] = []
        # Submodules / sourcemaps → new host candidates
        for sm in (getattr(pivots, "submodules", []) or []):
            host = sm.get("host")
            if host:
                new_arts.append(Artifact(
                    kind="host",
                    payload={"scheme": "https", "host": host, "port": 443},
                    severity="hint",
                ))
        for h in (getattr(pivots, "extra_hosts", []) or []):
            new_arts.append(Artifact(
                kind="host",
                payload={"scheme": "https", "host": h, "port": 443},
                severity="hint",
            ))
        n_sm = len(getattr(pivots, "submodules", []) or [])
        n_sm_hosts = sum(1 for sm in (getattr(pivots, "submodules", []) or [])
                         if sm.get("host"))
        n_xh = len(getattr(pivots, "extra_hosts", []) or [])
        if n_sm + n_xh:
            findings.append(Finding(
                rule_id="git-pivots",
                severity="medium",
                title=f"{n_sm} submodule(s) + {n_xh} extra host(s) discovered",
            ))
        return HandlerResult(
            status="ok", new_artifacts=new_arts, findings=findings,
            cost=ResourceCost(wall_clock_s=1.0),
            notes=f"submodules={n_sm} ({n_sm_hosts} with host) extra_hosts={n_xh}",
        )


# ---------------------------------------------------------------------------
# D2: Origin finder handler
# ---------------------------------------------------------------------------
class OriginFinderHandler:
    handler_id = "OriginFinderHandler"
    handler_class = "recon"
    handles = {"host"}
    requires_consent = False
    estimated_cost = ResourceCost(http=20, wall_clock_s=15.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_origin_finder", False)

    async def run(self, art, ctx):
        from .origin_finder import discover_origins, write_origin_report
        report = await discover_origins(
            ctx.target_url, http_client=ctx.http_client, log=ctx.log,
        )
        await asyncio.to_thread(write_origin_report, report, ctx.output_dir)
        new_arts: list[Artifact] = []
        findings: list[Finding] = []
        for c in (getattr(report, "candidates", []) or []):
            score = float(getattr(c, "similarity", 0.0) or 0.0)
            sev = "high" if score >= 0.8 else "medium"
            new_arts.append(Artifact(
                kind="origin_candidate",
                payload={
                    "scheme": getattr(c, "scheme", "https"),
                    "host": getattr(c, "host", ""),
                    "port": getattr(c, "port", 443),
                },
                severity=sev,  # type: ignore[arg-type]
                confidence=score,
            ))
            findings.append(Finding(
                rule_id="origin-discovery",
                severity=sev,
                title=f"origin candidate {getattr(c, 'host', '?')} "
                      f"(simhash sim={score:.2f})",
            ))
        return HandlerResult(
            status="ok", new_artifacts=new_arts, findings=findings,
            cost=ResourceCost(http=20, wall_clock_s=10.0),
            notes=f"{len(new_arts)} origin candidates",
        )


# ---------------------------------------------------------------------------
# D10: WebDAV handler
# ---------------------------------------------------------------------------
class WebdavHandler:
    handler_id = "WebdavHandler"
    handler_class = "recon"
    handles = {"host"}
    requires_consent = False
    estimated_cost = ResourceCost(http=10, wall_clock_s=5.0)

    async def can_handle(self, art, ctx):
        return ctx.extra.get("enable_webdav", False)

    async def run(self, art, ctx):
        from .webdav import run_webdav, write_webdav_report
        report = await run_webdav(ctx.http_client, ctx.target_url, log=ctx.log)
        await asyncio.to_thread(write_webdav_report, report, ctx.output_dir)
        findings: list[Finding] = []
        if getattr(report, "enabled", False):
            findings.append(Finding(
                rule_id="webdav-enabled",
                severity="high",
                title=f"WebDAV enabled at {ctx.target_url}",
                detail=f"methods={getattr(report, 'methods', [])}",
            ))
        return HandlerResult(
            status="ok", findings=findings,
            cost=ResourceCost(http=10, wall_clock_s=2.0),
            notes=f"webdav_enabled={getattr(report, 'enabled', False)}",
        )


# ---------------------------------------------------------------------------
# C3: Cloud enum handler (terminal — runs from reserve)
# ---------------------------------------------------------------------------
class CloudEnumHandler:
    handler_id = "CloudEnumHandler"
    handler_class = "verify"
    handles = {"key", "verified_key"}
    requires_consent = True
    estimated_cost = ResourceCost(http=30, wall_clock_s=15.0)

    async def can_handle(self, art, ctx):
        # Only run for keys whose rule_id hints at a cloud provider
        if not ctx.extra.get("enable_cloud_enum", False):
            return False
        rule = art.payload.get("rule_id", "") if art.payload else ""
        return any(p in rule.lower()
                   for p in ("aws", "github", "gitlab", "slack", "stripe"))

    async def run(self, art, ctx):
        # The handler doesn't have the raw key material — it lives in
        # secrets/files/. For graph mode we expose this as a no-op stub
        # that emits a "needs-credentials" finding so users know to enable
        # explicit --cloud-enum + --secrets-export in linear mode.
        return HandlerResult(
            status="skipped",
            findings=[Finding(
                rule_id="cloud-enum-deferred",
                severity="hint",
                title=f"Cloud-enum for {art.payload.get('rule_id', '?')} "
                      f"requires raw key material — run linear mode "
                      f"with --cloud-enum",
            )],
            cost=ResourceCost(),
            notes="raw key material not bound to graph artifact",
        )


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------
def all_optin_handlers() -> list[Any]:
    """Return one instance of every adapter (registration is gated by
    `Handler.can_handle()`, which inspects `ctx.extra.enable_*` flags)."""
    return [
        SastHandler(),
        CicdSecretsHandler(),
        JwtForgeHandler(),
        LiveDiffHandler(),
        GitPivotsHandler(),
        OriginFinderHandler(),
        WebdavHandler(),
        CloudEnumHandler(),
    ]


__all__ = [
    "SastHandler", "CicdSecretsHandler", "JwtForgeHandler",
    "LiveDiffHandler", "GitPivotsHandler", "OriginFinderHandler",
    "WebdavHandler", "CloudEnumHandler", "all_optin_handlers",
]
