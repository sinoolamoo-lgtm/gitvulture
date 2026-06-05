"""End-to-end orchestrator: runs the full GitVulture pipeline.

A single coroutine `run_scan()` drives all phases and emits progress events
through an optional callback so both the CLI (rich progress) and the web
dashboard (SSE/poll) can subscribe to the same state machine.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Optional

from ..ai.triage import summarize_findings_for_llm, triage
from ..logger import get_logger
from ..secrets.git_walker import walk_repository
from ..secrets.patterns import Finding
from ..secrets.verifier import verify_findings
from .escalation import EscalationEngine
from .http_client import HttpClient
from .index_parser import IndexEntry, parse_index
from .object_engine import ObjectEngine
from .recon import ReconResult, run_recon
from .ref_discovery import RefSet, discover_refs
from .reconstructor import RebuildResult, init_repo, reconstruct

ProgressCb = Callable[[dict], Optional[Awaitable[None]]]

PHASES = [
    "recon",
    "ref_discovery",
    "object_acquisition",
    "reconstruction",
    "secret_hunt",
    "verification",
    "ai_triage",
    "done",
]


@dataclass
class ScanOptions:
    target_url: str
    output_dir: Path
    ai_triage: bool = True
    verify_secrets: bool = False
    insecure_ssl: bool = False
    bypass_403: bool = True
    ua_rotate: bool = True
    proxy: Optional[str] = None
    proxy_list: list[str] = field(default_factory=list)
    rate_limit: float = 30.0
    concurrency: int = 20
    timeout: float = 15.0
    escalate: bool = False
    offensive: bool = False
    s3_hints: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target_url: str
    output_dir: str
    started_at: float
    finished_at: Optional[float] = None
    duration_s: Optional[float] = None
    recon: Optional[ReconResult] = None
    refs: Optional[RefSet] = None
    rebuild: Optional[RebuildResult] = None
    index_entries: list[IndexEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    ai_report: Optional[dict] = None
    escalation: Optional[dict] = None
    object_count: int = 0
    pack_count: int = 0
    waf: Optional[str] = None
    errors: list[str] = field(default_factory=list)
    phase: str = "init"

    def to_dict(self) -> dict:
        def _conv(o):
            if hasattr(o, "__dict__"):
                d = o.__dict__.copy()
                for k, v in list(d.items()):
                    if isinstance(v, set):
                        d[k] = sorted(v)
                    elif isinstance(v, Path):
                        d[k] = str(v)
                    elif isinstance(v, dict):
                        d[k] = {kk: _conv(vv) for kk, vv in v.items()}
                    elif isinstance(v, list):
                        d[k] = [_conv(x) for x in v]
                    elif hasattr(v, "__dict__"):
                        d[k] = _conv(v)
                if "raw_files" in d:
                    d.pop("raw_files", None)
                return d
            return o
        result = _conv(self)
        return result


async def _emit(cb: Optional[ProgressCb], event: dict) -> None:
    if cb is None:
        return
    try:
        ret = cb(event)
        if asyncio.iscoroutine(ret):
            await ret
    except Exception:
        pass


async def run_scan(
    opts: ScanOptions,
    progress: Optional[ProgressCb] = None,
) -> ScanResult:
    log = get_logger()
    started = time.time()
    opts.output_dir.mkdir(parents=True, exist_ok=True)
    git_dir = opts.output_dir / ".git"
    if git_dir.exists():
        shutil.rmtree(git_dir, ignore_errors=True)
    git_dir.mkdir(parents=True, exist_ok=True)

    log_lines: list[str] = []

    def _log(msg: str):
        # legacy callback for components that still take a `log=` function
        log_lines.append(msg)
        if progress:
            try:
                ret = progress({"type": "log", "msg": msg})
                if asyncio.iscoroutine(ret):
                    asyncio.create_task(ret)
            except Exception:
                pass
        # also surface as trace in the live stream
        log.trace(msg)

    client = HttpClient(
        base_url=opts.target_url,
        timeout=opts.timeout,
        concurrency=opts.concurrency,
        rate_limit=opts.rate_limit,
        insecure=opts.insecure_ssl,
        proxy=opts.proxy,
        proxy_list=opts.proxy_list,
        ua_rotate=opts.ua_rotate,
        bypass_403=opts.bypass_403,
        verbose_log=_log,
    )
    result = ScanResult(target_url=opts.target_url, output_dir=str(opts.output_dir),
                        started_at=started)

    try:
        # ----- Phase 1: Recon ------------------------------------------------
        result.phase = "recon"
        log.phase("PHASE 1  ::  RECONNAISSANCE")
        await client.calibrate_soft_404()
        await _emit(progress, {"type": "phase", "phase": "recon", "status": "running"})
        recon = await run_recon(client)
        result.recon = recon
        result.waf = recon.waf
        if not recon.exposed:
            result.errors.append("No .git exposure detected.")
            # If we still have S3 hints + escalate, jump straight to L16
            if opts.escalate and opts.s3_hints:
                await _emit(progress, {"type": "phase", "phase": "recon",
                                       "status": "skipped",
                                       "detail": "no .git, S3-only mode"})
                # Mark a synthetic refs/rebuild so downstream code doesn't crash
                from .ref_discovery import RefSet
                from .reconstructor import RebuildResult
                refs = RefSet()
                rebuild = RebuildResult(repo_dir=opts.output_dir)
                result.refs = refs
                result.rebuild = rebuild
                # Jump to Phase 8 (escalation only)
                result.phase = "escalation"
                esc_artifacts = {
                    "recon": asdict(recon),
                    "refs": {"branches": {}, "commits": []},
                    "index_entries": [],
                    "rebuild": {},
                    "s3_hints": opts.s3_hints,
                }
                from .escalation import EscalationEngine
                engine = EscalationEngine(
                    client, opts.target_url, esc_artifacts,
                    ai_session_id=f"gitvulture-esc-{int(started)}",
                    offensive=opts.offensive,
                    out_dir=opts.output_dir,
                    log=_log,
                    emit=lambda evt: _emit(progress, evt),
                )
                esc_report = await engine.run()
                def _ser(o):
                    if hasattr(o, "__dict__"):
                        return {k: _ser(v) for k, v in o.__dict__.items()}
                    if isinstance(o, (list, tuple)):
                        return [_ser(x) for x in o]
                    if isinstance(o, dict):
                        return {k: _ser(v) for k, v in o.items()}
                    if isinstance(o, set):
                        return sorted(o)
                    return o
                result.escalation = _ser(esc_report)
                for f in esc_report.new_findings:
                    result.findings.append(f)
                result.phase = "done"
                return result
            result.phase = "done"
            await _emit(progress, {"type": "phase", "phase": "recon", "status": "failed",
                                   "detail": "no .git exposure"})
            return result
        await _emit(progress, {"type": "phase", "phase": "recon", "status": "done",
                               "data": asdict(recon)})

        # ----- Phase 2: Ref discovery ---------------------------------------
        result.phase = "ref_discovery"
        log.phase("PHASE 2  ::  REF DISCOVERY")
        await _emit(progress, {"type": "phase", "phase": "ref_discovery", "status": "running"})
        refs = await discover_refs(client)
        result.refs = refs

        # Write discovered metadata files to local .git
        for name, content in refs.raw_files.items():
            p = git_dir / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)
        # Ensure HEAD always exists
        if not (git_dir / "HEAD").exists() and recon.head_ref:
            (git_dir / "HEAD").write_text(recon.head_ref + "\n")
        # CRITICAL: git refuses to recognize a directory without refs/.
        # Ensure refs/heads, refs/tags exist + materialize packed-refs as
        # loose ref files (some git versions fall back to loose refs).
        (git_dir / "refs" / "heads").mkdir(parents=True, exist_ok=True)
        (git_dir / "refs" / "tags").mkdir(parents=True, exist_ok=True)
        (git_dir / "refs" / "remotes").mkdir(parents=True, exist_ok=True)
        for ref_name, ref_sha in (refs.branches or {}).items():
            if not ref_sha or len(ref_sha) != 40:
                continue
            ref_path = git_dir / ref_name
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            if not ref_path.exists():
                ref_path.write_text(ref_sha + "\n")
        for ref_name, ref_sha in (refs.tags or {}).items():
            if not ref_sha or len(ref_sha) != 40:
                continue
            ref_path = git_dir / ref_name
            ref_path.parent.mkdir(parents=True, exist_ok=True)
            if not ref_path.exists():
                ref_path.write_text(ref_sha + "\n")
        await _emit(progress, {
            "type": "phase", "phase": "ref_discovery", "status": "done",
            "data": {
                "commits": len(refs.commits),
                "branches": len(refs.branches),
                "tags": len(refs.tags),
                "reflog_ghosts": len(refs.reflog_old_commits),
                "files": sorted(refs.discovered_files)[:50],
            }
        })

        # ----- Phase 3: Object acquisition ----------------------------------
        result.phase = "object_acquisition"
        log.phase("PHASE 3  ::  OBJECT ACQUISITION (packs + loose + BFS)")
        await _emit(progress, {"type": "phase", "phase": "object_acquisition", "status": "running"})
        engine = ObjectEngine(client, git_dir, log=_log)
        packs, pack_shas = await engine.fetch_packs()
        result.pack_count = len(packs)
        # Parse the index file (if we got it) — yields file paths + blob SHAs
        index_data = refs.raw_files.get("index", b"")
        if index_data:
            try:
                result.index_entries = parse_index(index_data)
                log.success(f"index parsed:  {len(result.index_entries)} tracked files")
            except Exception as e:
                log.warning(f"index parse error: {e}")
        index_blob_shas = {e.sha1 for e in result.index_entries}
        seed = (set(refs.commits) | set(refs.reflog_old_commits)
                | set(pack_shas) | index_blob_shas)
        all_objs = await engine.bfs_expand(seed, max_rounds=10)
        result.object_count = len([1 for sha in all_objs
                                   if (git_dir / "objects" / sha[:2] / sha[2:]).exists()])
        await _emit(progress, {
            "type": "phase", "phase": "object_acquisition", "status": "done",
            "data": {"packs": len(packs), "objects": result.object_count,
                     "index_files": len(result.index_entries)}
        })

        # ----- Phase 4: Reconstruction --------------------------------------
        result.phase = "reconstruction"
        log.phase("PHASE 4  ::  REPOSITORY RECONSTRUCTION")
        await _emit(progress, {"type": "phase", "phase": "reconstruction", "status": "running"})
        init_repo(opts.output_dir, git_dir)
        rebuild = reconstruct(opts.output_dir / ".git")
        result.rebuild = rebuild
        log.success(
            f"reconstruction: {len(rebuild.commits)} commits, "
            f"{len(rebuild.branches)} branches, "
            f"{len(rebuild.dangling_commits)} dangling commits, "
            f"{len(rebuild.dangling_blobs)} dangling blobs, "
            f"{len(rebuild.files_on_head)} files on HEAD"
        )
        await _emit(progress, {
            "type": "phase", "phase": "reconstruction", "status": "done",
            "data": {
                "commits": len(rebuild.commits),
                "branches": rebuild.branches,
                "tags": rebuild.tags,
                "dangling_commits": rebuild.dangling_commits,
                "dangling_blobs": len(rebuild.dangling_blobs),
                "fsck_errors": len(rebuild.fsck_errors),
                "head_branch": rebuild.head_branch,
                "files_on_head": rebuild.files_on_head[:50],
            }
        })

        # ----- Phase 5: Secret hunt -----------------------------------------
        result.phase = "secret_hunt"
        log.phase("PHASE 5  ::  SECRET HUNT (commits + dangling + reflog)")
        await _emit(progress, {"type": "phase", "phase": "secret_hunt", "status": "running"})
        findings = walk_repository(
            opts.output_dir,
            rebuild.commits,
            rebuild.dangling_commits,
            rebuild.dangling_blobs,
        )
        result.findings = findings
        for f in findings:
            log.secret_hit(f.rule_id, f.file_path, f.redacted, f.severity)
        if not findings:
            log.info("no secrets detected in commit history")
        await _emit(progress, {
            "type": "phase", "phase": "secret_hunt", "status": "done",
            "data": {"findings": len(findings)}
        })

        # ----- Phase 6: Live verification (OPT-IN) --------------------------
        if opts.verify_secrets and findings:
            result.phase = "verification"
            log.phase("PHASE 6  ::  LIVE SECRET VERIFICATION")
            await _emit(progress, {"type": "phase", "phase": "verification", "status": "running"})
            await verify_findings(findings)
            verified = sum(1 for f in findings if f.extra.get("verified"))
            log.success(f"verified {verified}/{len(findings)} secrets against live APIs")

        # ----- Phase 7: AI triage -------------------------------------------
        if opts.ai_triage:
            result.phase = "ai_triage"
            log.phase("PHASE 7  ::  AI TRIAGE (Claude)")
            log.ai("requesting strategic analysis from Claude Sonnet")
            await _emit(progress, {"type": "phase", "phase": "ai_triage", "status": "running"})
            f_summary = summarize_findings_for_llm(findings)
            recon_dict = asdict(recon) if recon else {}
            repo_summary = {
                "head_branch": rebuild.head_branch,
                "branches": rebuild.branches,
                "commits": [
                    {"sha": c.sha[:12], "author": c.author, "date": c.date,
                     "message": c.message, "files": c.files_changed[:10]}
                    for c in rebuild.commits[:30]
                ],
                "dangling_commits": rebuild.dangling_commits[:10],
            }
            ai = await triage(
                opts.target_url,
                recon_dict,
                repo_summary,
                f_summary,
                session_id=f"gitvulture-{int(started)}",
            )
            result.ai_report = ai
            if ai.get("error"):
                log.error(f"AI triage failed: {ai['error']}")
            else:
                log.success(
                    f"AI risk score: {ai.get('risk_score', '?')}, "
                    f"lab pattern: {ai.get('lab_pattern', 'none')}"
                )
                summary = ai.get("executive_summary", "")
                if summary:
                    log.info(f"AI summary: {summary[:200]}")
            await _emit(progress, {"type": "phase", "phase": "ai_triage", "status": "done",
                                   "data": ai})

        # ----- Phase 8: AI-driven escalation ladder -------------------------
        if opts.escalate:
            result.phase = "escalation"
            log.phase("PHASE 8  ::  ESCALATION LADDER (L1-L16)")
            await _emit(progress, {"type": "phase", "phase": "escalation", "status": "running"})
            from .escalation import EscalationEngine
            esc_artifacts = {
                "recon": asdict(recon) if recon else {},
                "refs": {
                    "branches": dict(refs.branches) if refs else {},
                    "commits": sorted(refs.commits)[:200] if refs else [],
                },
                "index_entries": [asdict(e) for e in result.index_entries],
                "rebuild": {
                    "branches": rebuild.branches if rebuild else [],
                    "commits": [c.sha for c in (rebuild.commits if rebuild else [])][:30],
                } if rebuild else {},
                "s3_hints": opts.s3_hints,
            }
            engine = EscalationEngine(
                client, opts.target_url, esc_artifacts,
                ai_session_id=f"gitvulture-esc-{int(started)}",
                offensive=opts.offensive,
                out_dir=opts.output_dir,
                log=_log,
                emit=lambda evt: _emit(progress, evt),
            )
            esc_report = await engine.run()

            def _ser(o):
                if hasattr(o, "__dict__"):
                    return {k: _ser(v) for k, v in o.__dict__.items()}
                if isinstance(o, (list, tuple)):
                    return [_ser(x) for x in o]
                if isinstance(o, dict):
                    return {k: _ser(v) for k, v in o.items()}
                if isinstance(o, set):
                    return sorted(o)
                return o
            result.escalation = _ser(esc_report)
            for f in esc_report.new_findings:
                result.findings.append(f)
            await _emit(progress, {"type": "phase", "phase": "escalation", "status": "done",
                                   "data": esc_report.summary})

        result.phase = "done"
        await _emit(progress, {"type": "phase", "phase": "done", "status": "done"})

    finally:
        await client.close()
        result.finished_at = time.time()
        result.duration_s = result.finished_at - result.started_at
        # Persist JSON report
        report_path = opts.output_dir / "gitvulture-report.json"
        try:
            report_path.write_text(json.dumps(result.to_dict(), default=str, indent=2))
        except Exception as e:
            result.errors.append(f"failed to write report: {e}")

    return result
