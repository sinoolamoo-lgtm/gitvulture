"""Worklist Graph scheduler (ARCHITECTURE.md §5).

This is the spec-mandated replacement for the linear `EscalationEngine.run()`
pipeline. The scheduler enforces:

  - Canonical-form identity (§5.1, Trap 1): an artifact id is derived from a
    whitelist of identity-defining fields per kind. Metadata (severity,
    confidence, lineage, …) is EXCLUDED so the same logical artifact across
    runs collapses to the same id.

  - State-as-kind (§5.1, Trap 2): promotions are graph edges between distinct
    artifact kinds (`key → verified_key → enumerated_key`), never metadata
    mutation on the same artifact. This prevents the dedup paradox.

  - Deterministic priority + monotonic seq tie-break (§5.5): no wall-clock
    in the priority key. Same SEED → identical task ordering for replay.

  - Budget reserve for terminal handlers (§5.6, Trap 4): a sub-budget is
    held back from general handlers; only handlers in `TERMINAL_HANDLERS`
    may draw from it. Guarantees a (partial) report on budget exhaustion.

  - Cycle guard (§5.4): a parent.origin_lineage chain prevents A→B→A loops.
    `reenqueue_depth` capped at 3 per lineage chain.

  - Visited-set termination (§5.7): queue-empty AND no in-flight for K=3
    scheduler ticks, OR budget exhausted, OR SIGINT.

The scheduler is wire-compatible with `ScopeGuard.authorize_handler()` from
§2.1.1; it asks the guard before every handler dispatch.

Object acquisition is NOT atomized (§5.8, Trap 3) — `ObjectEngineHandler`
keeps its BFS internal and emits ONLY coarse artifacts (`repo_reconstructed`,
findings, sast sinks). Scheduler memory stays O(escalation surface).
"""
from __future__ import annotations

import asyncio
import hashlib
import heapq
import json
import time
from dataclasses import dataclass, field, replace
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterable,
    Literal,
    Optional,
    Protocol,
    runtime_checkable,
)


ArtifactId = str   # sha256(canonical_form)[:16]


# ---------------------------------------------------------------------------
# Canonical-form whitelist (§5.1, Trap 1)
# ---------------------------------------------------------------------------
CANONICAL_FIELDS: dict[str, frozenset[str]] = {
    "host":                       frozenset({"scheme", "host", "port"}),
    "endpoint":                   frozenset({"method", "normalized_url"}),
    "blob":                       frozenset({"sha"}),
    "commit":                     frozenset({"sha"}),
    "ref":                        frozenset({"name", "sha"}),
    "finding":                    frozenset({"rule_id", "file_path", "line_no", "match_hash"}),
    "key":                        frozenset({"key_material_hash"}),
    "verified_key":               frozenset({"key_material_hash"}),
    "enumerated_key":             frozenset({"key_material_hash"}),
    "sast_sink":                  frozenset({"rule_id", "file", "function", "line"}),
    "ssrf_primitive_unconfirmed": frozenset({"endpoint_id", "param"}),
    "ssrf_primitive":             frozenset({"endpoint_id", "param"}),
    "repo_reconstructed":         frozenset({"repo_dir"}),
    "dangling_blob":              frozenset({"sha"}),
    "dangling_commit":            frozenset({"sha"}),
    "fingerprinted_endpoint":     frozenset({"method", "normalized_url"}),
    "confirmed_exploit":          frozenset({"finding_id"}),
    "cred":                       frozenset({"username", "service"}),
    "waf_profile":                frozenset({"host_id"}),
    "origin_candidate":           frozenset({"scheme", "host", "port"}),
    "sourcemap":                  frozenset({"url"}),
}

# Fields that must NEVER influence identity (Trap 1)
METADATA_FIELDS_EXCLUDED = frozenset({
    "severity", "confidence", "created_at", "origin_lineage", "extra",
    "cost", "verified", "notes", "reachable",
})


# ---------------------------------------------------------------------------
# Priority tables (§5.5)
# ---------------------------------------------------------------------------
SEVERITY_PRIO: dict[str, int] = {
    "critical": 0, "high": 10, "medium": 20,
    "low": 30, "hint": 40, "info": 50,
}
HANDLER_CLASS_PRIO: dict[str, int] = {
    "recon": 0, "ref_discovery": 1, "smart_http": 1,
    "object_acq": 2, "reconstruct": 3, "secret_hunt": 4,
    "verify": 5, "sast": 5, "live_diff": 5,
    "escalation": 6, "ai_probe": 7, "exploit_roadmap": 8,
    "terminal": 9,
}

Severity = Literal["critical", "high", "medium", "low", "hint", "info"]


# ---------------------------------------------------------------------------
# Resource accounting (§5.6)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ResourceCost:
    http: int = 0
    llm_tokens: int = 0
    wall_clock_s: float = 0.0

    def __add__(self, other: "ResourceCost") -> "ResourceCost":
        return ResourceCost(
            http=self.http + other.http,
            llm_tokens=self.llm_tokens + other.llm_tokens,
            wall_clock_s=self.wall_clock_s + other.wall_clock_s,
        )

    def fits_in(self, b: "ResourceCost") -> bool:
        return (self.http <= b.http
                and self.llm_tokens <= b.llm_tokens
                and self.wall_clock_s <= b.wall_clock_s)


_DEFAULT_FLOOR = ResourceCost(http=10, llm_tokens=0, wall_clock_s=1.0)


class BudgetReserveViolation(Exception):
    """Non-terminal handler tried to draw from the reserve."""


@dataclass
class Budget:
    """§5.6 — separate report-reserve for terminal handlers."""
    max_wall_clock_s: float = 1800.0
    max_http_requests: int = 50_000
    max_llm_tokens: int = 500_000
    max_handler_calls: int = 10_000

    report_reserve: ResourceCost = field(
        default_factory=lambda: ResourceCost(http=2_500, llm_tokens=20_000, wall_clock_s=60.0),
    )

    spent: ResourceCost = field(default_factory=ResourceCost)
    handler_calls: int = 0
    started_at: float = field(default_factory=time.monotonic)

    @property
    def remaining_total(self) -> ResourceCost:
        return ResourceCost(
            http=max(0, self.max_http_requests - self.spent.http),
            llm_tokens=max(0, self.max_llm_tokens - self.spent.llm_tokens),
            wall_clock_s=max(
                0.0,
                self.max_wall_clock_s - (time.monotonic() - self.started_at),
            ),
        )

    @property
    def remaining_non_reserve(self) -> ResourceCost:
        tot = self.remaining_total
        return ResourceCost(
            http=max(0, tot.http - self.report_reserve.http),
            llm_tokens=max(0, tot.llm_tokens - self.report_reserve.llm_tokens),
            wall_clock_s=max(0.0, tot.wall_clock_s - self.report_reserve.wall_clock_s),
        )

    def can_afford(self, cost: ResourceCost, *, terminal: bool = False) -> bool:
        if self.handler_calls >= self.max_handler_calls:
            return False
        avail = self.remaining_total if terminal else self.remaining_non_reserve
        return cost.fits_in(avail)

    def consume(self, cost: ResourceCost, *, terminal: bool = False) -> None:
        # Sanity: a non-terminal that ends up exceeding the non-reserve cap
        # eats into the reserve — raise so the worker can kill it.
        if not terminal:
            non_res = self.remaining_non_reserve
            if not cost.fits_in(non_res):
                raise BudgetReserveViolation(
                    "non-terminal handler exceeded non-reserve budget "
                    f"(cost={cost}, remaining_non_reserve={non_res})"
                )
        self.spent = self.spent + cost
        self.handler_calls += 1

    def exhausted(self) -> bool:
        return (self.handler_calls >= self.max_handler_calls
                or self.remaining_total.http <= 0
                or self.remaining_total.wall_clock_s <= 0.0)


# ---------------------------------------------------------------------------
# Artifact + Task + HandlerResult (§5.2)
# ---------------------------------------------------------------------------
def _canonical_id(kind: str, payload: dict) -> ArtifactId:
    """sha256(canonical_form)[:16] — pure function of identity fields."""
    whitelist = CANONICAL_FIELDS.get(kind)
    if whitelist is None:
        # Unknown kind: fall back to the full sorted payload (still
        # deterministic, but safer to register kinds explicitly).
        ident_keys = sorted(k for k in payload.keys()
                            if k not in METADATA_FIELDS_EXCLUDED)
    else:
        ident_keys = sorted(whitelist)
    body = {"_kind": kind}
    for k in ident_keys:
        if k in payload:
            body[k] = payload[k]
    raw = json.dumps(body, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Artifact:
    """A typed node in the worklist graph (§5.2)."""
    kind: str
    payload: dict
    id: ArtifactId = ""
    severity: Severity = "info"
    confidence: float = 1.0
    origin_lineage: tuple[ArtifactId, ...] = ()
    created_at: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        # Compute id post-creation (the field is frozen → use object.__setattr__).
        if not self.id:
            object.__setattr__(self, "id", _canonical_id(self.kind, self.payload))
        # Cap lineage at 32 to bound memory (§0.1 glossary).
        if len(self.origin_lineage) > 32:
            object.__setattr__(self, "origin_lineage", self.origin_lineage[-32:])


@dataclass
class Task:
    seq: int
    handler_id: str
    artifact_id: ArtifactId
    priority: int
    attempt: int = 0
    reenqueue_depth: int = 0
    parent_task_seq: Optional[int] = None


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    detail: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class HandlerResult:
    status: Literal["ok", "skipped", "failed", "retry"]
    new_artifacts: list[Artifact] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    cost: ResourceCost = field(default_factory=ResourceCost)
    notes: str = ""


# ---------------------------------------------------------------------------
# Handler protocol (§5.3)
# ---------------------------------------------------------------------------
@runtime_checkable
class Handler(Protocol):
    handler_id: str
    handler_class: str
    handles: set[str]
    requires_consent: bool
    estimated_cost: Optional[ResourceCost]

    async def can_handle(self, artifact: Artifact, ctx: "Ctx") -> bool: ...
    async def run(self, artifact: Artifact, ctx: "Ctx") -> HandlerResult: ...


# Terminal handlers always run from `Budget.report_reserve` (§5.6.1).
TERMINAL_HANDLERS: frozenset[str] = frozenset({
    "ExploitRoadmapHandler",
    "ReportWriterHandler",
    "SecretsExporterHandler",
    "GraphDotWriterHandler",
    "AuditFlushHandler",
})


# ---------------------------------------------------------------------------
# Cycle / depth guard
# ---------------------------------------------------------------------------
MAX_REENQUEUE_DEPTH = 3


def priority(art: Artifact, handler: Handler) -> int:
    """§5.5 — deterministic, no wall-clock."""
    sev = SEVERITY_PRIO.get(art.severity, 50)
    cls = HANDLER_CLASS_PRIO.get(handler.handler_class, 9)
    return sev * 100 + cls * 10


# ---------------------------------------------------------------------------
# Execution context
# ---------------------------------------------------------------------------
@dataclass
class Ctx:
    """Read-only-ish dependency bag passed to every handler."""
    target_url: str
    output_dir: Any   # pathlib.Path
    log: Any = None
    http_client: Any = None
    scope_guard: Any = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Audit JSONL (§5.4 + §5.10)
# ---------------------------------------------------------------------------
class _GraphAudit:
    """Append-only JSONL audit of every scheduler decision."""

    def __init__(self, path: Optional[Any]):
        self.path = path
        self._fh = None
        if path is not None:
            try:
                self._fh = open(path, "a", encoding="utf-8")
            except OSError:
                self._fh = None

    def write(self, record: dict) -> None:
        if self._fh is None:
            return
        try:
            self._fh.write(json.dumps(record, default=str) + "\n")
            self._fh.flush()
        except OSError:
            pass

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None


# ---------------------------------------------------------------------------
# Worklist scheduler (§5.4)
# ---------------------------------------------------------------------------
class Worklist:
    """Async priority-queue worklist driving the artifact graph."""

    def __init__(
        self,
        handlers: Iterable[Handler],
        ctx: Ctx,
        budget: Optional[Budget] = None,
        concurrency: int = 4,
        audit_path: Optional[Any] = None,
        checkpoint_path: Optional[Any] = None,
        checkpoint_every: int = 100,
        resume_from: Optional[Any] = None,
    ):
        self.handlers: dict[str, Handler] = {h.handler_id: h for h in handlers}
        # Reverse map: artifact kind → list of handler ids
        self._by_kind: dict[str, list[str]] = {}
        for h in self.handlers.values():
            for k in h.handles:
                self._by_kind.setdefault(k, []).append(h.handler_id)
        self.ctx = ctx
        self.budget = budget or Budget()
        self.concurrency = max(1, concurrency)

        # State
        self.seen_artifacts: dict[ArtifactId, Artifact] = {}
        self.visited: set[tuple[str, ArtifactId]] = set()
        self._queue: list[tuple[int, int, Task]] = []
        self._seq: int = 0
        self._in_flight: int = 0
        self._cond = asyncio.Condition()
        self.findings: list[Finding] = []
        self._audit = _GraphAudit(audit_path)
        self._stopping = False
        self._idle_ticks = 0
        self._completed_tasks = 0
        self._recent_transitions: list[dict] = []

        # Checkpoint / resume (§5.11)
        self._checkpoint_path = checkpoint_path
        self._checkpoint_every = max(1, checkpoint_every) if checkpoint_every else 0
        if resume_from is not None:
            self._restore(resume_from)

        # SIGUSR1 live state dump (§5.10) — non-Windows only
        self._install_sigusr1()

    # --- public API -------------------------------------------------------
    async def submit(
        self,
        artifact: Artifact,
        parent_task: Optional[Task] = None,
    ) -> None:
        """Add an artifact and enqueue every interested handler."""
        # 1. Canonicalize (already done at __post_init__).
        # 2. Identity-merge: same id → keep first, merge lineage.
        existing = self.seen_artifacts.get(artifact.id)
        if existing is not None:
            # Same logical artifact — merge lineage, keep stricter severity.
            merged_lineage = tuple(
                dict.fromkeys((*existing.origin_lineage, *artifact.origin_lineage))
            )[-32:]
            merged_sev = (artifact.severity
                          if SEVERITY_PRIO.get(artifact.severity, 50)
                          < SEVERITY_PRIO.get(existing.severity, 50)
                          else existing.severity)
            artifact = Artifact(
                kind=existing.kind,
                payload=existing.payload,
                id=existing.id,
                severity=merged_sev,
                confidence=max(existing.confidence, artifact.confidence),
                origin_lineage=merged_lineage,
                created_at=existing.created_at,
            )
            self.seen_artifacts[artifact.id] = artifact
            self._audit.write({"event": "merge", "artifact_id": artifact.id})
            return

        # 3. Cycle guard
        if parent_task is not None and artifact.id in (parent_task.artifact_id,):
            self._audit.write({
                "event": "loop_guard_tripped",
                "artifact_id": artifact.id,
                "via_task_seq": parent_task.seq,
            })
            return

        self.seen_artifacts[artifact.id] = artifact

        # 4. Enqueue one task per interested handler (skip already-visited)
        handler_ids = self._by_kind.get(artifact.kind, [])
        for hid in handler_ids:
            if (hid, artifact.id) in self.visited:
                continue
            handler = self.handlers[hid]
            try:
                if not await handler.can_handle(artifact, self.ctx):
                    continue
            except Exception as e:
                self._audit.write({
                    "event": "can_handle_error",
                    "handler": hid, "artifact_id": artifact.id, "error": str(e),
                })
                continue
            self._seq += 1
            t = Task(
                seq=self._seq,
                handler_id=hid,
                artifact_id=artifact.id,
                priority=priority(artifact, handler),
                reenqueue_depth=(parent_task.reenqueue_depth + 1
                                 if parent_task else 0),
                parent_task_seq=parent_task.seq if parent_task else None,
            )
            if t.reenqueue_depth > MAX_REENQUEUE_DEPTH:
                self._audit.write({
                    "event": "depth_cap",
                    "task_seq": t.seq, "handler": hid,
                })
                continue
            heapq.heappush(self._queue, (t.priority, t.seq, t))
            self._audit.write({
                "event": "enqueue", "task_seq": t.seq, "handler": hid,
                "artifact_id": artifact.id, "priority": t.priority,
            })
        # Wake any blocked worker
        async with self._cond:
            self._cond.notify_all()

    async def run(self) -> "RunReport":
        """Drive the graph to quiescence."""
        workers = [asyncio.create_task(self._worker(i))
                   for i in range(self.concurrency)]
        await asyncio.gather(*workers, return_exceptions=True)
        # Final checkpoint + audit state-dump (§5.11 + §5.10)
        if self._checkpoint_path is not None:
            self._write_checkpoint()
        try:
            self._audit.write({"event": "final_state", "state": self.dump_state()})
        except Exception:
            pass
        self._audit.close()
        return RunReport(
            seen=len(self.seen_artifacts),
            handler_calls=self.budget.handler_calls,
            spent=self.budget.spent,
            findings=list(self.findings),
            artifacts=dict(self.seen_artifacts),
        )

    # --- internals --------------------------------------------------------
    async def _worker(self, wid: int) -> None:
        while not self._stopping:
            task = await self._dequeue_or_idle()
            if task is None:
                return
            self._in_flight += 1
            try:
                await self._run_task(task)
            finally:
                self._in_flight -= 1
                async with self._cond:
                    self._cond.notify_all()

    async def _dequeue_or_idle(self) -> Optional[Task]:
        async with self._cond:
            while True:
                if self._stopping:
                    return None
                if self.budget.exhausted():
                    self._stopping = True
                    self._cond.notify_all()
                    return None
                if self._queue:
                    _prio, _seq, t = heapq.heappop(self._queue)
                    return t
                if self._in_flight == 0:
                    # Termination debounce (K=3)
                    self._idle_ticks += 1
                    if self._idle_ticks >= 3:
                        self._stopping = True
                        self._cond.notify_all()
                        return None
                # Block until anything changes
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=0.05)
                except asyncio.TimeoutError:
                    continue
                else:
                    self._idle_ticks = 0

    async def _run_task(self, task: Task) -> None:
        handler = self.handlers.get(task.handler_id)
        if handler is None:
            return
        artifact = self.seen_artifacts.get(task.artifact_id)
        if artifact is None:
            return

        # Handler-level scope-guard pre-check (§2.1.1)
        if self.ctx.scope_guard is not None and hasattr(
            self.ctx.scope_guard, "authorize_handler"
        ):
            try:
                decision = self.ctx.scope_guard.authorize_handler(handler, artifact)
                allowed = getattr(decision, "allowed", True)
                if not allowed:
                    self._audit.write({
                        "event": "denied", "task_seq": task.seq,
                        "handler": handler.handler_id,
                        "reason": getattr(decision, "reason", "denied"),
                    })
                    return
            except Exception:
                pass  # guard absent → permissive

        # Budget pre-check (floor estimate if no declared cost)
        est = handler.estimated_cost or _DEFAULT_FLOOR
        terminal = handler.__class__.__name__ in TERMINAL_HANDLERS
        if not self.budget.can_afford(est, terminal=terminal):
            self._audit.write({
                "event": "budget_skip", "task_seq": task.seq,
                "handler": handler.handler_id, "terminal": terminal,
            })
            self.visited.add((handler.handler_id, artifact.id))
            return

        # Mark visited BEFORE run so reentrancy can't re-enqueue this pair
        self.visited.add((handler.handler_id, artifact.id))

        # Run with retry/backoff
        try:
            result = await handler.run(artifact, self.ctx)
        except Exception as e:
            if task.attempt < 2:
                task.attempt += 1
                # Re-push with same seq for stable priority ordering
                heapq.heappush(self._queue, (task.priority, task.seq, task))
                await asyncio.sleep(0.1 * (2 ** task.attempt))
                self._audit.write({
                    "event": "retry", "task_seq": task.seq,
                    "handler": handler.handler_id, "error": str(e),
                })
                return
            self._audit.write({
                "event": "failed", "task_seq": task.seq,
                "handler": handler.handler_id, "error": str(e),
            })
            return

        # Account
        try:
            self.budget.consume(result.cost or est, terminal=terminal)
        except BudgetReserveViolation as e:
            self._audit.write({
                "event": "reserve_violation",
                "task_seq": task.seq, "handler": handler.handler_id,
                "error": str(e),
            })
            self._stopping = True
            return

        # Children + findings
        for new in result.new_artifacts:
            # Stamp lineage if missing
            if not new.origin_lineage:
                new = replace(
                    new,
                    origin_lineage=(*artifact.origin_lineage, artifact.id)[-32:],
                )
            await self.submit(new, parent_task=task)
        for f in result.findings:
            self.findings.append(f)

        self._audit.write({
            "event": "ok", "task_seq": task.seq,
            "handler": handler.handler_id,
            "new_artifacts": [a.id for a in result.new_artifacts],
            "findings": len(result.findings),
        })

        # Track for SIGUSR1 dumps & checkpoint trigger
        self._recent_transitions.append({
            "task_seq": task.seq,
            "handler": handler.handler_id,
            "artifact_id": artifact.id,
            "status": result.status,
            "new_artifacts": len(result.new_artifacts),
        })
        if len(self._recent_transitions) > 20:
            self._recent_transitions = self._recent_transitions[-20:]
        self._completed_tasks += 1
        if (self._checkpoint_path is not None
                and self._checkpoint_every
                and self._completed_tasks % self._checkpoint_every == 0):
            self._write_checkpoint()

    # ----- §5.10 observability ----------------------------------------------
    def dump_state(self) -> dict:
        """Snapshot of current scheduler state — used by SIGUSR1 and the
        interactive `graph` command (§5.10)."""
        # Top-10 pending priorities (peek without mutating heap)
        top10 = sorted(self._queue)[:10]
        top10_view = [
            {"priority": p, "seq": s, "handler": t.handler_id,
             "artifact_id": t.artifact_id}
            for p, s, t in top10
        ]
        spent = self.budget.spent
        total_http = max(1, self.budget.max_http_requests)
        total_wall = max(0.001, self.budget.max_wall_clock_s)
        return {
            "queue_size": len(self._queue),
            "in_flight": self._in_flight,
            "seen_artifacts": len(self.seen_artifacts),
            "completed_tasks": self._completed_tasks,
            "budget_pct": {
                "http": round(100.0 * spent.http / total_http, 1),
                "wall_clock": round(
                    100.0 * (time.monotonic() - self.budget.started_at) / total_wall,
                    1,
                ),
                "llm_tokens": round(
                    100.0 * spent.llm_tokens / max(1, self.budget.max_llm_tokens), 1,
                ),
                "handler_calls": round(
                    100.0 * self.budget.handler_calls
                    / max(1, self.budget.max_handler_calls), 1,
                ),
            },
            "top10_priorities": top10_view,
            "recent_transitions": list(self._recent_transitions[-10:]),
            "stopping": self._stopping,
        }

    def _install_sigusr1(self) -> None:
        """Install a SIGUSR1 handler that dumps state to stderr (§5.10).
        No-op on Windows or when no signal subsystem is available."""
        try:
            import signal
            import sys
            sig = getattr(signal, "SIGUSR1", None)
            if sig is None:
                return  # Windows
            wl_ref = self
            def _handler(_signum, _frame):
                try:
                    state = wl_ref.dump_state()
                except Exception as e:
                    sys.stderr.write(f"[graph SIGUSR1] dump_state failed: {e}\n")
                    sys.stderr.flush()
                    return
                try:
                    sys.stderr.write(
                        "[graph SIGUSR1] " + json.dumps(state, default=str) + "\n"
                    )
                    sys.stderr.flush()
                except Exception:
                    pass
                try:
                    wl_ref._audit.write({"event": "sigusr1_dump", "state": state})
                except Exception:
                    pass
            signal.signal(sig, _handler)
        except (ValueError, OSError, AttributeError):
            # ValueError: signal only works in main thread; harmless during tests.
            # Re-arm SIG_IGN as a safety net so the process won't die.
            try:
                import signal as _s
                _s.signal(_s.SIGUSR1, _s.SIG_IGN)
            except Exception:
                pass

    # ----- §5.11 checkpoint + resume ----------------------------------------
    def _write_checkpoint(self) -> None:
        """Serialize ids+metadata only (no raw secret bodies — §5.11)."""
        if self._checkpoint_path is None:
            return
        try:
            from pathlib import Path
            p = Path(str(self._checkpoint_path))
            payload = {
                "version": 1,
                "completed_tasks": self._completed_tasks,
                "seen_artifacts": [
                    {
                        "id": a.id,
                        "kind": a.kind,
                        "payload": _safe_payload(a.kind, a.payload),
                        "severity": a.severity,
                        "confidence": a.confidence,
                        "origin_lineage": list(a.origin_lineage),
                    }
                    for a in self.seen_artifacts.values()
                ],
                "visited": [list(v) for v in self.visited],
                "queue": [
                    {"priority": pr, "seq": sq, "handler_id": t.handler_id,
                     "artifact_id": t.artifact_id, "attempt": t.attempt,
                     "reenqueue_depth": t.reenqueue_depth,
                     "parent_task_seq": t.parent_task_seq}
                    for pr, sq, t in self._queue
                ],
                "budget_spent": {
                    "http": self.budget.spent.http,
                    "llm_tokens": self.budget.spent.llm_tokens,
                    "wall_clock_s": self.budget.spent.wall_clock_s,
                    "handler_calls": self.budget.handler_calls,
                },
                "seq": self._seq,
                "findings_count": len(self.findings),
            }
            p.write_text(json.dumps(payload, default=str), encoding="utf-8")
            try:
                import os
                os.chmod(p, 0o600)
            except OSError:
                pass
            self._audit.write({"event": "checkpoint", "tasks": self._completed_tasks})
        except OSError:
            pass

    def _restore(self, resume_from: Any) -> None:
        """Reload `seen_artifacts`, `visited`, `queue`, and budget from a
        previous run's `.checkpoint.json`. Best-effort; partial restore
        triggers a warning in the audit log but does not abort."""
        from pathlib import Path
        p = Path(str(resume_from))
        if not p.exists():
            return
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._audit.write({"event": "resume_failed", "reason": "parse"})
            return
        for a in payload.get("seen_artifacts", []):
            art = Artifact(
                kind=a["kind"],
                payload=a.get("payload", {}),
                id=a.get("id", ""),
                severity=a.get("severity", "info"),
                confidence=float(a.get("confidence", 1.0)),
                origin_lineage=tuple(a.get("origin_lineage", []) or []),
            )
            self.seen_artifacts[art.id] = art
        for v in payload.get("visited", []):
            if len(v) == 2:
                self.visited.add((v[0], v[1]))
        for t in payload.get("queue", []):
            task = Task(
                seq=t.get("seq", 0),
                handler_id=t.get("handler_id", ""),
                artifact_id=t.get("artifact_id", ""),
                priority=t.get("priority", 0),
                attempt=t.get("attempt", 0),
                reenqueue_depth=t.get("reenqueue_depth", 0),
                parent_task_seq=t.get("parent_task_seq"),
            )
            heapq.heappush(self._queue, (task.priority, task.seq, task))
        bs = payload.get("budget_spent", {})
        self.budget.spent = ResourceCost(
            http=int(bs.get("http", 0)),
            llm_tokens=int(bs.get("llm_tokens", 0)),
            wall_clock_s=float(bs.get("wall_clock_s", 0.0)),
        )
        self.budget.handler_calls = int(bs.get("handler_calls", 0))
        self._seq = int(payload.get("seq", 0))
        self._completed_tasks = int(payload.get("completed_tasks", 0))
        self._audit.write({
            "event": "resumed",
            "artifacts": len(self.seen_artifacts),
            "queue": len(self._queue),
            "completed_tasks": self._completed_tasks,
        })


def _safe_payload(kind: str, payload: dict) -> dict:
    """Drop fields that may contain raw secret material from checkpoints
    (§5.11 — keys + values restricted to id-defining hashes)."""
    SECRET_LIKE = {"value", "secret", "raw", "token", "password", "key_material"}
    return {k: v for k, v in (payload or {}).items() if k not in SECRET_LIKE}


@dataclass
class RunReport:
    seen: int
    handler_calls: int
    spent: ResourceCost
    findings: list[Finding]
    artifacts: dict[ArtifactId, Artifact]


__all__ = [
    "Artifact", "ArtifactId", "Budget", "BudgetReserveViolation",
    "CANONICAL_FIELDS", "Ctx", "Finding", "Handler", "HandlerResult",
    "MAX_REENQUEUE_DEPTH", "ResourceCost", "RunReport", "Task",
    "TERMINAL_HANDLERS", "Worklist", "priority",
]


# Install a default no-op for SIGUSR1 at module import (Unix only) so the
# Python interpreter doesn't terminate with the default disposition if a
# signal arrives BEFORE `Worklist.__init__` registers the real dump handler
# (e.g. during the long-running recon phase before the graph is built).
try:
    import signal as _signal
    if hasattr(_signal, "SIGUSR1"):
        try:
            _signal.signal(_signal.SIGUSR1, _signal.SIG_IGN)
        except (ValueError, OSError):
            pass
except ImportError:
    pass
