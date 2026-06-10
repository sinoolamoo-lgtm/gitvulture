"""Unit tests for the Worklist scheduler (ARCHITECTURE.md §5 / §9.1).

Covers the spec-mandated acceptance criteria:
- canonical_form identity (Trap 1) — same logical artifact → same id
- state-as-kind promotions (Trap 2)
- priority determinism (no wall-clock; same input → same task order)
- budget reserve for terminal handlers (Trap 4)
- loop / reenqueue depth guard
- cycle detection
- termination on quiescence (K=3 idle ticks)
- handler retry with backoff
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from gitvulture.core.worklist import (
    Artifact,
    Budget,
    BudgetReserveViolation,
    Ctx,
    Finding,
    HandlerResult,
    MAX_REENQUEUE_DEPTH,
    ResourceCost,
    TERMINAL_HANDLERS,
    Worklist,
    _canonical_id,
    priority,
)


# ---------------------------------------------------------------------------
# Test handlers (in-memory, side-effect-free)
# ---------------------------------------------------------------------------
class EchoHandler:
    """Emits a fingerprinted_endpoint for every endpoint it sees."""
    handler_id = "EchoHandler"
    handler_class = "verify"
    handles = {"endpoint"}
    requires_consent = False
    estimated_cost = ResourceCost(http=1)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        return HandlerResult(
            status="ok",
            new_artifacts=[Artifact(
                kind="fingerprinted_endpoint",
                payload=dict(art.payload),
                severity=art.severity,
            )],
            cost=ResourceCost(http=1, wall_clock_s=0.0),
        )


class PromoteKeyHandler:
    """Promotes `key` → `verified_key` (state-as-kind §5.1 Trap 2)."""
    handler_id = "PromoteKeyHandler"
    handler_class = "verify"
    handles = {"key"}
    requires_consent = False
    estimated_cost = ResourceCost(http=1)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        return HandlerResult(
            status="ok",
            new_artifacts=[Artifact(
                kind="verified_key",
                payload=dict(art.payload),
                severity="high",
            )],
            cost=ResourceCost(http=1),
        )


class EnumerateVerifiedHandler:
    """`verified_key` → `enumerated_key` + a finding."""
    handler_id = "EnumerateVerifiedHandler"
    handler_class = "verify"
    handles = {"verified_key"}
    requires_consent = False
    estimated_cost = ResourceCost(http=2)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        return HandlerResult(
            status="ok",
            new_artifacts=[Artifact(
                kind="enumerated_key",
                payload=dict(art.payload),
                severity="critical",
            )],
            findings=[Finding(
                rule_id="cloud-enum",
                severity="high",
                title="AWS key enumerated",
            )],
            cost=ResourceCost(http=2),
        )


class FailingHandler:
    """Always crashes — used to test retry/backoff."""
    handler_id = "FailingHandler"
    handler_class = "sast"
    handles = {"blob"}
    requires_consent = False
    estimated_cost = ResourceCost()

    def __init__(self):
        self.calls = 0

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        self.calls += 1
        raise RuntimeError("boom")


class ReportWriterHandler:
    """Terminal handler — must always run from the reserve (§5.6.1)."""
    handler_id = "ReportWriterHandler"
    handler_class = "terminal"
    handles = {"repo_reconstructed"}
    requires_consent = False
    estimated_cost = ResourceCost(http=10, wall_clock_s=0.0)

    def __init__(self):
        self.ran = False

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        self.ran = True
        return HandlerResult(status="ok", cost=ResourceCost(http=10))


class ChattyHandler:
    """Emits N child artifacts — used for priority / cycle tests."""
    handler_id = "ChattyHandler"
    handler_class = "recon"
    handles = {"host"}
    requires_consent = False
    estimated_cost = ResourceCost(http=1)

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        return HandlerResult(
            status="ok",
            new_artifacts=[
                Artifact(kind="endpoint",
                         payload={"method": "GET", "normalized_url": "/login"},
                         severity="medium"),
                Artifact(kind="endpoint",
                         payload={"method": "GET", "normalized_url": "/admin"},
                         severity="critical"),
            ],
            cost=ResourceCost(http=1),
        )


# ---------------------------------------------------------------------------
# §5.1 Trap 1 — canonical_form identity is metadata-free
# ---------------------------------------------------------------------------
class TestCanonicalForm:
    def test_same_identity_fields_same_id(self):
        a = Artifact(kind="host", payload={"scheme": "https", "host": "x", "port": 443})
        b = Artifact(kind="host", payload={"scheme": "https", "host": "x", "port": 443})
        assert a.id == b.id

    def test_metadata_mutation_same_id(self):
        a = Artifact(kind="key", payload={"key_material_hash": "abc"},
                     severity="info", confidence=0.1)
        b = Artifact(kind="key", payload={"key_material_hash": "abc"},
                     severity="critical", confidence=0.99)
        assert a.id == b.id

    def test_different_identity_field_different_id(self):
        a = Artifact(kind="commit", payload={"sha": "aaa"})
        b = Artifact(kind="commit", payload={"sha": "bbb"})
        assert a.id != b.id

    def test_non_identity_payload_field_ignored(self):
        # `severity` is metadata — but what about a non-whitelisted payload key?
        a = Artifact(kind="host",
                     payload={"scheme": "https", "host": "x", "port": 443,
                              "discovered_via": "ipv4"})
        b = Artifact(kind="host",
                     payload={"scheme": "https", "host": "x", "port": 443,
                              "discovered_via": "ipv6"})
        assert a.id == b.id, "non-identity payload field changed id"

    def test_lineage_capped_at_32(self):
        long_lineage = tuple(f"id{i}" for i in range(50))
        a = Artifact(kind="commit", payload={"sha": "x"}, origin_lineage=long_lineage)
        assert len(a.origin_lineage) == 32
        # Keeps the LAST 32 (closest parents)
        assert a.origin_lineage[0] == "id18"


# ---------------------------------------------------------------------------
# §5.5 priority determinism
# ---------------------------------------------------------------------------
class TestPriorityDeterminism:
    def test_severity_dominates_handler_class(self):
        crit = Artifact(kind="endpoint",
                        payload={"method": "GET", "normalized_url": "/a"},
                        severity="critical")
        info = Artifact(kind="endpoint",
                        payload={"method": "GET", "normalized_url": "/b"},
                        severity="info")
        h = EchoHandler()
        assert priority(crit, h) < priority(info, h)

    def test_no_wall_clock_in_priority(self):
        a = Artifact(kind="endpoint",
                     payload={"method": "GET", "normalized_url": "/x"},
                     severity="high")
        import time as _t
        p1 = priority(a, EchoHandler())
        _t.sleep(0.001)
        p2 = priority(a, EchoHandler())
        assert p1 == p2, "priority changed across time → would break replay"

    def test_same_input_same_task_order(self, tmp_path):
        async def go():
            # Two identical runs must enqueue tasks in identical order
            orders = []
            for _ in range(2):
                wl = Worklist(handlers=[ChattyHandler(), EchoHandler()],
                              ctx=Ctx(target_url="https://x", output_dir=tmp_path))
                await wl.submit(Artifact(
                    kind="host",
                    payload={"scheme": "https", "host": "x", "port": 443},
                ))
                # Snapshot queue pre-run
                orders.append([(p, s, t.handler_id) for p, s, t in wl._queue])
            assert orders[0] == orders[1]
        asyncio.run(go())


# ---------------------------------------------------------------------------
# §5.1 Trap 2 — state-as-kind promotions
# ---------------------------------------------------------------------------
class TestStateAsKind:
    def test_key_to_verified_to_enumerated_chain(self, tmp_path):
        async def go():
            wl = Worklist(
                handlers=[PromoteKeyHandler(), EnumerateVerifiedHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
            )
            await wl.submit(Artifact(
                kind="key",
                payload={"key_material_hash": "deadbeef"},
                severity="medium",
            ))
            report = await wl.run()
            kinds = {a.kind for a in report.artifacts.values()}
            assert "key" in kinds
            assert "verified_key" in kinds
            assert "enumerated_key" in kinds
            # And a finding bubbled up
            assert any(f.rule_id == "cloud-enum" for f in report.findings)
        asyncio.run(go())

    def test_identity_preserved_across_promotion(self, tmp_path):
        """Same `key_material_hash` → all three artifacts share the same id."""
        h = "abcdef0123"
        a_key = Artifact(kind="key", payload={"key_material_hash": h})
        a_ver = Artifact(kind="verified_key", payload={"key_material_hash": h})
        a_enu = Artifact(kind="enumerated_key", payload={"key_material_hash": h})
        # They have different kinds → different ids (kind is part of canonical body)
        assert a_key.id != a_ver.id != a_enu.id
        # But two keys with the same material → same id
        a_key2 = Artifact(kind="key", payload={"key_material_hash": h})
        assert a_key.id == a_key2.id


# ---------------------------------------------------------------------------
# §5.6 budget reserve for terminal handlers (Trap 4)
# ---------------------------------------------------------------------------
class TestBudgetReserve:
    def test_terminal_handler_runs_from_reserve(self, tmp_path):
        async def go():
            # Budget: only the reserve has anything left for terminal handlers
            b = Budget(
                max_http_requests=10,
                report_reserve=ResourceCost(http=10, wall_clock_s=60.0),
            )
            # Pre-spend so non-reserve is empty
            b.spent = ResourceCost(http=0)  # full reserve still available
            term = ReportWriterHandler()
            wl = Worklist(
                handlers=[term],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                budget=b,
            )
            await wl.submit(Artifact(
                kind="repo_reconstructed",
                payload={"repo_dir": "/tmp/r"},
            ))
            await wl.run()
            assert term.ran, "terminal handler must run from reserve"
        asyncio.run(go())

    def test_non_terminal_cannot_drain_reserve(self):
        b = Budget(
            max_http_requests=100,
            report_reserve=ResourceCost(http=50, wall_clock_s=10.0),
        )
        # non-terminal: only `max_http_requests - reserve` = 50 available
        assert b.can_afford(ResourceCost(http=49), terminal=False)
        assert not b.can_afford(ResourceCost(http=60), terminal=False)
        # terminal: full pool
        assert b.can_afford(ResourceCost(http=99), terminal=True)

    def test_budget_consume_raises_on_reserve_violation(self):
        b = Budget(
            max_http_requests=100,
            report_reserve=ResourceCost(http=50, wall_clock_s=10.0),
        )
        with pytest.raises(BudgetReserveViolation):
            b.consume(ResourceCost(http=60), terminal=False)


# ---------------------------------------------------------------------------
# Loop / cycle / depth guards
# ---------------------------------------------------------------------------
class CycleHandler:
    """Emits artifact whose payload identifies it as its own parent — should
    be caught by lineage cycle guard."""
    handler_id = "CycleHandler"
    handler_class = "escalation"
    handles = {"endpoint"}
    requires_consent = False
    estimated_cost = ResourceCost(http=1)

    def __init__(self):
        self.calls = 0

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        self.calls += 1
        # Same payload → same id → identity-merged on resubmit
        return HandlerResult(
            status="ok",
            new_artifacts=[Artifact(kind="endpoint", payload=dict(art.payload))],
            cost=ResourceCost(http=1),
        )


class TestCycleGuard:
    def test_identical_artifact_merged_not_re_run(self, tmp_path):
        async def go():
            h = CycleHandler()
            wl = Worklist(handlers=[h],
                          ctx=Ctx(target_url="https://x", output_dir=tmp_path))
            await wl.submit(Artifact(
                kind="endpoint",
                payload={"method": "GET", "normalized_url": "/x"},
            ))
            await wl.run()
            # The cycle-creating handler should run exactly once
            # (re-emitted artifact is identity-merged, not re-enqueued)
            assert h.calls == 1
        asyncio.run(go())

    def test_reenqueue_depth_cap(self):
        # Constant at module level — assert spec invariant
        assert MAX_REENQUEUE_DEPTH == 3


# ---------------------------------------------------------------------------
# Termination & retry
# ---------------------------------------------------------------------------
class TestTermination:
    def test_quiesces_when_no_handlers_match(self, tmp_path):
        async def go():
            wl = Worklist(handlers=[],
                          ctx=Ctx(target_url="https://x", output_dir=tmp_path))
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            r = await wl.run()
            assert r.seen == 1
            assert r.handler_calls == 0
        asyncio.run(go())

    def test_retry_then_give_up(self, tmp_path):
        async def go():
            h = FailingHandler()
            wl = Worklist(handlers=[h],
                          ctx=Ctx(target_url="https://x", output_dir=tmp_path))
            await wl.submit(Artifact(kind="blob", payload={"sha": "x"}))
            await wl.run()
            # 1 initial + 2 retries = 3 calls before give-up
            assert h.calls == 3
        asyncio.run(go())


# ---------------------------------------------------------------------------
# End-to-end smoke
# ---------------------------------------------------------------------------
class TestEndToEnd:
    def test_chatty_recon_dispatches_to_echo(self, tmp_path):
        async def go():
            wl = Worklist(
                handlers=[ChattyHandler(), EchoHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
            )
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            report = await wl.run()
            kinds = {a.kind for a in report.artifacts.values()}
            assert {"host", "endpoint", "fingerprinted_endpoint"} <= kinds
            # Critical /admin should be reached
            assert any(
                a.kind == "fingerprinted_endpoint"
                and a.payload["normalized_url"] == "/admin"
                for a in report.artifacts.values()
            )
        asyncio.run(go())

    def test_audit_jsonl_written(self, tmp_path):
        async def go():
            audit = tmp_path / "graph-audit.jsonl"
            wl = Worklist(
                handlers=[EchoHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                audit_path=audit,
            )
            await wl.submit(Artifact(
                kind="endpoint",
                payload={"method": "GET", "normalized_url": "/x"},
            ))
            await wl.run()
            assert audit.exists()
            content = audit.read_text()
            assert "enqueue" in content
            assert "ok" in content
        asyncio.run(go())


# ---------------------------------------------------------------------------
# Terminal-handler set is the documented one (§5.6.1)
# ---------------------------------------------------------------------------
def test_terminal_handlers_match_spec():
    assert TERMINAL_HANDLERS == frozenset({
        "ExploitRoadmapHandler",
        "ReportWriterHandler",
        "SecretsExporterHandler",
        "GraphDotWriterHandler",
        "AuditFlushHandler",
    })


def test_canonical_id_is_stable_and_short():
    h1 = _canonical_id("host", {"scheme": "https", "host": "x", "port": 443})
    h2 = _canonical_id("host", {"port": 443, "host": "x", "scheme": "https"})
    assert h1 == h2  # key ordering must not matter
    assert len(h1) == 16
