"""Tests for §5.10 observability (dump_state, SIGUSR1) and §5.11
checkpoint/resume.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gitvulture.core.worklist import (
    Artifact,
    Budget,
    Ctx,
    HandlerResult,
    ResourceCost,
    Worklist,
    _safe_payload,
)


# ---------------------------------------------------------------------------
# Test handlers
# ---------------------------------------------------------------------------
class _SimpleHandler:
    handler_id = "_SimpleHandler"
    handler_class = "recon"
    handles = {"host"}
    requires_consent = False
    estimated_cost = ResourceCost(http=1)

    def __init__(self, kind_out="endpoint"):
        self.kind_out = kind_out
        self.calls = 0

    async def can_handle(self, art, ctx):
        return True

    async def run(self, art, ctx):
        self.calls += 1
        return HandlerResult(
            status="ok",
            new_artifacts=[Artifact(
                kind=self.kind_out,
                payload={"method": "GET", "normalized_url": f"/x{self.calls}"},
                severity="high",
            )],
            cost=ResourceCost(http=1),
        )


# ---------------------------------------------------------------------------
# §5.10 — observability
# ---------------------------------------------------------------------------
class TestDumpState:
    def test_dump_state_keys(self, tmp_path):
        async def go():
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
            )
            state = wl.dump_state()
            assert "queue_size" in state
            assert "in_flight" in state
            assert "seen_artifacts" in state
            assert "completed_tasks" in state
            assert "budget_pct" in state
            assert "top10_priorities" in state
            assert "recent_transitions" in state
            assert "stopping" in state
            assert isinstance(state["top10_priorities"], list)
            assert {"http", "wall_clock", "llm_tokens", "handler_calls"} \
                <= set(state["budget_pct"].keys())
        asyncio.run(go())

    def test_dump_state_after_run_records_transitions(self, tmp_path):
        async def go():
            h = _SimpleHandler()
            wl = Worklist(
                handlers=[h],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
            )
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            await wl.run()
            state = wl.dump_state()
            assert state["completed_tasks"] >= 1
            assert state["seen_artifacts"] >= 2  # host + endpoint
            assert len(state["recent_transitions"]) >= 1
            t = state["recent_transitions"][0]
            assert "handler" in t and "status" in t
        asyncio.run(go())

    def test_final_state_appended_to_audit(self, tmp_path):
        async def go():
            audit = tmp_path / "audit.jsonl"
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                audit_path=audit,
            )
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            await wl.run()
            lines = audit.read_text().splitlines()
            events = [json.loads(line)["event"] for line in lines]
            assert "final_state" in events
        asyncio.run(go())


# Signal subsystem only available on Unix; gracefully skip on Windows.
HAS_SIGUSR1 = hasattr(signal, "SIGUSR1")


@pytest.mark.skipif(not HAS_SIGUSR1, reason="SIGUSR1 not available")
class TestSigusr1:
    def test_install_does_not_crash_on_unix(self, tmp_path):
        # Constructor installs the handler — must not raise even when the
        # signal is sent during a sync test.
        async def go():
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
            )
            # Send SIGUSR1 to self — the handler must run without crashing
            try:
                os.kill(os.getpid(), signal.SIGUSR1)
                await asyncio.sleep(0.05)
            except (OSError, ValueError):
                pytest.skip("cannot send SIGUSR1 in this env")
            # Just ensure no exception bubbled up
            assert wl.dump_state()["stopping"] is False
        asyncio.run(go())


# ---------------------------------------------------------------------------
# §5.11 — checkpoint + resume
# ---------------------------------------------------------------------------
class TestCheckpoint:
    def test_checkpoint_written_after_n_tasks(self, tmp_path):
        async def go():
            cp = tmp_path / ".checkpoint.json"
            # checkpoint_every=1 → every task triggers a write
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                checkpoint_path=cp,
                checkpoint_every=1,
            )
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            await wl.run()
            assert cp.exists()
            data = json.loads(cp.read_text())
            assert data["version"] == 1
            assert data["completed_tasks"] >= 1
            assert "seen_artifacts" in data
            assert "visited" in data
            assert "queue" in data
            assert "budget_spent" in data
        asyncio.run(go())

    def test_checkpoint_chmod_0600(self, tmp_path):
        async def go():
            cp = tmp_path / ".checkpoint.json"
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                checkpoint_path=cp,
                checkpoint_every=1,
            )
            await wl.submit(Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            ))
            await wl.run()
            mode = cp.stat().st_mode & 0o777
            assert mode == 0o600
        asyncio.run(go())

    def test_resume_restores_state(self, tmp_path):
        async def go():
            cp = tmp_path / ".checkpoint.json"
            # Manually write a checkpoint with some state
            payload = {
                "version": 1,
                "completed_tasks": 5,
                "seen_artifacts": [
                    {"id": "abc123", "kind": "host",
                     "payload": {"scheme": "https", "host": "y", "port": 443},
                     "severity": "info", "confidence": 1.0,
                     "origin_lineage": []},
                ],
                "visited": [["_SimpleHandler", "abc123"]],
                "queue": [],
                "budget_spent": {"http": 42, "llm_tokens": 0,
                                 "wall_clock_s": 5.0, "handler_calls": 5},
                "seq": 5,
            }
            cp.write_text(json.dumps(payload))

            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://y", output_dir=tmp_path),
                resume_from=cp,
            )
            assert len(wl.seen_artifacts) == 1
            assert ("_SimpleHandler", "abc123") in wl.visited
            assert wl.budget.spent.http == 42
            assert wl.budget.handler_calls == 5
            assert wl._seq == 5
            assert wl._completed_tasks == 5
        asyncio.run(go())

    def test_resume_missing_file_is_safe(self, tmp_path):
        async def go():
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://y", output_dir=tmp_path),
                resume_from=tmp_path / "nope.json",
            )
            assert wl.seen_artifacts == {}
        asyncio.run(go())

    def test_resume_corrupt_file_is_safe(self, tmp_path):
        cp = tmp_path / "bad.json"
        cp.write_text("{not json")
        async def go():
            wl = Worklist(
                handlers=[_SimpleHandler()],
                ctx=Ctx(target_url="https://y", output_dir=tmp_path),
                resume_from=cp,
            )
            assert wl.seen_artifacts == {}
        asyncio.run(go())


class TestSafePayload:
    """§5.11 — no raw secret material in checkpoints."""

    def test_strips_value_token_secret(self):
        p = {
            "rule_id": "aws-key",
            "value": "AKIAIOSFODNN7EXAMPLE",
            "token": "eyJ...",
            "secret": "topsecret",
            "raw": "raw-bytes",
            "password": "hunter2",
            "key_material": "deadbeef",
            "method": "GET",
        }
        out = _safe_payload("key", p)
        assert "value" not in out
        assert "token" not in out
        assert "secret" not in out
        assert "raw" not in out
        assert "password" not in out
        assert "key_material" not in out
        # Non-secret fields are preserved
        assert out["rule_id"] == "aws-key"
        assert out["method"] == "GET"

    def test_empty_payload(self):
        assert _safe_payload("key", {}) == {}
        assert _safe_payload("key", None) == {}


# ---------------------------------------------------------------------------
# Round-trip: write checkpoint, restore from it, scan continues correctly
# ---------------------------------------------------------------------------
class TestRoundTrip:
    def test_resume_does_not_re_visit(self, tmp_path):
        """A resumed scan must not re-run handlers on visited (h,a) pairs."""
        async def go():
            cp = tmp_path / ".checkpoint.json"
            host_art = Artifact(
                kind="host",
                payload={"scheme": "https", "host": "x", "port": 443},
            )
            # Write a checkpoint claiming we already visited (h,a)
            payload = {
                "version": 1,
                "completed_tasks": 1,
                "seen_artifacts": [
                    {"id": host_art.id, "kind": "host",
                     "payload": dict(host_art.payload),
                     "severity": "info", "confidence": 1.0, "origin_lineage": []},
                ],
                "visited": [["_SimpleHandler", host_art.id]],
                "queue": [],
                "budget_spent": {"http": 1, "llm_tokens": 0,
                                 "wall_clock_s": 0.1, "handler_calls": 1},
                "seq": 1,
            }
            cp.write_text(json.dumps(payload))

            h = _SimpleHandler()
            wl = Worklist(
                handlers=[h],
                ctx=Ctx(target_url="https://x", output_dir=tmp_path),
                resume_from=cp,
            )
            # Re-submit the same host — must NOT re-enqueue (already visited)
            await wl.submit(host_art)
            await wl.run()
            assert h.calls == 0, "resumed scan re-ran a visited (handler, artifact)"
        asyncio.run(go())
