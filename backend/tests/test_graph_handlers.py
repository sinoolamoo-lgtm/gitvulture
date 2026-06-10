"""Tests for the graph-mode handler adapters (D2/C3/C6/C7/C8/C9/D10/SAST).

These are smoke / gate tests: they verify each adapter's
- handler protocol shape (handles, handler_class, handler_id, requires_consent)
- `can_handle()` gating logic (respects ctx.extra.enable_* flags)
- module-not-loaded path (returns 'skipped' on missing recovered_source/)

End-to-end functional tests for the underlying modules already exist in
dedicated suites (test_l3_d2, test_c3_c7_c9, test_cicd_secrets, etc.).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from gitvulture.core.graph_handlers import (
    CicdSecretsHandler,
    CloudEnumHandler,
    GitPivotsHandler,
    JwtForgeHandler,
    LiveDiffHandler,
    OriginFinderHandler,
    SastHandler,
    WebdavHandler,
    all_optin_handlers,
)
from gitvulture.core.worklist import Artifact, Ctx, Handler


ALL_ADAPTERS = [
    SastHandler,
    CicdSecretsHandler,
    JwtForgeHandler,
    LiveDiffHandler,
    GitPivotsHandler,
    OriginFinderHandler,
    WebdavHandler,
    CloudEnumHandler,
]


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("cls", ALL_ADAPTERS)
def test_adapter_implements_handler_protocol(cls):
    h = cls()
    # Required attributes
    assert isinstance(h.handler_id, str) and h.handler_id
    assert isinstance(h.handler_class, str) and h.handler_class
    assert isinstance(h.handles, set) and h.handles
    assert isinstance(h.requires_consent, bool)
    # Required methods (signature only, not behavior here)
    assert callable(getattr(h, "can_handle", None))
    assert callable(getattr(h, "run", None))
    # Runtime-checkable protocol
    assert isinstance(h, Handler)


def test_handler_ids_are_unique():
    ids = [cls().handler_id for cls in ALL_ADAPTERS]
    assert len(ids) == len(set(ids)), f"duplicate handler ids: {ids}"


def test_all_optin_handlers_returns_one_of_each():
    instances = all_optin_handlers()
    assert len(instances) == len(ALL_ADAPTERS)
    ids = {h.handler_id for h in instances}
    expected = {cls().handler_id for cls in ALL_ADAPTERS}
    assert ids == expected


# ---------------------------------------------------------------------------
# can_handle() gating
# ---------------------------------------------------------------------------
def _make_ctx(tmp_path: Path, **flags):
    return Ctx(
        target_url="https://example.com/",
        output_dir=tmp_path,
        extra=dict(flags),
    )


def _make_art():
    return Artifact(
        kind="repo_reconstructed",
        payload={"repo_dir": "/tmp/r"},
    )


def _make_host_art():
    return Artifact(
        kind="host",
        payload={"scheme": "https", "host": "example.com", "port": 443},
    )


class TestGating:
    def test_sast_default_off(self, tmp_path):
        async def go():
            h = SastHandler()
            ctx = _make_ctx(tmp_path)
            assert await h.can_handle(_make_art(), ctx) is False
            ctx = _make_ctx(tmp_path, enable_sast=True)
            assert await h.can_handle(_make_art(), ctx) is True
        asyncio.run(go())

    def test_cicd_default_on(self, tmp_path):
        async def go():
            h = CicdSecretsHandler()
            assert await h.can_handle(_make_art(), _make_ctx(tmp_path)) is True
            ctx = _make_ctx(tmp_path, enable_cicd=False)
            assert await h.can_handle(_make_art(), ctx) is False
        asyncio.run(go())

    def test_jwt_default_on(self, tmp_path):
        async def go():
            h = JwtForgeHandler()
            assert await h.can_handle(_make_art(), _make_ctx(tmp_path)) is True
            ctx = _make_ctx(tmp_path, enable_jwt_forge=False)
            assert await h.can_handle(_make_art(), ctx) is False
        asyncio.run(go())

    def test_origin_finder_default_off(self, tmp_path):
        async def go():
            h = OriginFinderHandler()
            assert await h.can_handle(_make_host_art(), _make_ctx(tmp_path)) is False
            ctx = _make_ctx(tmp_path, enable_origin_finder=True)
            assert await h.can_handle(_make_host_art(), ctx) is True
        asyncio.run(go())

    def test_webdav_default_off(self, tmp_path):
        async def go():
            h = WebdavHandler()
            assert await h.can_handle(_make_host_art(), _make_ctx(tmp_path)) is False
            ctx = _make_ctx(tmp_path, enable_webdav=True)
            assert await h.can_handle(_make_host_art(), ctx) is True
        asyncio.run(go())

    def test_cloud_enum_default_off_and_requires_cloud_rule(self, tmp_path):
        async def go():
            h = CloudEnumHandler()
            # Even with flag ON, non-cloud rule should be ignored
            ctx = _make_ctx(tmp_path, enable_cloud_enum=True)
            art = Artifact(kind="key", payload={"key_material_hash": "x",
                                                "rule_id": "random"})
            assert await h.can_handle(art, ctx) is False
            aws_art = Artifact(kind="key", payload={"key_material_hash": "y",
                                                    "rule_id": "aws-key"})
            assert await h.can_handle(aws_art, ctx) is True
        asyncio.run(go())


# ---------------------------------------------------------------------------
# Graceful no-op when recovered_source/ missing
# ---------------------------------------------------------------------------
class TestNoSource:
    def test_jwt_no_source_skipped(self, tmp_path):
        async def go():
            h = JwtForgeHandler()
            ctx = _make_ctx(tmp_path)
            r = await h.run(_make_art(), ctx)
            assert r.status == "skipped"
        asyncio.run(go())

    def test_sast_no_source_skipped(self, tmp_path):
        async def go():
            h = SastHandler()
            ctx = _make_ctx(tmp_path, enable_sast=True)
            r = await h.run(_make_art(), ctx)
            assert r.status == "skipped"
        asyncio.run(go())

    def test_git_pivots_no_source_skipped(self, tmp_path):
        async def go():
            h = GitPivotsHandler()
            ctx = _make_ctx(tmp_path)
            r = await h.run(_make_art(), ctx)
            assert r.status == "skipped"
        asyncio.run(go())

    def test_live_diff_no_endpoints_skipped(self, tmp_path):
        async def go():
            (tmp_path / "recovered_source").mkdir()
            h = LiveDiffHandler()
            ctx = _make_ctx(tmp_path)  # no endpoints in extra
            r = await h.run(_make_art(), ctx)
            assert r.status == "skipped"
        asyncio.run(go())

    def test_cicd_empty_dir_ok_zero_findings(self, tmp_path):
        async def go():
            (tmp_path / "recovered_source").mkdir()
            h = CicdSecretsHandler()
            ctx = _make_ctx(tmp_path)
            r = await h.run(_make_art(), ctx)
            assert r.status == "ok"
            assert r.findings == []
        asyncio.run(go())


# ---------------------------------------------------------------------------
# CloudEnumHandler returns a 'deferred' finding (graph stub)
# ---------------------------------------------------------------------------
def test_cloud_enum_emits_deferred_finding(tmp_path):
    async def go():
        h = CloudEnumHandler()
        ctx = _make_ctx(tmp_path, enable_cloud_enum=True)
        art = Artifact(kind="key", payload={"key_material_hash": "x",
                                             "rule_id": "aws-key"})
        r = await h.run(art, ctx)
        assert r.status == "skipped"
        assert len(r.findings) == 1
        assert r.findings[0].rule_id == "cloud-enum-deferred"
    asyncio.run(go())
