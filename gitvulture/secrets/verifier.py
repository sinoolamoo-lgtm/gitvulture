"""Opt-in live verification of selected secret types.

WARNING: This module performs real network requests to third-party APIs to
confirm whether a leaked credential is currently valid. ONLY enable when you
have explicit authorization from the target / asset owner.
"""
from __future__ import annotations

import asyncio
from typing import Iterable

import httpx

from .patterns import Finding


async def _check_github(token: str) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=True) as c:
            r = await c.get("https://api.github.com/user", headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github+json",
            })
            if r.status_code == 200:
                login = r.json().get("login", "?")
                return True, f"valid (user={login})"
            return False, f"http {r.status_code}"
    except Exception as e:
        return False, f"err: {e}"


async def _check_stripe(key: str) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=True) as c:
            r = await c.get("https://api.stripe.com/v1/balance", auth=(key, ""))
            if r.status_code == 200:
                return True, "valid"
            return False, f"http {r.status_code}"
    except Exception as e:
        return False, f"err: {e}"


async def _check_slack(token: str) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=True) as c:
            r = await c.get("https://slack.com/api/auth.test", headers={
                "Authorization": f"Bearer {token}",
            })
            if r.status_code == 200 and r.json().get("ok"):
                return True, f"valid (team={r.json().get('team')})"
            return False, r.json().get("error", "invalid")
    except Exception as e:
        return False, f"err: {e}"


async def _check_sendgrid(key: str) -> tuple[bool, str]:
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=True) as c:
            r = await c.get(
                "https://api.sendgrid.com/v3/scopes",
                headers={"Authorization": f"Bearer {key}"},
            )
            return (r.status_code == 200), f"http {r.status_code}"
    except Exception as e:
        return False, f"err: {e}"


_CHECKERS = {
    "github-pat": _check_github,
    "github-oauth": _check_github,
    "github-app": _check_github,
    "stripe-live": _check_stripe,
    "stripe-test": _check_stripe,
    "slack-token": _check_slack,
    "sendgrid-key": _check_sendgrid,
}


async def verify_findings(findings: Iterable[Finding]) -> None:
    """In-place mutation: writes verification result into each Finding.extra."""
    tasks = []
    targets: list[Finding] = []
    for f in findings:
        checker = _CHECKERS.get(f.rule_id)
        if checker:
            targets.append(f)
            tasks.append(checker(f.match))
    if not tasks:
        return
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for f, res in zip(targets, results):
        if isinstance(res, Exception):
            f.extra["verified"] = False
            f.extra["verify_msg"] = str(res)
        else:
            ok, msg = res
            f.extra["verified"] = ok
            f.extra["verify_msg"] = msg
