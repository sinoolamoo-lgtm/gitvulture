"""SQL injection probing (L13) — read-only, evidence-based detection.

We never POST destructive payloads. Each candidate endpoint is hit with a
small matrix of harmless probes:
  - boolean-based (single quote, double quote)
  - time-based (SLEEP / pg_sleep / WAITFOR)
  - error-based (UNION-style fragments that trigger common DB errors)

A probe is flagged as INJECTABLE if it matches any of:
  - DB error fingerprint in the body (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - reflected payload + content-size delta vs. baseline > 50 bytes
  - response time delta > 4s on time-based payloads
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .http_client import HttpClient


DB_ERROR_RE = re.compile(
    r"(SQL syntax.*MySQL|Warning.*mysql_|MySQLSyntaxErrorException|"
    r"valid MySQL result|MySqlClient\.|com\.mysql\.jdbc|"
    r"PostgreSQL.*ERROR|PG::SyntaxError|pg_query|"
    r"Microsoft.*ODBC.*SQL Server|SQLServer JDBC Driver|"
    r"OLE DB.*SQL Server|Unclosed quotation mark|"
    r"ORA-\d{5}|Oracle error|quoted string not properly terminated|"
    r"SQLite/JDBCDriver|System\.Data\.SQLite\.SQLiteException|"
    r"sqlite3\.OperationalError)",
    re.IGNORECASE,
)

PAYLOADS_BOOLEAN = ["'", "''", "\"", "`", "')", "')#", "%27"]
PAYLOADS_ERROR = ["'\"--", "' AND 1=convert(int,@@version)--", "' OR 1=1--"]
PAYLOADS_TIME = [
    "' AND SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    "'); WAITFOR DELAY '0:0:5'--",
    "' OR (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
]


@dataclass
class InjectionFinding:
    endpoint: str
    param: Optional[str]
    payload: str
    technique: str   # 'error' | 'boolean' | 'time'
    evidence: str
    severity: str = "critical"


@dataclass
class SqliReport:
    candidates: list[str] = field(default_factory=list)
    findings: list[InjectionFinding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    probes_sent: int = 0


def _params_in_path(url: str) -> list[str]:
    """Extract query parameter names from a URL."""
    if "?" not in url:
        return []
    qs = url.split("?", 1)[1]
    return [p.split("=", 1)[0] for p in qs.split("&") if "=" in p]


async def probe_sqli(client: HttpClient, candidates: list[str],
                      log=None) -> SqliReport:
    """Probe a list of candidate URLs for SQL injection.

    `candidates` is a list of absolute URLs (e.g. derived from L3/L6 hits).
    For each URL we try GET with payload appended as a new query parameter
    `id`, and if the URL already has parameters, also fuzz each parameter.
    """
    log = log or (lambda *a, **kw: None)
    report = SqliReport(candidates=list(candidates))

    async def _do_get(url: str) -> tuple[int, int, float, bytes]:
        t0 = time.monotonic()
        r = await client._request(url)
        return r.status, len(r.content), time.monotonic() - t0, r.content

    async def probe(url: str):
        # 1) baseline
        b_status, b_size, b_dur, _ = await _do_get(url)
        report.probes_sent += 1
        params = _params_in_path(url) or ["id"]
        for param in params[:3]:
            base = url
            # Helper: build payloaded URL
            def with_payload(payload: str) -> str:
                p = payload
                if "?" in base:
                    if f"{param}=" in base:
                        return re.sub(
                            rf"({re.escape(param)}=)[^&]*",
                            lambda m: m.group(1) + p,
                            base, count=1,
                        )
                    return base + f"&{param}={p}"
                return base + f"?{param}={p}"
            # 2) error / boolean
            for payload in PAYLOADS_BOOLEAN + PAYLOADS_ERROR:
                u = with_payload(payload)
                s, sz, dur, body = await _do_get(u)
                report.probes_sent += 1
                txt = body[:8000].decode("utf-8", errors="replace")
                m = DB_ERROR_RE.search(txt)
                if m:
                    report.findings.append(InjectionFinding(
                        endpoint=url, param=param, payload=payload,
                        technique="error",
                        evidence=f"DB error fingerprint: {m.group(0)[:120]}",
                    ))
                    log(f"[L13] SQLi (error) on {url} param={param}")
                    return
                if abs(sz - b_size) > 200 and s == b_status:
                    report.findings.append(InjectionFinding(
                        endpoint=url, param=param, payload=payload,
                        technique="boolean",
                        severity="high",
                        evidence=f"size delta {sz - b_size} vs baseline {b_size}",
                    ))
                    log(f"[L13] SQLi (boolean) on {url} param={param}")
                    return
            # 3) time-based — only if baseline was fast (<2s)
            if b_dur < 2.0:
                for payload in PAYLOADS_TIME:
                    u = with_payload(payload)
                    s, sz, dur, _ = await _do_get(u)
                    report.probes_sent += 1
                    if dur > b_dur + 4.0:
                        report.findings.append(InjectionFinding(
                            endpoint=url, param=param, payload=payload,
                            technique="time",
                            evidence=f"response time {dur:.1f}s vs baseline {b_dur:.1f}s",
                        ))
                        log(f"[L13] SQLi (time) on {url} param={param} ({dur:.1f}s)")
                        return

    # Throttle: SQLi probes are slow, run small batches
    BATCH = 4
    sem = asyncio.Semaphore(BATCH)
    async def gated(u): 
        async with sem:
            try:
                await probe(u)
            except Exception as e:
                report.notes.append(f"probe error {u}: {e}")
    await asyncio.gather(*(gated(u) for u in candidates[:40]),
                          return_exceptions=True)
    return report
