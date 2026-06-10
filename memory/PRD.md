# GitVulture — Project Memory

## Original problem statement
Build a Python CLI that exploits exposed `.git` directories on web targets.
Must surpass `git-dumper` / `GitTools` / `AIGitsploit` with:
- sqlmap-style live verbose logging
- 16-stage object recovery + escalation chain
- Anti-hallucination AI roadmap (Emergent LLM key)
- Interactive TUI + opt-in AI gating ("Lazy AI")
- Proxy/auth/cookie/header customisation
- WAF / soft-404 / 302-redirect bypass
- Cross-platform installers (Linux, macOS, Windows .ps1 + .bat, Docker)

## Architecture (CLI only — no FastAPI/React)
```
/app/
├── gitvulture/
│   ├── core/  (recon, object_engine, escalation, http_client, aggressive, crypto_attack)
│   ├── ai/    (triage, exploit_roadmap with strict-mode citation verifier)
│   ├── cli.py
│   ├── interactive.py
│   ├── logger.py
│   ├── bypass_library.py
├── scripts/   (jwt_forge_attack.py, auth_brute.py)
├── install.sh           # Linux/macOS/WSL
├── install.ps1          # Windows PowerShell
├── install.bat          # Windows CMD double-click installer
├── Dockerfile           # python:3.12-slim image
├── .dockerignore
├── USAGE.md
└── README.md
```

## CHANGELOG

### 2026-02 (Round 13) — Opt-in graph adapters + §5.10 + §5.11
- **8 new graph-mode handler adapters** (`graph_handlers.py`, ~350 LOC):
  SastHandler (C1), CicdSecretsHandler (C6), JwtForgeHandler (C7),
  LiveDiffHandler (C8), GitPivotsHandler (C9), OriginFinderHandler (D2),
  WebdavHandler (D10), CloudEnumHandler (C3). Each gated via
  `ctx.extra.enable_*` flags so `--graph` mode now has functional parity
  with the linear pipeline (modulo AI/LLM phases). New CLI flags:
  `--graph-sast`, `--graph-cloud-enum`, `--graph-origin-finder`,
  `--graph-webdav`.
- **§5.10 observability**: `Worklist.dump_state()` returns queue_size,
  in_flight, completed_tasks, budget_pct, top-10 pending priorities,
  last-10 transitions. SIGUSR1 handler dumps state to stderr +
  `sigusr1_dump` audit event for replay tools. Final state appended on
  `run()` completion. SIG_IGN installed at module-import time so the
  process can't terminate before Worklist binds its handler.
- **§5.11 checkpoint + resume**: `.checkpoint.json` written every 100
  completed tasks + once on scan-end (chmod 0600). `_safe_payload()`
  strips any `value`/`secret`/`raw`/`token`/`password`/`key_material`
  fields so no raw secret bytes ever reach the file. `--resume OUT_DIR`
  CLI flag restores visited pairs → handlers skip already-seen
  artifacts → warm resume in **0.1s** vs 12.8s cold scan (verified
  live).
- **Live verification (Stage 1 lab)**: cold `--graph` scan completed in
  12.8s with 8 handler calls + 156 git objects; mid-flight SIGUSR1
  captured 2 state dumps; `--resume` restored state and finished in
  0.1s; all graph artifacts written (graph-report.json,
  cicd-secrets.{json,md}, report.html, graph-audit.jsonl).
- **Final test count: 120/120 passing** (86 prior + 12 observability/
  checkpoint + 22 graph-handlers protocol/gating tests).

### 2026-02 (Round 12+) — Live Stage 1 demo + critical pack-discovery fix
**Live demo target**: `https://172.105.126.219/` (Web Security Academy
"Git Directory Exposure" lab, Stage 1 — Easy)

**Critical fix shipped during the live run**:
- `core/object_engine.py::fetch_packs()` previously relied **solely** on
  `/.git/objects/info/packs`. When this returns 404 (common on Apache
  servers that don't auto-generate that index file but DO expose `.git/`
  via `mod_autoindex`), the BFS would fetch 0 objects.
- Fix: if `info/packs` is missing, scrape the directory listing HTML of
  `/.git/objects/pack/` and extract `pack-<sha>.pack` filenames with a
  pure regex (`pack-[0-9a-f]{40}\.pack`). Works for both Apache and
  nginx listing styles.
- Without the fix: 0 objects, 0 commits.
- With the fix: 156 object SHAs from a 2.93 MB pack file, 9 commits,
  2 branches, 131 source files recovered.
- 4 dedicated regression tests in
  `/app/backend/tests/test_pack_listing_fallback.py`.

**Stage 1 outcome**:
- `.git` exposure confirmed → Apache/2.4.25 with directory listing enabled
- Pack file `pack-880f92a73e8f86c6515c89ea7e774ac7c8d48985` (2.9 MB) pulled
- 9 commits + 2 branches reconstructed → 131 files recovered (incl.
  `index.php`, `webparts/header.php`, `footer.php`, `sitemap.xml`)
- Origin repo identified: `github.com:raymondsarinas/sequoiahotel.net.git`
- 23-rule secret hunt: 0 hardcoded secrets (stage 1 is asset-only)
- L1-L16 escalation: 800 path probes, 31 hits (assets)
- All artifacts written: report.html, gitvulture-report.json,
  cicd-secrets.{json,md}, git-pivots.{json,md}, scope-audit.jsonl (1.3 MB)

**Final test count: 86/86 passing** (41 baseline + 20 C6 + 21 graph + 4 pack-listing).

### 2026-02 (Round 12) — C6 CI/CD Secrets + §5 Worklist Graph Refactor
- **C6 CI/CD secrets** (`gitvulture/core/cicd_secrets.py`, 256 LOC):
  parses 7 platforms (GitHub Actions, GitLab CI, CircleCI, Bitbucket,
  Jenkins, Travis, Azure Pipelines) for inline literal secrets,
  `${{ secrets.X }}` refs, OIDC `id-token: write` + audience claims
  (cloud-takeover signal). Wired into orchestrator after C7; ON by
  default, `--no-cicd-secrets` to skip. 20 dedicated pytest tests.
- **§5 Worklist Graph** (`gitvulture/core/worklist.py`, ~430 LOC):
  spec-mandated rewrite of the escalation backbone. Implements
  canonical-form artifact identity (Trap 1), state-as-kind promotions
  (Trap 2), no-atomization for BFS (Trap 3), terminal-handler budget
  reserve (Trap 4). 21 pytest tests covering every §9.1 acceptance
  criterion (canonical_form, priority determinism, state-as-kind,
  budget reserve, cycle guard, termination, retry).
- **Graph driver** (`gitvulture/core/graph_driver.py`, ~280 LOC):
  4 handler adapters (Recon / SecretHunt / SecretsExporter /
  ReportWriter) + `run_graph_scan()` entry. Wired behind `--graph` flag
  so the linear orchestrator stays default — zero regression risk.
- Final test count: **82/82 passing** (41 prior + 20 C6 + 21 graph).
- Live verification: `gitvulture https://example.com/ --graph` →
  0.3s scan, ScopeGuard + Worklist + audit JSONL all functioning.

### 2026-02 (latest) — Bullet-proof plain mode + auto-fallback for Windows
User reported the tool still appeared frozen on Windows despite all previous
fixes. Since the dev sandbox is Linux-aarch64 and cannot run Wine x86, I added
a guaranteed-to-work fallback path that bypasses rich entirely:

1. **`--plain` CLI flag**: forces a pure `print(..., flush=True)` backend in
   `Logger`. No rich, no ANSI, no Panel, no rules. Output is bare ASCII that
   works on every terminal that ever existed — including Windows CMD with
   no VT support, log files, CI consoles, etc.
2. **`GITVULTURE_PLAIN=1` env var**: same effect as `--plain`, set by the new
   plain launcher so users can just run `gitvulture-plain ...`.
3. **`gitvulture-plain.bat` second launcher**: `install.bat` now installs TWO
   shortcuts on PATH — `gitvulture.bat` (rich, coloured) and
   `gitvulture-plain.bat` (bullet-proof). Users with broken terminals can
   switch in 1 command without re-installing.
4. **Auto-detect plain mode on Windows**: if `colorama.just_fix_windows_console()`
   AND the Win32 `SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING)` syscall
   BOTH fail, the logger silently falls back to plain so the user never sees
   garbage ANSI text.
5. **`_strip_markup` regex** correctly preserves rich-escaped literals (`\[`),
   so plain output shows `[INFO]` not `[*]`.

**Live verification** in this sandbox (Linux, no TTY, simulating the worst
Windows case):
```
=== --plain mode end-to-end ===
total lines             : 35
heartbeat ticks         : 9 (one every 2 s)
ANSI codes leaked       : 0
max silent gap          : 2.93s   ← previously ∞ on frozen Windows
```
Rich mode also re-tested — colours intact, no regression.

### 2026-02 (later still) — Windows-specific live-output fixes
1. **Launcher no longer relies on PATH / activate.bat**: `install.bat` now
   writes `%USERPROFILE%\gitvulture.bat` as a direct invocation:
   ```
   "C:\...\venv\Scripts\python.exe" -u -m gitvulture.cli %*
   ```
2. **ANSI VT-mode enabled at startup**: `cli.py:main()` runs `os.system("")`
   on Windows + `colorama.just_fix_windows_console()`.
3. **colorama added as Windows-only dependency** in pyproject.toml.
4. **New `gitvulture --doctor` self-check** — prints environment info ONE LINE
   AT A TIME with `flush=True` and zero rich/buffering.

### 2026-02 — Live output fix (the "frozen tool" bug)
**Root cause** identified by running the tool through `while read` + millisecond
timestamps: on Windows / inside `tee` / over SSH, Python's stdout was
**block-buffered** (8 KB), causing 30+ seconds of total silence between output
chunks. The user saw a frozen banner and concluded the tool was hung.

Fixes applied **and tested live** (httpbin.org target, 13 s scan, 203 lines):
- `gitvulture/cli.py` :: `main()` now sets `PYTHONUNBUFFERED=1` and calls
  `sys.stdout.reconfigure(line_buffering=True)` before anything else.
- `gitvulture/logger.py` :: `Console(force_terminal=True, force_interactive=False)`
  so ANSI + immediate flush survive pipes / tee.
- `gitvulture/logger.py` :: new **heartbeat ticker** — emits a `[TICK]` pulse
  every 2 s of silence with live counters. Honours `--quiet`.
- `gitvulture/cli.py` :: starts/stops heartbeat around `run_scan` in try/finally.

### 2026-02 — Windows installer hardening + Docker support
- **install.bat (P0 bug)**: Replaced the broken FOR/substring config loader in
  the generated `%USERPROFILE%\gitvulture.bat` launcher with a simpler
  `findstr /b /c:"EMERGENT_LLM_KEY="` pipeline. Comments (`#…`) are now
  skipped naturally and substring expansion (which silently failed on FOR
  variables without DelayedExpansion) is no longer needed.
- **Dockerfile**: New `python:3.12-slim` image. Uses Emergent's extra index
  for `emergentintegrations==0.2.0`, installs `gitvulture` editable, exposes
  `/root/.gitvulture` as a volume for sqlmap-style output persistence.
- **.dockerignore**: keeps the build context lean.
- **USAGE.md**: new "Docker — zero-install" section + `install.bat` mention.

### (previous sessions, summarised)
- v1.4 strict-mode AI roadmap with citation verification + Interactive TUI
- 16 escalation stages + 302-redirect / soft-404 bypass library (40+ tricks)
- Proxy / auth-proxy / custom headers / cookies / basic-auth flags
- install.sh + install.ps1 + comprehensive USAGE.md
- Mega-command end-to-end test against the lab target

## Roadmap

### P1 — next
- (nothing pinned — awaiting user instruction)

### P2 — backlog
- GitHub Actions workflow that builds + publishes the Docker image to GHCR
- Optional `--report html` (already JSON/MD) for a self-contained one-page report
- Tor / chained-proxy support (already chainable via `HTTPS_PROXY`, document it)

## Integrations
- **Emergent Universal LLM key** — consumed by `gitvulture/ai/exploit_roadmap.py`
  and `gitvulture/ai/triage.py` via `emergentintegrations==0.2.0`. The key is
  read from `EMERGENT_LLM_KEY` (env or `~/.gitvulture/config.env`).

## Verification status
- `install.bat`: static syntax check passed (labels resolve, 25/25 parens
  balanced, generated launcher expands to valid CMD). Live `winget` flow
  cannot be executed inside the Linux sandbox — user verification on a
  Windows host required.
- `Dockerfile`: `docker` binary not present in this sandbox, but the
  layer order is conventional and the `pyproject.toml` it consumes is the
  same one used by the working `install.sh` flow.

## Test credentials
N/A — CLI tool, no auth backend.
