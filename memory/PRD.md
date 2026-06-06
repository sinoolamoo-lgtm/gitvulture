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

### 2026-02 (later still) — Windows-specific live-output fixes
After user reported the tool still appeared frozen on Windows even after the
generic line-buffering fix, the following Windows-specific issues were
addressed:

1. **Launcher no longer relies on PATH / activate.bat**: `install.bat` now
   writes `%USERPROFILE%\gitvulture.bat` as a direct invocation:
   ```
   "C:\...\venv\Scripts\python.exe" -u -m gitvulture.cli %*
   ```
   The `-u` flag is the bullet-proof way to disable Python's stdio buffering
   on Windows (more reliable than PYTHONUNBUFFERED alone, which can be
   overridden by parent process).
2. **ANSI VT-mode enabled at startup**: `cli.py:main()` now runs `os.system("")`
   on Windows to enable Virtual Terminal Processing in conhost (Windows 10/11),
   then calls `colorama.just_fix_windows_console()` as belt-and-braces. Without
   this, rich prints literal `[90m[INFO][0m` text on the screen instead of
   coloured output.
3. **colorama added as Windows-only dependency** in pyproject.toml.
4. **New `gitvulture --doctor` self-check** — prints environment info ONE LINE
   AT A TIME with `flush=True` and zero rich/buffering. Designed to be the
   first command a user runs if the tool looks broken. It also prints a 5-tick
   heartbeat so the user can visually confirm live output is working.

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
