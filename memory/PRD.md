# GitVulture v1.4 — Strict-Mode AI + Interactive TUI + Lazy AI + Residential Proxies

## What ships in v1.4 (this session)

### 1. AI Strict-Mode (anti-hallucination)
`/app/gitvulture/ai/exploit_roadmap.py`
- New SYSTEM_PROMPT requires every scenario to include `evidence_citations`
  pointing to actual JSON paths inside the artefact bundle
  (e.g. `recovered_files[3].path`, `recon.head_ref`)
- New `verification_steps` field per scenario — concrete signals the operator
  can use to confirm the exploit succeeded
- `_resolve_citation()` walks the bundle to confirm every cited path exists
- `_verify_roadmap()`:
  • REJECTS scenarios with zero valid citations
  • DOWNGRADES confidence ("high" → "low") if any citation is bogus
  • Adds `[unverified]` / `[partially verified]` prefix to titles
  • Logs all warnings to the live verbose stream
- Bundle now exposes `failed_attacks` array (stages that produced 0 hits) so
  the LLM cannot re-recommend already-failed vectors

### 2. Lazy AI
`/app/gitvulture/cli.py`
- AI is now **opt-in** (was opt-out). `--ai` or `--exploit-roadmap` to enable.
- When AI is off, EMERGENT_LLM_KEY is removed from the process env so no
  downstream module accidentally calls it
- `--no-ai` retained for backwards compat

### 3. Interactive TUI (new)
`/app/gitvulture/interactive.py`
- `gitvulture --interactive` opens a menu-driven workflow
- Workflow is a DAG of nodes (start → recon → refs → objects/index → …)
- User picks options by number or keyword
- Built-in commands at every prompt:
  `back · forward · skip · redo · status · proxy · ai · quit · help`
- AI consultation node ("ai_guide") is OPT-IN per step
- History stack lets the user rewind to any prior node
- Proxy can be set/changed at any prompt with the `proxy` command
- Status command shows what data has been collected so far

### 4. Authenticated Residential Proxies
`/app/gitvulture/cli.py` + `/app/gitvulture/interactive.py`
- `--proxy http://user:pass@host:port` already worked via httpx — now
  documented and tested
- New `--proxy-auth USER:PASS` flag injects creds into an existing
  `--proxy http://host:port` URL (convenient for residential rotators)
- Interactive `proxy` command guides user through configuring auth proxy

### 5. Bypass Library (centralized)
`/app/gitvulture/bypass_library.py`
- 40+ path tricks (semicolons, double-slashes, .;/, %2e, ::$DATA, …)
- 30+ header tricks (X-Original-URL, X-Forwarded-*, Range, Host injection,
  Forwarded RFC7239, True-Client-IP, CF-Connecting-IP, X-WAP-Profile, …)
- Encoding variants (single, double, %2f, %u002f, Unicode full-width)
- 13 HTTP methods (incl. WebDAV: PROPFIND, MKCOL, COPY, MOVE)
- WAF fingerprint dictionary (12 vendors)
- Time-based payload templates (MySQL, MSSQL, Postgres)

## Verified
- `_verify_roadmap()` unit test: rejected fake citations, downgraded uncited
  scenarios, kept valid ones — assertion-driven test in execute_bash
- Interactive TUI smoke test against the lab: detected exposure, showed live
  options, accepted navigation commands
- AI flag matrix tested: `--ai`, `--no-ai`, `--exploit-roadmap`,
  `--interactive` all behave per spec

## Files touched this session
- `/app/gitvulture/ai/exploit_roadmap.py` — strict-mode + verifier
- `/app/gitvulture/cli.py` — lazy AI + `--interactive` + `--proxy-auth`
- `/app/gitvulture/interactive.py` — new (550 LoC)
- `/app/gitvulture/bypass_library.py` — new (centralized tricks)

## Backlog
- Persist interactive session state to disk so user can resume across runs
- Hot-swap proxy mid-run via interactive `proxy` command actually replacing
  the live HttpClient instance (currently only affects next created client)
- `--auto-exploit` flag that takes the top scenario from a verified roadmap
  and executes its `ready_commands` automatically inside `--scope`
- Add WebDAV (PROPFIND/MKCOL) probes to the standard ladder
- Surface bypass_library tricks into the http_client's bypass chain
