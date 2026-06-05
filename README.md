# GitVulture v1.1 — One-command .git directory exploitation

> A complete rewrite of the runtime layer of the original AIGitsploit/GitVulture
> codebase, focused on **live sqlmap-style verbose output**, **mechanical
> auto-escalation** (no AI required for the first 5 levels), and **opt-in AI
> deep-dive** for advanced stages (L6, L8, L12, L15).

```bash
gitvulture https://target.tld/                 # full auto: scan + escalate + AI
gitvulture https://target.tld/ --no-ai         # mechanical-only (no LLM calls)
gitvulture https://target.tld/ --no-escalate   # stop after the 7-phase scan
gitvulture https://target.tld/ -vv             # show every HTTP transaction
gitvulture --list-targets                      # browse past scans
```

## What was wrong with the original code (and is now fixed)

| #  | File                       | Problem                                                                 | Fix                                                                |
|----|----------------------------|-------------------------------------------------------------------------|---------------------------------------------------------------------|
| 1  | `cli.py`                   | `rich.Progress` spinner hid every action; user could not see anything   | Removed; replaced with sqlmap-style streaming logger                |
| 2  | `core/http_client.py`      | Per-request activity was never logged                                   | Every request now routes through `logger.http()`                    |
| 3  | `core/http_client.py`      | 403 bypass tried on every 404 → 12×8 = 96 extra requests per miss       | Bypass now only fires on 401/403 (true denial)                      |
| 4  | `core/http_client.py`      | No soft-404 calibration; CDN/WAF "200 OK" pages were mistaken for hits  | New `calibrate_soft_404()` + body fingerprinting                    |
| 5  | `core/recon.py`            | HEAD detection used `len(content) == 41` (only one specific case)       | Regex on `ref: refs/...` OR a raw SHA1                              |
| 6  | `core/orchestrator.py`     | `asyncio.create_task(_emit(...))` antipattern — events lost on shutdown | `_emit` is now awaited or scheduled safely                          |
| 7  | `core/orchestrator.py`     | `.git/refs/` directory never created → `git fsck` refused to open repo  | Now seeds `refs/heads/`, `refs/tags/`, `refs/remotes/` + loose refs |
| 8  | `core/object_engine.py`    | BFS tried to re-fetch pack-only SHAs as loose → 404 storm               | Tracks `_packed_shas`, skips them in `fetch_loose()`                |
| 9  | `core/escalation.py`       | AI stages crashed without `EMERGENT_LLM_KEY`                            | AI-only stages now skip gracefully with a `[WARN]`                  |
| 10 | runtime                    | No way to tell whether the tool was working or hanging                  | Live, timestamped, color-coded log lines at every step              |

## What was kept (because it was already best-in-class)

* **16-level escalation ladder** (L1 bypass storm → L2 pivot → L3 endpoint
  synthesis → L4 hidden paths → L5 auth fingerprint → L6 AI loop → L7 super
  secret scan → L9 aggressive blob retrieval → L10 pack hunt → L11 recovered
  source scan → L12 AI wave 2 → L13 SQLi probe → L14 JWT/crypto attacks →
  L15 AI forgery lab → L16 S3 enum → L8 final AI strategy)
* **Pack-index v2 streaming parser** in `core/object_engine.py`
* **Curated 22-rule secret engine** with entropy gating in `secrets/patterns.py`
* **sqlmap-style storage layout**: `~/.gitvulture/output/<host>/<utc-ts>/`
* **Index parser** for DIRC v2/v3/v4
* **Reflog ghost recovery** in `ref_discovery.py`

## What was borrowed from competing tools (and from my earlier `gitexpose` prototype)

| Feature                                | Inspired by              |
|----------------------------------------|--------------------------|
| Sqlmap-style severity tags + `-v/-vv/-vvv` | sqlmap (obviously)   |
| Soft-404 calibration via per-host fingerprint | gitexpose         |
| SHA-1 verification of every recovered object | gitexpose          |
| Live `secret_hit()` console line       | gitleaks / trufflehog    |
| Bright-coloured stats panel at end     | nmap / sqlmap            |

## Live verbose output

```
[20:33:04] [INFO] [*] probing target  http://target/.git/  for exposure
[20:33:04] [INFO] [+] exposed .git/ detected via HEAD  →  ref: refs/heads/master
[20:33:04] [INFO] [+] config file readable
[20:33:04] [INFO] [+] directory listing on .git/ is enabled — full mirror possible
─── PHASE 2  ::  REF DISCOVERY ───
[20:33:05] [INFO] [*] fetching 19 well-known git metadata files
[20:33:05] [INFO] [+] recovered  packed-refs  (105B)
[20:33:05] [INFO] [+] recovered  index  (137B)
[20:33:05] [INFO] [+] discovered ref  logs/refs/heads/master
─── PHASE 3  ::  OBJECT ACQUISITION ───
[20:33:05] [INFO] [+] pack idx  pack-99ae90da0b…  →  7 object SHAs
[20:33:05] [INFO] [+] BFS converged: 8 total objects known
─── PHASE 5  ::  SECRET HUNT ───
[20:33:05] [INFO] [+] SECRET high github-pat   deleted.txt  → ghp***********xyz
[20:33:05] [INFO] [+] SECRET high slack-token  deleted.txt  → xox***********pq
```

Add `-v` to also see every individual HTTP request, `-vv` for internal traces,
`-vvv` for outgoing payloads.

## Verbosity tiers (mirrors sqlmap exactly)

| Flag   | Levels shown                                              |
|--------|-----------------------------------------------------------|
| (none) | CRITICAL · ERROR · WARNING · INFO · SUCCESS · PHASE rules |
| `-v`   | + DEBUG (every HTTP transaction, every object stored)     |
| `-vv`  | + TRACE (soft-404 calibration, retries, internal state)   |
| `-vvv` | + PAYLOAD (every URL just before it is sent)              |

## Auto-mode logic (one command = full power)

Running `gitvulture <url>` with no flags will:
1. Calibrate soft-404 for the target host.
2. Probe `HEAD`, `config`, listing, alternates.
3. Pull every well-known `.git/` file.
4. Brute-force 140 common ref paths.
5. Discover pack files (via `objects/info/packs` + dir listing).
6. BFS-walk every commit / tree / blob reachable from refs + index + reflog.
7. Reconstruct the working tree via `git fsck` / `git checkout`.
8. Hunt secrets across every commit diff + dangling blob + reflog ghost.
9. Run the **16-stage escalation ladder** (L1-L7 are mechanical, no AI needed —
   if `EMERGENT_LLM_KEY` is missing, only L6/L8/L12/L15 are skipped).
10. Emit a sqlmap-style stats panel + a JSON report on disk.

Pass `--no-escalate` to stop after step 8, or `--no-ai` to skip every LLM call.

## Install

```bash
git clone https://github.com/sinoolamoo-lgtm/AIGitsploit.git
cd AIGitsploit && bash install.sh
```

(or manually: `pip install -e .` after fetching `emergentintegrations==0.2.0`
from the Emergent private index.)

## Legal

Use only on assets you are **explicitly authorized to test**.
Pass `--i-have-permission` to silence the warning;
pass `--scope HOST_OR_IP` to make GitVulture abort if the target leaves scope.
