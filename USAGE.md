# GitVulture — Complete Usage Guide

> Every command-line option, with a copy-pasteable example for each.
> Every line you see in the terminal is live, timestamped, and sqlmap-style.

## Installation

### Linux / macOS / WSL
```bash
git clone https://github.com/sinoolamoo-lgtm/AIGitsploit.git
cd AIGitsploit
chmod +x install.sh
./install.sh
# add ~/.local/bin to PATH if the installer warned you
export PATH="$HOME/.local/bin:$PATH"
gitvulture --help
```

### Windows
```powershell
git clone https://github.com/sinoolamoo-lgtm/AIGitsploit.git
cd AIGitsploit
powershell -ExecutionPolicy Bypass -File install.ps1
# open a NEW terminal so PATH refreshes
gitvulture --help
```

Or double-click **`install.bat`** (CMD edition). It auto-installs Python 3.12
and Git via `winget`, clones the repo into `%USERPROFILE%\gitvulture`, writes
the LLM key to `%USERPROFILE%\.gitvulture\config.env`, and drops a launcher
on your `PATH` (`%USERPROFILE%\AppData\Local\Microsoft\WindowsApps\gitvulture.bat`).

### Docker — zero-install, fully isolated
```bash
docker build -t gitvulture .
# show help
docker run --rm -it gitvulture --help
# real run (persist output to ./output on the host)
docker run --rm -it \
    -e EMERGENT_LLM_KEY=$EMERGENT_LLM_KEY \
    -v "$PWD/output:/root/.gitvulture/output" \
    gitvulture https://target.example.com --ai --escalate -vv --insecure
```
The container uses Python 3.12-slim + git, installs `emergentintegrations`
from Emergent's index, and exposes `/root/.gitvulture` as a volume so loot
survives container removal.

Both installers (Linux/macOS/Windows):
- create a virtualenv at `~/.gitvulture/venv`
- write `~/.gitvulture/config.env` containing your `EMERGENT_LLM_KEY`
  (pre-filled with the bundled universal key — you can paste your own)
- drop a `gitvulture` wrapper into `~/.local/bin` (or `%USERPROFILE%\.gitvulture\bin`)
  that auto-loads the config on every run

## Verbosity tiers — read the live output like sqlmap

| flag | what you see |
|------|--------------|
| (none) | CRITICAL · ERROR · WARNING · INFO · SUCCESS · PHASE rules |
| `-v`   | + DEBUG: every HTTP transaction, every object stored |
| `-vv`  | + TRACE: soft-404 calibration, retries, internal state |
| `-vvv` | + PAYLOAD: every URL just before it is sent |

Every line looks like sqlmap: `[hh:mm:ss] [LEVEL] symbol message`.

## All options — one example per flag

### Target & output
```bash
# Minimum command — auto-detects exposure, dumps everything, runs L1–L16 ladder
gitvulture https://target.tld/

# Custom output directory
gitvulture https://target.tld/ -o ./my-loot

# List previously scanned targets
gitvulture --list-targets
```

### Verbosity & logging
```bash
# Quiet (only errors / success / phase rules)
gitvulture https://target.tld/ -q

# Debug — every HTTP transaction
gitvulture https://target.tld/ -v

# Trace — internals, retries, soft-404 calibration
gitvulture https://target.tld/ -vv

# Maximum — every outgoing payload URL
gitvulture https://target.tld/ -vvv

# No ANSI colors (good for piping into files)
gitvulture https://target.tld/ --no-color

# Mirror everything to a plain-text log file
gitvulture https://target.tld/ --log-file /tmp/scan.log

# Mirror everything to JSON-Lines (one event per line — pipe into jq)
gitvulture https://target.tld/ --json-log /tmp/scan.jsonl
```

### AI gating (lazy — opt-in only)
```bash
# Disable AI explicitly (default since v1.4)
gitvulture https://target.tld/ --no-ai

# Enable AI triage
gitvulture https://target.tld/ --ai

# Generate the strict-mode AI exploitation roadmap (3 ranked scenarios,
# each with evidence_citations verified against the artefact bundle)
gitvulture https://target.tld/ --ai --exploit-roadmap

# Skip the L1–L16 escalation ladder (just the 7-phase core scan)
gitvulture https://target.tld/ --no-escalate
```

### Interactive TUI mode (menu-driven workflow)
```bash
# Launch without a target — you'll be prompted
gitvulture --interactive

# Launch with a target pre-loaded
gitvulture --interactive https://target.tld/

# Inside the TUI you can use: back · forward · skip · redo
#                              status · proxy · ai · help · quit
```

### Authentication / scope guard
```bash
# Acknowledge you are authorized (silences the legal warning)
gitvulture https://target.tld/ --i-have-permission

# Restrict the scope — abort if the target host isn't whitelisted
gitvulture https://target.tld/ --i-have-permission --scope target.tld

# Multiple scopes
gitvulture https://target.tld/ --scope target.tld --scope 10.0.0.5
```

### Performance tuning
```bash
# Concurrency (default 20)
gitvulture https://target.tld/ --concurrency 50

# Per-worker rate limit (default 30 req/s aggregate)
gitvulture https://target.tld/ --rate-limit 5

# Request timeout (seconds)
gitvulture https://target.tld/ --timeout 30
```

### TLS / WAF evasion
```bash
# Ignore self-signed certs / hostname mismatches (e.g. PortSwigger labs)
gitvulture https://54.185.155.123/ --insecure

# Rotate User-Agent on every request
gitvulture https://target.tld/ --rotate-ua

# Disable the 403-bypass storm
gitvulture https://target.tld/ --no-bypass-403
```

### Proxy — including authenticated residential
```bash
# Plain HTTP proxy
gitvulture https://target.tld/ --proxy http://10.10.10.10:8080

# Authenticated residential proxy (inline)
gitvulture https://target.tld/ --proxy http://user:pass@residential.example.com:8000

# Authenticated proxy (creds passed separately — cleaner shell history)
gitvulture https://target.tld/ \
    --proxy http://residential.example.com:8000 \
    --proxy-auth alice:s3cret

# SOCKS5 with auth
gitvulture https://target.tld/ --proxy socks5://alice:s3cret@127.0.0.1:1080

# Rotating proxy list (one URL per line)
gitvulture https://target.tld/ --proxy-list ./proxies.txt
```

### Custom headers / cookies / basic-auth
```bash
# Single header
gitvulture https://target.tld/ -H "Authorization: Bearer ey..."

# Multiple headers
gitvulture https://target.tld/ -H "X-Forwarded-For: 127.0.0.1" -H "X-Test: yes"

# Override the User-Agent
gitvulture https://target.tld/ --user-agent "Mozilla/5.0 (CustomBot)"

# Cookie header
gitvulture https://target.tld/ --cookies "PHPSESSID=abc; theme=dark"

# HTTP Basic Auth on the target itself
gitvulture https://target.tld/ --auth admin:hunter2
```

### Phase control & active probing
```bash
# Enable offensive probes (SQLi payloads, default-creds POST, JWT forgery)
gitvulture https://target.tld/ --offensive

# Live-verify any leaked tokens against the real issuer APIs
# (opt-in — sends each token to api.github.com / etc.)
gitvulture https://target.tld/ --verify-secrets

# Add a known S3 bucket name for L16 enumeration
gitvulture https://target.tld/ --s3-bucket my-cool-bucket --s3-bucket backup-cool
```

### Report output
```bash
# Print final report as JSON to stdout in addition to the file
gitvulture https://target.tld/ --json
```

## A single command using every safe-to-combine flag

```bash
gitvulture https://54.185.155.123/ \
    -vv --no-color \
    -o ./loot-$(date +%s) \
    --log-file ./loot.log \
    --json-log ./loot.jsonl \
    --insecure --rotate-ua \
    --i-have-permission --scope 54.185.155.123 \
    --concurrency 25 --rate-limit 40 --timeout 12 \
    --proxy http://corp.proxy:3128 \
    --proxy-auth alice:s3cret \
    -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Original-URL: /admin" \
    --cookies "PHPSESSID=demo" \
    --user-agent "Mozilla/5.0 GitVultureRecon" \
    --offensive --verify-secrets \
    --s3-bucket diskover-backup \
    --ai --exploit-roadmap \
    --json
```

This **one command** activates:
- `-vv` sqlmap-style verbose with TRACE detail
- structured plain-text + JSON-lines audit log
- TLS-insecure mode + UA rotation
- scope guard + legal acknowledgment
- concurrency/rate-limit/timeout tuning
- authenticated residential proxy
- two custom headers + cookie + custom UA
- active offensive probes + live secret verification
- additional S3 bucket hint
- AI strict-mode triage + verified exploitation roadmap
- JSON final report to stdout

(No mutually exclusive flags are used. The only one not included is
`--no-ai`/`--no-escalate`/`--no-bypass-403` which would *disable* features.)

## Reading the output

### Phase rules
The `─── PHASE n :: TITLE ───` lines mark the major scan phases:
```
PHASE 1 :: RECONNAISSANCE
PHASE 2 :: REF DISCOVERY
PHASE 3 :: OBJECT ACQUISITION
PHASE 4 :: REPOSITORY RECONSTRUCTION
PHASE 5 :: SECRET HUNT
PHASE 8 :: ESCALATION LADDER (L1-L16)
PHASE 9 :: AI EXPLOITATION ROADMAP
```

### LOOT table
At the end, GitVulture prints a table highlighting the highest-value
artefacts. Private keys are bolded red. PHP/source files referencing
`password` get a yellow tag.

### Strict-mode warnings
If the AI emits a citation that doesn't resolve in the artefact bundle,
you'll see:
```
[12:34:56] [WARNING] [!]   AI verifier: scenario 'SQL injection' — invalid citations: ['escalation.hit_count_per_stage["SQL Injection"]']
[12:34:56] [INFO]    [+] roadmap verified  →  3 scenarios kept (1 warnings)
```
Downgraded scenarios get a `[partially verified]` prefix; rejected ones
disappear entirely. Filename hallucinations in the prose summary are
inline-wrapped with `[HALLUCINATED:name.ext]`.

## Quick recipes

```bash
# 1. Audit-friendly run (full log + report)
gitvulture https://target.tld/ -vv \
    --log-file audit.log --json-log audit.jsonl \
    --i-have-permission --scope target.tld

# 2. Stealth (slow + UA-rotated + residential)
gitvulture https://target.tld/ \
    --rate-limit 1 --concurrency 2 --rotate-ua \
    --proxy http://user:pass@res-proxy.com:8000 \
    --i-have-permission --scope target.tld

# 3. Full exploit pipeline (AI roadmap + offensive)
gitvulture https://target.tld/ \
    --offensive --ai --exploit-roadmap -vv \
    --i-have-permission --scope target.tld

# 4. Mechanical-only (zero LLM calls, zero cost)
gitvulture https://target.tld/ --no-ai \
    --i-have-permission --scope target.tld

# 5. Interactive (you drive)
gitvulture --interactive
```

## Legal

Use only against assets you are **explicitly authorized to test** —
bug-bounty scopes, CTF labs (HTB / TryHackMe / PortSwigger), your own
infrastructure. Pass `--i-have-permission` and `--scope` to make your
intent explicit. The maintainers assume no liability for misuse.
