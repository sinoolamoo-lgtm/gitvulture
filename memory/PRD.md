# GitVulture v1.2 PRD — Validated on web-security-academy lab

## Lab validation result (Stage 1 - Easy, https://54.185.155.123/)
GitVulture **fully compromised** the lab target with a SINGLE command:

```bash
gitvulture https://54.185.155.123/ --insecure --i-have-permission \
           --scope 54.185.155.123 --no-ai
```

### Loot recovered automatically
- **2 × RSA 2048-bit private keys** (validated with `openssl rsa`)
  - `keys/diskover-web_privatekey.pem` (1704 B)
  - `keys/diskover_privatekey.pem` (1683 B)
- **Live source code**: `login.php`, `nav.php`, `utils.js`, `.gitignore`, `.gitattributes`
- **App reconnaissance**: 4 `.DS_Store`, 4 images
- **Repository fingerprint**: `git@github.com:diskoverdata/license-admin.git`
- **Branch**: `feature/permission-model`
- **Developer**: Bobby Painter `<bobby.painter@diskoverdata.com>`
- **Login form** at `/login.php` with CSRF token captured

### Stages executed (auto-cascade, no AI required)
```
PHASE 1 :: RECONNAISSANCE
PHASE 2 :: REF DISCOVERY
PHASE 3 :: OBJECT ACQUISITION
PHASE 4 :: REPOSITORY RECONSTRUCTION
PHASE 5 :: SECRET HUNT
PHASE 8 :: ESCALATION LADDER (L1-L16)
    L01 :: HARDENED .GIT BYPASS STORM       0 hits
    L02 :: UPSTREAM REPOSITORY PIVOT        4 hits  ← GitHub org discovered
    L03 :: INDEX → ENDPOINT SYNTHESIS       5 hits  ← live endpoints
    L04 :: HIDDEN FILE PROBES               1 hit   ← .DS_Store leaked
    L05 :: AUTH SURFACE FINGERPRINT         1 hit   ← login form + CSRF
    L07 :: SECRET SUPER-SCAN                0 hits
    L09 :: AGGRESSIVE BLOB RETRIEVAL        14 hits ← KEYS + SOURCE
    L10 :: PACK FILE HUNT                   0 hits
    L11 :: RECOVERED SOURCE SUPER-SCAN      2 hits  ← key-content secrets
    L13 :: SQL INJECTION PROBING            10 hits
    L14 :: CRYPTO ATTACKS                   0 hits
    L16 :: AWS S3 ENUMERATION               0 hits
    (L6/L8/L12/L15 skipped because --no-ai)
```
Total: **12 stages / 1019 probes / 113.89 s** for full takedown.

## Bug fixes shipped this session (round 2)
1. `escalation.py` L2: `rstrip(".git")` would chop random chars from SSH URLs.
   Replaced with proper suffix-stripping.
2. `escalation.py` L2: enhanced to enumerate the org's public repos (sibling
   repos can leak the same source even when the canonical repo is private).
3. `escalation.py` L3/L4/L5/L9: added live `[+]` success lines so each
   discovered endpoint / login form / recovered blob is announced.
4. `escalation.py` L14: scoped JWT testing to the actual target host only
   (was probing github.com & web.archive.org → 79 false-positive findings).
5. `crypto_attack.py`: added baseline-response comparison; a forged token now
   counts as "accepted" only when it materially changes the server's reply.
6. `cli.py`: `--no-ai` now removes EMERGENT_LLM_KEY from env so escalation
   AI stages (L6/L8/L12/L15) get skipped gracefully.
7. `cli.py`: added a **LOOT table** at the end that highlights private keys
   in red and tags source files with content hints.

## Auto-escalation behavior (as requested)
Default `gitvulture <url>` triggers escalation **automatically** at every step.
Each `L#` stage feeds its findings to the next via shared `artifacts` /
`report.discovered_endpoints`, so:
- L2's org enumeration informs L9's upstream fallback
- L3's live endpoints feed L13 (SQLi) and L14 (JWT testing)
- L9's recovered private keys feed L14's RS256/HS256 forgery attempts
- L11's recovered source feeds L7's super secret scan
- L15 (AI forgery lab) ingests everything for synthesized exploits

No flag is required. To disable, pass `--no-escalate`.

## Next action items
- Stage 2/3 of the same lab (Locked) — once URLs known, run again with
  `--scope 54.185.155.123` and the dynamic medium-stage path.
- Add `--auto-stop-on-loot` flag for users who only want exposure detection +
  first secret hit, then bail.
- Optional `--unmask-secrets` to print full key bytes instead of redacted form
  (gated behind `--i-have-permission`).
