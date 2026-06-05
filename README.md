# GitExpose

**Advanced Git Directory Exposure Exploitation Framework** — a CLI tool that
detects exposed `.git/` directories, dumps the entire repository (including
pack files, dangling commits and reflog entries), restores the working tree,
and scans the recovered content for secrets — all with **live, sqlmap-style
verbose output** so you can see exactly what is happening at every moment.

## Why GitExpose vs. git-dumper / GitTools / GitHack

| Capability                              | GitExpose | git-dumper | GitTools/Dumper | GitHack |
|-----------------------------------------|-----------|------------|-----------------|---------|
| Live colored verbose log (`-v/-vv/-vvv`)| ✅        | ❌         | ❌              | ❌      |
| JSON-lines audit log (`--json-log`)     | ✅        | ❌         | ❌              | ❌      |
| Pack-file discovery & explode           | ✅        | ⚠️ partial | ❌              | ❌      |
| Dangling / unreachable blob recovery    | ✅        | ❌         | ❌              | ❌      |
| `logs/HEAD` reflog parsing              | ✅        | ❌         | ❌              | ❌      |
| Index parsing (deleted-but-staged)      | ✅        | ⚠️         | ❌              | ❌      |
| Branch/tag/remote brute force           | ✅        | ❌         | ❌              | ❌      |
| Soft-404 detection (CDN / WAF)          | ✅        | ❌         | ❌              | ❌      |
| Built-in secret scanner (22 rules)      | ✅        | ❌         | ❌              | ❌      |
| Extras probe (.env, .DS_Store, backups) | ✅        | ❌         | ❌              | ❌      |
| HTML + JSON reports                     | ✅        | ❌         | ❌              | ❌      |
| Async concurrency + rate limiting       | ✅        | ⚠️ threads | ⚠️ bash         | ❌      |
| Scope guard (`--scope`, opt-in flag)    | ✅        | ❌         | ❌              | ❌      |

## Install

```bash
pip install -e .
```

(`dulwich`, `aiohttp`, `aiofiles`, `rich` are pulled automatically.)

## Quick start

```bash
# Run against an authorized target with verbose output
gitexpose -u https://target.tld/ -v --i-have-permission

# Self-signed cert / IP target (typical for PortSwigger labs)
gitexpose -u https://54.185.155.123/ --insecure -vv \
          --i-have-permission --scope 54.185.155.123 \
          -o ./loot --report-html loot/report.html

# Through Burp
gitexpose -u https://target.tld/ --proxy http://127.0.0.1:8080 --insecure -vvv
```

## Verbosity tiers (sqlmap-style)

| Flag   | Levels shown                                            |
|--------|---------------------------------------------------------|
| (none) | CRITICAL · ERROR · WARNING · INFO · SUCCESS             |
| `-v`   | + DEBUG (every HTTP transaction)                        |
| `-vv`  | + TRACE (soft-404 calibration, retries, internal state) |
| `-vvv` | + PAYLOAD (every URL just before it is sent)            |

Every line ships with a timestamp `[hh:mm:ss]` and severity tag `[LEVEL]` so
output can be `grep`'d / piped to other tools or stored as JSON-lines via
`--json-log`.

## Phases

1. **detection** — HEAD signature, config marker, directory listing, alternates.
2. **well-known files** — HEAD, ORIG_HEAD, MERGE_HEAD, packed-refs, index, …
3. **refs discovery** — packed-refs + info/refs + brute-force common branches.
4. **pack files** — download `objects/info/packs`, fetch every `.pack` + `.idx`,
   explode into loose objects via `dulwich`.
5. **loose object walk** — BFS from every known SHA (refs + index + reflog).
   When directory listing is enabled, also mirror every `objects/aa/` subdir.
6. **extras** — `.env`, `.DS_Store`, backup files, SSH keys, configs.
7. **restore worktree** — write HEAD's tree out + dump every recovered blob to
   `loot/.gitexpose_all_blobs/` (so even deleted files are inspectable).
8. **secret scan** — 22 high-precision regex rules with Shannon-entropy gating.

## Output layout

```
./gitexpose_loot/
├── .git/                       # full recovered repo (open with `git log` etc.)
├── .gitexpose_all_blobs/       # every blob raw bytes (recoverable secrets)
├── .gitexpose_extras/          # files found by the extras probe
├── <restored source tree>      # HEAD's working copy
└── gitexpose_report.json       # machine-readable summary
```

## Legal

Use only on assets you are **explicitly authorized to test**. Pass
`--i-have-permission` (and ideally `--scope HOST_OR_IP`) to acknowledge.
