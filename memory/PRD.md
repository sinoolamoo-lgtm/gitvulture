# GitVulture v1.3 — AI Exploitation Roadmap shipped

## Latest milestone (this session)
Added the **`--exploit-roadmap`** flag that produces an AI-generated, ranked
exploitation plan with ready-to-paste commands.

### How it works
After all scan phases + escalation finish, the orchestrator collects:
- recon (server, WAF, branch, repo URL, dev email)
- recovered files (paths, sizes, source previews ≤1.5 KB each)
- private-key inventory (presence + algorithm)
- git history (commits, dangling, reflog)
- detected secrets
- live endpoints + their status/size
- escalation hit counts per stage

…serializes it into a ≤50 KB JSON bundle and sends it to Claude
(`claude-sonnet-4-6` via `emergentintegrations.llm.chat.LlmChat` and the
universal Emergent LLM key). The system prompt asks for STRICT JSON with:
- executive summary
- detected lab pattern (portswigger/htb/thm/none)
- overall confidence
- 3 ranked scenarios — each with title, rationale, impact, effort, confidence,
  step list, ready-to-run shell/curl commands, mitigations to bypass
- research questions for additional time budget
- "do not retry" — vectors already proven dead

### Validated against the PortSwigger lab (https://54.185.155.123/)
Run command:
```bash
gitvulture https://54.185.155.123/ --insecure --i-have-permission \
           --scope 54.185.155.123 --exploit-roadmap
```
Result (~364 s total, 2 AI calls):

1. **#1 Forge Admin JWT via Leaked Keys**  — confidence **high**, ~10 min
   * Step list + 9 ready commands including PyJWT signing script
   * Identifies leaked keys as Diskover license-signing material
2. **#2 SQL Injection via License API**  — confidence medium, ~25 min
   * 10 ready commands including sqlmap + INTO OUTFILE webshell PoC
3. **#3 GitHub Repo History Secret Harvest**  — confidence medium, ~15 min
   * git clone + trufflehog walkthrough

The AI also produced 2 follow-up research questions and a "do not retry"
list (.git bypass, pack hunt, S3 enum, alg=none confusion — all proven dead
on this target).

## Cumulative bug fixes / improvements across sessions
1. Removed `rich.Progress` spinner → live sqlmap-style streaming logger
2. Sqlmap-style severity tags + `-v / -vv / -vvv` tiers
3. 403 bypass scoped to 401/403 only (no more 404 storms)
4. Soft-404 calibration per host
5. `git fsck`-compatible `.git/refs/` layout
6. BFS skips pack-only SHAs
7. `--no-ai` propagates to escalation (removes EMERGENT_LLM_KEY from env)
8. L2 upstream pivot: proper suffix stripping + GitHub org sibling repo enum
9. L14 crypto attacks: scoped to target host only + baseline comparison →
   eliminated 79 false positives
10. LOOT table in CLI summary — highlights private keys in red
11. AI-powered exploitation roadmap (THIS SESSION)

## Files of interest
- `/app/gitvulture/ai/exploit_roadmap.py` — the new module
- `/app/gitvulture/logger.py` — sqlmap-style logger
- `/app/gitvulture/core/orchestrator.py` — phase 9 wiring
- `/app/gitvulture/cli.py` — `--exploit-roadmap` flag + roadmap render
- `/app/scripts/jwt_forge_attack.py` — standalone JWT forgery PoC
- `/app/scripts/auth_brute.py` — Basic-Auth + form-login brute
- `/tmp/lablootput2/gitvulture-report.json` — full validated lab report

## Next action items (handoff to user)
- Stage 2/3 of the lab need the user to submit Stage-1 evidence in the
  PortSwigger lab UI to reveal the medium-stage hash.
- Execute Scenario #1 from the AI roadmap once that hash is known.
- For deeper persistence, consider L17 (built-in Basic-Auth brute) and
  L18 (license-forgery PoC) as future additions.

## Backlog
- `--exploit-roadmap` should optionally dump the bundle JSON to disk for
  manual review (`--save-roadmap-bundle`).
- HTML report for the roadmap (currently console + JSON only).
- Live-tail mode that streams the AI response token-by-token via SSE.
