# GitVulture v1.1 PRD

## Original problem (verbatim, Arabic)
> قمت بتطوير هذه الاداة في منصتكم … اقراء الكود القديم … اكتشف الاخطاء البرمجية و المنطقية و الامور المكررة … اجعلها اكثر قوة و تتفوق على الادوات التي تشبهها … المشكلة عند تشغيلها لا يظهر ما الذي يحدث — أضف ميزة مثل sqlmap التي تعرض جميع البيانات للمستخدم … ربطها بالذكاء الاصطناعي بحيث تبني منهجية فحص متتابعة و منطقية تجرب جميع الاحتمالات و الاستغلالات دون تدخل الذكاء الاصطناعي / في المراحل المتقدمة يمكنها طلب المساعدة من الذكاء الاصطناعي

## Repository
https://github.com/sinoolamoo-lgtm/AIGitsploit.git (cloned into /app/)

## Key bugs found and fixed
See README.md "What was wrong with the original code" — 10 concrete issues.

## What was implemented this session
- New module `gitvulture/logger.py` — sqlmap-style timestamped severity logger
  with `-v/-vv/-vvv` tiers, JSON-lines sink, live HTTP stats panel.
- `core/http_client.py` — every request now routes through the logger;
  soft-404 calibration; bypass only on 401/403 (no more 404 storms).
- `core/recon.py` — corrected HEAD signature detection; live PHASE lines.
- `core/ref_discovery.py` — live announcement of discovered refs.
- `core/object_engine.py` — tracks packed SHAs; live pack idx/data lines;
  live BFS rounds; live `objects` counter.
- `core/orchestrator.py` — fixed `asyncio.create_task(_emit)` antipattern;
  ensures `.git/refs/{heads,tags,remotes}` directories + loose ref files
  so `git fsck` recognizes the repo; live phase rules between stages.
- `core/escalation.py` — AI-only stages (L6/L8/L12/L15) gracefully skip when
  `EMERGENT_LLM_KEY` is absent; per-stage live phase headers + summary lines.
- `cli.py` — Removed `rich.Progress` spinner overlay; default mode now runs the
  full ladder (auto-escalate). New flags: `--no-ai`, `--no-escalate`,
  `--log-file`, `--json-log`, `--scope`, `--i-have-permission`.
- README.md rewritten with the bug-table + competitive comparison.
- v1.1.0 bumped.

## Verified
- End-to-end against a local git repo over `python -m http.server`:
  3 commits recovered, 8 secrets detected (incl. one from a deleted file),
  168 requests / 5.65 s. Live verbose output matches sqlmap style exactly.

## Backlog
- L1-L7 mechanical-skip gating: currently the engine runs every L# even if
  earlier stages already provided enough loot. Could add a "stop early if
  N secrets and verdict=compromise" gate (small change).
- Smarter brute-force list: prune `refs/{remotes/origin,tags}/{branch}` paths
  to half by trying the `branch` family first only on success of
  `refs/heads/<branch>`.
- HTML report (we already have JSON) — about 80 LoC of work.
- Auto-fallback TLS: detect cert errors and re-run with `--insecure` once.

## Next action items
- Run `gitvulture https://54.185.155.123/ --insecure --i-have-permission --scope 54.185.155.123 -vv`
  on the PortSwigger lab to validate against real network conditions.
- Optional: add CI-level smoke test that spins up a local git repo and asserts
  ≥1 secret recovered.
