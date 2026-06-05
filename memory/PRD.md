# GitExpose – Product Requirements Doc

## Problem Statement (verbatim)
> قمت بتطوير هذه الاداة في منصتكم هذه لكي تساعدني على حل اختبار في منصة web-security-academy.net المشهورة في هذا الاختبار تم وضع سيرفر قانوني لعمل اختبار عليه و هو عبارة عن رقم اي بي و هو ضمن السكوب المسموح بفحصه كما هو موضح في الصورة / حاول ان تعيد قراءة كامل ملفات المشروع و اكتشف الاخطاء البرمجية و المنطقية و الامور المكررة و الامور التي ليس لها قيمة او لا تعمل / ايضا حاول ان تجعلها اكثر قوة و تتفوق على الادوات التي تشبهها في هذا المجال لهذا السبب يجب ان تقوم بمقارنة حقيقية بحيث كل عمل من الاعمال تقوم به هذه الاداة يجب ان يتفوق على العمل الذي تقوم به اداة منافسة لها / هناك مشكلة في تشغيل الاداة و هي عندما اشغلها لا يظهر لي ما الذي يحدث في الوقت الحالي يجب ان نضيف هذه الخاصية تماما مثل اداة sqlmap التي تعرض جميع البيانات للمستخدم لكي يعرف ما الذي يحدث

## User choices
- CLI only (Python, no web UI)
- Go ahead with full implementation; self-critique each step
- Welcome to reuse code/ideas from competing tools

## Architecture
`/app/gitexpose/` Python package, installable via `pip install -e .`
Entry point: `gitexpose` (console script) or `python -m gitexpose`.

```
gitexpose/
├── __main__.py
├── cli.py            # argparse-based CLI, scope guard, reports
├── banner.py         # ASCII banner + legal notice
├── logger.py         # sqlmap-style colored logger (CRITICAL/ERROR/WARN/INFO/SUCCESS/DEBUG/TRACE/PAYLOAD)
├── http_client.py    # aiohttp client w/ retries, soft-404 calibration, proxy, UA rotation
├── settings.py       # well-known files, brute force lists, soft-404 markers
├── core/
│   ├── detector.py   # HEAD signature / config marker / directory listing detection
│   ├── refs.py       # HEAD, packed-refs, info/refs, reflog, brute-force common branches
│   ├── pack.py       # pack discovery + explode via dulwich
│   ├── index.py      # parse .git/index → blob SHAs (incl. staged-but-deleted)
│   ├── objects.py    # parse loose objects, SHA-1 validation, extract referenced SHAs
│   ├── extractor.py  # restore HEAD's tree + dump every recovered blob
│   ├── secrets.py    # 22 high-precision regex rules + Shannon entropy gating
│   └── dumper.py     # 8-phase orchestrator
└── reporters/__init__.py  # JSON + HTML reports
```

## What's implemented (Jan 2026)
- 8 phases: detection → known files → refs → packs → object BFS → object dir mirror → extras → worktree restore → secret scan
- Sqlmap-style **live verbose** output with timestamps and severity tags + 3 verbose tiers (`-v`, `-vv`, `-vvv`)
- Async HTTP with concurrency, retries, rate limiting, soft-404 calibration, UA rotation, proxy, basic auth, custom headers/cookies, TLS skip
- Pack file explode via dulwich (works for newest dulwich 1.x API)
- Reflog (`logs/HEAD`) parsing → discovers commits unreachable from refs
- Index parsing → discovers staged-but-deleted file blobs
- Brute-force list for common branches/tags/remotes
- Secret scanner with 22 rules (AWS, GitHub, GitLab, Slack, Google, Stripe, JWT, PEM, generic password/apikey, MongoDB/Postgres/MySQL/Redis URIs, etc.)
- All recovered blobs dumped to `.gitexpose_all_blobs/` so even deleted-file content is scannable
- HTML + JSON reports; JSON-lines audit log via `--json-log`
- Scope guard (`--scope`, `--i-have-permission`)

## Backlog / P1
- Optional `rich.progress` progress bar during object BFS
- Smart retry with TLS fallback (auto-suggest `--insecure` on cert error)
- Resume mode that picks up interrupted dumps from disk state
- Plugin mechanism for custom secret rules (YAML file)

## P2 / Future
- gRPC + WebSocket bridge so an external dashboard can subscribe to the JSON log live
- Built-in patch viewer that shows diff per commit
- GitHub search integration (find token's true owner)
- Distributed mode (split object BFS across workers via Redis)

## Next Action Items
- Try against the lab: `gitexpose -u https://54.185.155.123/ --insecure --i-have-permission --scope 54.185.155.123 -vv -o ./loot --report-html ./loot/report.html`
