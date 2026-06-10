#!/usr/bin/env python3
"""GitVulture - CLI entry point.

ONE-COMMAND DEFAULTS
--------------------
    gitvulture https://target.tld/

…will detect .git exposure, dump every recoverable object/pack/blob,
reconstruct the repo, hunt secrets across all commits + dangling
objects + reflog, then climb the 16-level escalation ladder. Each
stage is announced live, sqlmap-style, with timestamped severity tags.

Flags
-----
    -v / -vv / -vvv     verbose tiers (sqlmap-style)
    -q                  quiet (only errors / success / phase rules)
    --no-color          disable ANSI colours
    --no-ai             disable LLM calls (mechanical-only mode)
    --no-escalate       stop after the standard 7-phase scan
    --offensive         allow active probes (default-creds POST, SQLi, etc.)
    --insecure          ignore self-signed / hostname-mismatch TLS
    --proxy URL         single proxy
    --proxy-list FILE   rotating proxies (one per line)
    --json              also dump final report to stdout as JSON
    --list-targets      list past scans stored under ~/.gitvulture/output/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

# Load env files BEFORE any code that reads EMERGENT_LLM_KEY
try:
    from dotenv import load_dotenv  # type: ignore
    for candidate in [
        Path("/app/backend/.env"),
        Path.home() / ".gitvulture.env",
        Path.cwd() / ".env",
    ]:
        if candidate.exists():
            load_dotenv(candidate, override=False)
except Exception:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .core.orchestrator import ScanOptions, run_scan
from .logger import init_logger, get_logger
from .storage import default_base_dir, list_targets, new_scan_dir, slugify_host

BANNER = r"""
   ____ _ _ __     __    _ _                
  / ___(_) |\ \   / /   _| | |_ _   _ _ __ ___ 
 | |  _| | __\ \ / / | | | | __| | | | '__/ _ \
 | |_| | | |_ \ V /| |_| | | |_| |_| | | |  __/
  \____|_|\__| \_/  \__,_|_|\__|\__,_|_|  \___|
        .git exposure exploitation framework  v1.1
        live verbose · packed objects · dangling recovery · AI escalation
"""


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="gitvulture",
        description="One-command .git directory exposure exploitation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Target URL, e.g. https://victim.com")
    p.add_argument("-o", "--output", default=None,
                   help="Output directory (default: ~/.gitvulture/output/<host>/<ts>/)")
    p.add_argument("--list-targets", action="store_true",
                   help="List all targets stored in ~/.gitvulture/output/ and exit.")

    # Verbosity
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v debug, -vv trace, -vvv payload (every URL)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Only critical/error/success/phase lines")
    p.add_argument("--no-color", action="store_true",
                   help="Disable colored output")
    p.add_argument("--plain", action="store_true",
                   help="Force PLAIN print() output (no rich, no ANSI, no panels). "
                        "Use this if the tool looks frozen or prints garbage. "
                        "Works on every terminal that ever existed.")
    p.add_argument("--log-file", help="Write full plain-text log to file")
    p.add_argument("--json-log", help="Write structured JSON-lines log to file")

    # AI gating
    p.add_argument("--ai", action="store_true",
                   help="Enable AI triage + roadmap (default: OFF; AI is "
                        "opt-in to avoid noise and only fires on demand)")
    p.add_argument("--no-ai", action="store_true",
                   help="(legacy) Force disable LLM calls — kept for compat")
    p.add_argument("--no-escalate", action="store_true",
                   help="Stop after standard 7-phase scan (skip L1-L16 ladder)")
    p.add_argument("--escalate", action="store_true",
                   help="(alias / no-op — escalation runs by default; use "
                        "--no-escalate to opt out)")
    p.add_argument("--no-sast", action="store_true",
                   help="Skip the SAST (C1) static-analysis phase. SAST runs "
                        "by default if semgrep is installed.")
    p.add_argument("--origin-discovery", action="store_true",
                   help="D2 — try to find the real origin IP behind a CDN/WAF "
                        "via crt.sh + DNS permutations. Adds verified IPs to scope.")
    p.add_argument("--exploit-roadmap", action="store_true",
                   help="After scan, ask Claude (strict-mode, evidence-cited) "
                        "for a ranked exploitation plan. Implies --ai.")
    p.add_argument("--interactive", "-i", action="store_true",
                   help="Open interactive TUI: navigate phases manually, "
                        "back/forward/skip, ask AI only on demand")
    p.add_argument("--offensive", action="store_true",
                   help="Allow active probes (SQLi payloads, default-creds POST)")
    p.add_argument("--proxy-auth", metavar="USER:PASS",
                   help="Inject credentials into --proxy URL "
                        "(for residential proxies)")

    # HTTP
    p.add_argument("--no-bypass-403", action="store_true",
                   help="Disable 403 bypass tricks")
    p.add_argument("--insecure", action="store_true",
                   help="Ignore SSL cert errors (hostname mismatch, self-signed)")
    p.add_argument("--rotate-ua", action="store_true",
                   help="Rotate User-Agent on every request")
    p.add_argument("--user-agent", help="Override default User-Agent header")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Custom header `Name: value` (repeatable)")
    p.add_argument("--cookies", help="Cookie header value (`a=1; b=2`)")
    p.add_argument("--auth", help="HTTP Basic auth on target: user:pass")
    p.add_argument("--proxy", help="Single proxy URL (HTTP/SOCKS)")
    p.add_argument("--proxy-list", help="File with one proxy URL per line")
    p.add_argument("--rate-limit", type=float, default=30.0,
                   help="Max req/sec (default 30)")
    p.add_argument("--concurrency", type=int, default=20,
                   help="Parallel requests (default 20)")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--verify-secrets", action="store_true",
                   help="OPT-IN: live-check leaked tokens against issuer APIs")
    p.add_argument("--s3-bucket", action="append", default=[],
                   help="Extra S3 bucket name/URL to enumerate in L16 (repeatable)")

    # Output
    p.add_argument("--json", action="store_true",
                   help="Also print final report as JSON to stdout")
    p.add_argument("--scope", action="append", default=[],
                   help="Whitelist host/IP (abort if target host not listed)")
    p.add_argument("--i-have-permission", action="store_true",
                   help="Acknowledge you are authorized to test this target")
    p.add_argument("--doctor", action="store_true",
                   help="Print environment self-check (Python, OS, terminal, "
                        "ANSI support, env vars) and exit. Use this first if "
                        "the tool looks frozen or printed garbage.")
    return p.parse_args(argv)


def _run_doctor() -> int:
    """Environment self-check — prints ONE LINE AT A TIME so the user can
    see immediately if stdout is alive. No rich, no buffering, no magic."""
    import platform
    import time
    print("=" * 60, flush=True)
    print(" gitvulture --doctor  (live self-check)", flush=True)
    print("=" * 60, flush=True)
    checks = [
        ("python",         lambda: sys.version.split()[0]),
        ("executable",     lambda: sys.executable),
        ("platform",       lambda: platform.platform()),
        ("stdout TTY",     lambda: str(sys.stdout.isatty())),
        ("stdout encoding", lambda: sys.stdout.encoding or "?"),
        ("PYTHONUNBUFFERED", lambda: os.environ.get("PYTHONUNBUFFERED", "(not set)")),
        ("PYTHONIOENCODING", lambda: os.environ.get("PYTHONIOENCODING", "(not set)")),
        ("EMERGENT_LLM_KEY", lambda: "present" if os.environ.get("EMERGENT_LLM_KEY") else "MISSING"),
        ("rich version",   lambda: __import__("importlib.metadata", fromlist=["version"]).version("rich")),
    ]
    if sys.platform == "win32":
        checks.append(("colorama", lambda: __import__("colorama").__version__))
        checks.append(("ANSI VT mode", lambda: "enabled (os.system(''))"))

    for name, fn in checks:
        try:
            value = fn()
        except Exception as e:
            value = f"ERROR ({e!r})"
        print(f"  {name:>20} : {value}", flush=True)
        time.sleep(0.05)  # visual proof of live flushing

    print("-" * 60, flush=True)
    print(" colour test (you should see RED, GREEN, BLUE words below):",
          flush=True)
    print("   \033[31mRED\033[0m  \033[32mGREEN\033[0m  \033[34mBLUE\033[0m",
          flush=True)
    print(" If those words show as raw '[31mRED[0m' text, your terminal",
          flush=True)
    print(" does not support ANSI. Use --no-color or upgrade the terminal.",
          flush=True)
    print("-" * 60, flush=True)
    print(" heartbeat test (1 dot per second for 5 seconds):", flush=True)
    for i in range(5):
        print(f"  tick {i+1}/5  t={i+1}s", flush=True)
        time.sleep(1)
    print("=" * 60, flush=True)
    print(" Self-check complete. If you saw the dots appear one by one,",
          flush=True)
    print(" live output is working. Now try a real scan, e.g.:", flush=True)
    print("   gitvulture https://target.tld --insecure --i-have-permission",
          flush=True)
    print("=" * 60, flush=True)
    return 0


async def _main_async(args) -> int:
    # --doctor must run BEFORE rich init, so a broken rich install can't
    # block the self-check itself.
    if args.doctor:
        return _run_doctor()

    # Promote to plain mode automatically if env var GITVULTURE_PLAIN=1
    plain_mode = args.plain or bool(os.environ.get("GITVULTURE_PLAIN"))

    if plain_mode:
        # Bare ASCII banner — no rich, no ANSI, works everywhere.
        for line in BANNER.splitlines():
            print(line, flush=True)
        print(flush=True)
        # Tiny shim so the rest of _main_async (which uses console.print)
        # still works without branching everywhere.
        class _PlainConsole:
            def print(self, *a, **kw):
                import re
                msg = " ".join(str(x) for x in a) if a else ""
                msg = re.sub(r"\[/?[a-zA-Z0-9_# ]+\]", "", msg)
                print(msg, flush=True)
            def print_json(self, s, **kw):
                print(s, flush=True)
        console = _PlainConsole()
    else:
        console = Console(no_color=args.no_color)
        console.print(Panel.fit(BANNER, border_style="bright_green"))

    # ------------------------------ utility: list targets
    if args.list_targets:
        targets = list_targets()
        if not targets:
            console.print(f"[yellow]No targets stored yet. Default location: "
                          f"{default_base_dir()/'output'}[/yellow]")
            return 0
        for t in targets:
            console.print(f"\n[bold cyan]{t['host']}[/bold cyan]  "
                          f"({len(t['scans'])} scans, latest: {t['latest']})")
            for s in t['scans'][:5]:
                ico = "✓" if s['has_report'] else "·"
                console.print(f"  {ico} {s['name']}  {s['size_kb']} KB  {s['path']}")
        return 0

    if not args.target and not args.interactive:
        console.print("[red]error:[/red] target URL is required "
                      "(or use --interactive / --list-targets)")
        return 2

    # ------------------------------ Interactive mode short-circuit
    if args.interactive:
        # Init a lightweight logger for the interactive runner
        init_logger(
            verbose=args.verbose,
            quiet=args.quiet,
            no_color=args.no_color,
        )
        from .interactive import InteractiveRunner
        runner = InteractiveRunner(console)
        if args.target:
            runner.state.target_url = args.target.rstrip("/")
        if args.proxy:
            proxy = args.proxy
            if args.proxy_auth:
                from urllib.parse import urlparse, urlunparse
                u = urlparse(proxy)
                netloc = f"{args.proxy_auth}@{u.hostname}:{u.port}" if u.port \
                         else f"{args.proxy_auth}@{u.hostname}"
                proxy = urlunparse((u.scheme, netloc, u.path or "", "", "", ""))
            runner.state.proxy = proxy
        return await runner.run()

    # ------------------------------ legal scope gate
    from urllib.parse import urlparse
    host = urlparse(args.target).hostname or ""
    if args.scope and host not in args.scope:
        console.print(
            f"[red]error:[/red] target host '{host}' is not in --scope whitelist "
            f"{args.scope}"
        )
        return 2
    if not args.i_have_permission:
        console.print(
            "[yellow]![/yellow] [bold]Legal notice:[/bold] use only on targets you are "
            "[bold green]explicitly authorized[/bold green] to test."
        )
        console.print(
            "[yellow]![/yellow] (pass --i-have-permission to silence this warning)\n"
        )

    # ------------------------------ init live logger
    log = init_logger(
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color,
        log_file=Path(args.log_file) if args.log_file else None,
        json_log_file=Path(args.json_log) if args.json_log else None,
        plain=plain_mode,
    )

    # ------------------------------ proxy list
    proxies: list[str] = []
    if args.proxy_list:
        proxies = [line.strip() for line in Path(args.proxy_list).read_text().splitlines()
                   if line.strip() and not line.startswith("#")]

    # ------------------------------ output dir
    if args.output:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = new_scan_dir(args.target)

    # ------------------------------ build scan opts
    # AI is now OPT-IN only (was opt-out). Use --ai or --exploit-roadmap.
    user_wants_ai = (args.ai or args.exploit_roadmap) and not args.no_ai
    ai_enabled = user_wants_ai and bool(os.environ.get("EMERGENT_LLM_KEY"))
    if args.no_ai or not user_wants_ai:
        log.info("AI disabled (lazy mode): mechanical-only")
        # Hide the key from ALL downstream code (escalation reads env directly)
        os.environ.pop("EMERGENT_LLM_KEY", None)
    elif user_wants_ai and not os.environ.get("EMERGENT_LLM_KEY"):
        log.warning("EMERGENT_LLM_KEY missing — AI stages will be skipped")
    escalate = not args.no_escalate
    sast = not args.no_sast

    # Inject proxy auth if provided separately
    proxy = args.proxy
    if proxy and args.proxy_auth:
        # Convert proxy://host:port → proxy://user:pass@host:port
        from urllib.parse import urlparse, urlunparse
        u = urlparse(proxy)
        netloc = f"{args.proxy_auth}@{u.hostname}:{u.port}" if u.port \
                 else f"{args.proxy_auth}@{u.hostname}"
        proxy = urlunparse((u.scheme, netloc, u.path or "", "", "", ""))

    # Parse -H headers into dict
    extra_headers: dict = {}
    for h in (args.header or []):
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()

    auth_tuple = None
    if args.auth and ":" in args.auth:
        u, _, pw = args.auth.partition(":")
        auth_tuple = (u, pw)

    opts = ScanOptions(
        target_url=args.target.rstrip("/"),
        output_dir=out_dir,
        ai_triage=ai_enabled,
        verify_secrets=args.verify_secrets,
        insecure_ssl=args.insecure,
        bypass_403=not args.no_bypass_403,
        ua_rotate=args.rotate_ua,
        proxy=proxy,
        proxy_list=proxies,
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        timeout=args.timeout,
        escalate=escalate,
        offensive=args.offensive,
        s3_hints=args.s3_bucket,
        exploit_roadmap=args.exploit_roadmap and ai_enabled,
        extra_headers=extra_headers,
        cookies=args.cookies,
        user_agent=args.user_agent,
        auth=auth_tuple,
        sast=sast,
        origin_discovery=args.origin_discovery,
    )

    log.kv("target", opts.target_url)
    log.kv("output", str(opts.output_dir))
    log.kv("mode", ("auto + AI" if ai_enabled and escalate
                    else "auto (no AI)" if escalate
                    else "minimal"))
    log.kv("offensive", "ON" if args.offensive else "off")
    console.print()

    # ------------------------------ Run! NO Progress widget anymore — the live
    # logger emits its own sqlmap-style lines as the scan progresses.
    log.start_heartbeat(interval=2.0)
    try:
        result = await run_scan(opts)
    finally:
        log.stop_heartbeat()

    log.stats_panel()

    # ------------------------------ post-scan summary tables
    if not result.recon or not result.recon.exposed:
        console.print(Panel(
            "[red]No .git exposure detected at target.[/red]",
            border_style="red"
        ))
        return 1

    rebuild = result.rebuild
    console.print()
    console.print(Panel.fit(
        f"[green]✓ Exposure confirmed.[/green]  "
        f"HEAD: [white]{result.recon.head_ref}[/white]  "
        f"WAF: [white]{result.recon.waf or 'none'}[/white]  "
        f"detection: [white]{result.recon.detection_method or '-'}[/white]",
        border_style="green",
    ))

    if rebuild:
        t = Table(title="Repository Reconstruction", title_style="bold cyan")
        t.add_column("Metric")
        t.add_column("Value")
        t.add_row("HEAD branch", str(rebuild.head_branch))
        t.add_row("Branches", ", ".join(rebuild.branches) or "-")
        t.add_row("Tags", ", ".join(rebuild.tags) or "-")
        t.add_row("Total commits", str(len(rebuild.commits)))
        t.add_row("Dangling commits", str(len(rebuild.dangling_commits)))
        t.add_row("Dangling blobs", str(len(rebuild.dangling_blobs)))
        t.add_row("fsck errors", str(len(rebuild.fsck_errors)))
        t.add_row("Files on HEAD", str(len(rebuild.files_on_head)))
        t.add_row("Packs", str(result.pack_count))
        console.print(t)

        if rebuild.commits:
            ct = Table(title="Commit Timeline (newest first)", title_style="bold cyan")
            ct.add_column("SHA")
            ct.add_column("Date")
            ct.add_column("Author")
            ct.add_column("Message")
            for c in rebuild.commits[:30]:
                ct.add_row(c.sha[:10], c.date[:10],
                           c.author[:30], c.message[:80])
            console.print(ct)

    if result.index_entries:
        it = Table(title=f"Index Entries ({len(result.index_entries)} files)",
                   title_style="bold cyan")
        it.add_column("Mode")
        it.add_column("Blob SHA")
        it.add_column("Path")
        for e in result.index_entries[:60]:
            it.add_row(oct(e.mode), e.sha1[:10], e.path)
        console.print(it)

    if result.findings:
        st = Table(title=f"Secrets ({len(result.findings)})",
                   title_style="bold red")
        st.add_column("Severity")
        st.add_column("Rule")
        st.add_column("File")
        st.add_column("Value (redacted)")
        st.add_column("Source")
        for f in sorted(result.findings,
                        key=lambda x: ["critical", "high", "medium", "low"].index(x.severity)):
            sev_color = {"critical": "red", "high": "red",
                         "medium": "yellow", "low": "white"}[f.severity]
            st.add_row(f"[{sev_color}]{f.severity}[/{sev_color}]",
                       f.rule_id, f.file_path[:40], f.redacted, f.source)
        console.print(st)
    else:
        console.print("[yellow]No hard-coded secrets detected.[/yellow]")

    if result.ai_report:
        console.print(Panel.fit(
            "[bold green]AI TRIAGE[/bold green]\n\n" +
            json.dumps(result.ai_report, indent=2)[:4000],
            border_style="green",
        ))

    if result.escalation:
        console.print(Panel.fit(
            "[bold magenta]ESCALATION SUMMARY[/bold magenta]\n\n" +
            json.dumps(result.escalation.get("summary", {}), indent=2)[:2000],
            border_style="magenta",
        ))

    # ------------------------------ AI EXPLOIT ROADMAP
    if result.exploit_roadmap and not result.exploit_roadmap.get("error"):
        rm = result.exploit_roadmap
        console.print()
        console.rule("[bold red]EXPLOIT ROADMAP (AI-generated)[/bold red]", style="red")
        if rm.get("summary"):
            console.print(Panel(rm["summary"], title="executive summary",
                                  border_style="red", padding=(0, 1)))
        if rm.get("lab_pattern") and rm["lab_pattern"] != "none":
            console.print(f"  [yellow]lab pattern detected:[/yellow] "
                          f"[bold]{rm['lab_pattern']}[/bold]")
        if rm.get("overall_confidence"):
            console.print(f"  [yellow]overall confidence:[/yellow] "
                          f"[bold]{rm['overall_confidence']}[/bold]\n")
        for s in rm.get("scenarios", []):
            conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(
                s.get("confidence", "medium"), "white")
            console.print(Panel.fit(
                f"[bold cyan]#{s.get('rank', '?')}  {s.get('title', '')}[/bold cyan]\n"
                f"[bright_black]impact:[/bright_black] {s.get('impact', '-')}\n"
                f"[bright_black]effort:[/bright_black] ~{s.get('effort_minutes', '?')} min   "
                f"[bright_black]confidence:[/bright_black] "
                f"[{conf_color}]{s.get('confidence', '-')}[/{conf_color}]\n"
                f"[bright_black]rationale:[/bright_black] {s.get('rationale', '-')}",
                border_style=conf_color,
            ))
            if s.get("exploit_steps"):
                console.print("  [bold]exploit_steps:[/bold]")
                for i, step in enumerate(s["exploit_steps"], 1):
                    console.print(f"    [cyan]{i:>2}.[/cyan] {step}")
            if s.get("ready_commands"):
                console.print("  [bold]ready_commands:[/bold]")
                for cmd in s["ready_commands"]:
                    console.print(f"    [green]$[/green] [white]{cmd}[/white]")
            if s.get("mitigations_to_bypass"):
                console.print("  [bold]mitigations to bypass:[/bold]")
                for m in s["mitigations_to_bypass"]:
                    console.print(f"    [yellow]•[/yellow] {m}")
            console.print()
        if rm.get("research_questions"):
            console.print("[bold]research questions to investigate:[/bold]")
            for q in rm["research_questions"]:
                console.print(f"  [yellow]?[/yellow] {q}")
        if rm.get("do_not_retry"):
            console.print("\n[bold]do NOT retry these vectors:[/bold]")
            for d in rm["do_not_retry"]:
                console.print(f"  [bright_black]×[/bright_black] {d}")
        console.print()
    elif result.exploit_roadmap and result.exploit_roadmap.get("error"):
        console.print(f"[red]exploit roadmap error:[/red] "
                      f"{result.exploit_roadmap['error']}")

    # ------------------------------ LOOT SUMMARY (highest-value artifacts)
    recovered_dir = opts.output_dir / "recovered_source"
    if recovered_dir.exists():
        recovered_files = sorted(p for p in recovered_dir.rglob("*") if p.is_file())
        if recovered_files:
            console.print()
            lt = Table(
                title=f"[bold green]LOOT — Recovered files ({len(recovered_files)})[/bold green]",
                title_style="bold green",
                show_lines=False,
            )
            lt.add_column("Path", style="white")
            lt.add_column("Size", justify="right", style="cyan")
            lt.add_column("Type", style="yellow")
            high_value_extensions = {".pem", ".key", ".pfx", ".p12",
                                     ".env", ".ini", ".conf", ".php",
                                     ".sql", ".js", ".py", ".rb", ".go",
                                     ".java", ".cs", ".sh"}
            for p in recovered_files:
                rel = p.relative_to(recovered_dir)
                size = p.stat().st_size
                # Detect interesting content
                tag = ""
                if p.suffix.lower() in (".pem", ".key"):
                    tag = "[bold red]PRIVATE KEY[/bold red]"
                elif p.suffix.lower() == ".php" and b"password" in p.read_bytes()[:8192].lower():
                    tag = "[red]password ref[/red]"
                elif p.suffix.lower() in high_value_extensions:
                    tag = "source"
                else:
                    tag = "asset"
                lt.add_row(str(rel), f"{size}B", tag)
            console.print(lt)

    console.print(f"\n[bold]Report saved:[/bold] {opts.output_dir}/gitvulture-report.json")
    console.print(f"[bold]Recovered source:[/bold] {opts.output_dir}/recovered_source/")
    if result.secrets_dir:
        n = len(result.findings or [])
        if n:
            console.print(
                f"[bold red]🔑  Secrets ({n}) saved to:[/bold red] {result.secrets_dir}/"
            )
            console.print(
                f"    └─ open  [cyan]{result.secrets_dir}/secrets.md[/cyan]   for the human report"
            )
            console.print(
                f"    └─ files [cyan]{result.secrets_dir}/files/[/cyan]       verbatim copies of .env / .pem / etc."
            )
        else:
            console.print(
                f"[bold]Secrets folder:[/bold] {result.secrets_dir}/ [bright_black](empty — no findings)[/bright_black]"
            )
    if result.sast_dir:
        if result.sast_sinks:
            console.print(
                f"[bold yellow]⚠  SAST sinks ({result.sast_sinks}) saved to:[/bold yellow] {result.sast_dir}/"
            )
            console.print(
                f"    └─ open  [cyan]{result.sast_dir}/sast.md[/cyan]            grouped by severity"
            )
            console.print(
                f"    └─ open  [cyan]{result.sast_dir}/by-endpoint.md[/cyan]     pivoted by live route"
            )
        else:
            console.print(
                f"[bold]SAST folder:[/bold] {result.sast_dir}/ [bright_black](no sinks)[/bright_black]"
            )
    # Scope-audit pointer (E1)
    audit_path = opts.output_dir / "scope-audit.jsonl"
    if audit_path.exists():
        console.print(
            f"[bold]Scope audit:[/bold] {audit_path} [bright_black](every HTTP decision)[/bright_black]"
        )
    # L3 endpoints
    if result.endpoints_found:
        live_marker = (f" — [bold green]{result.live_reachable} live on target[/bold green]"
                       if result.live_reachable else "")
        console.print(
            f"[bold]Endpoints discovered (L3):[/bold] {result.endpoints_found}{live_marker}"
        )
        console.print(
            f"    └─ open  [cyan]{opts.output_dir}/endpoints.md[/cyan]    discovered routes"
        )
        if (opts.output_dir / "live-diff.md").exists():
            console.print(
                f"    └─ open  [cyan]{opts.output_dir}/live-diff.md[/cyan]    source ↔ deployment diff"
            )
    # D2 origin discovery
    if result.origin_candidates:
        v = result.origin_verified
        console.print(
            f"[bold]D2 Origin discovery:[/bold] {result.origin_candidates} candidates, "
            f"[bold green]{v} verified[/bold green]"
        )
        if (opts.output_dir / "origin-discovery.json").exists():
            console.print(
                f"    └─ open  [cyan]{opts.output_dir}/origin-discovery.json[/cyan]"
            )
    if args.json:
        console.print_json(json.dumps(result.to_dict(), default=str))
    log.close()
    return 0


def main():
    # ------------------------------------------------------------------ #
    # CRITICAL: defeat block-buffering of stdout/stderr.
    # Without this, on Windows CMD / PowerShell / when piped through tee or
    # ssh, the user sees a frozen screen for minutes while output piles up
    # in an 8 KB kernel buffer. This is THE reason the tool looked "dead".
    # ------------------------------------------------------------------ #
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    try:
        sys.stdout.reconfigure(line_buffering=True)   # type: ignore[attr-defined]
        sys.stderr.reconfigure(line_buffering=True)   # type: ignore[attr-defined]
    except Exception:
        pass

    # On Windows 10/11, ANSI escape sequences are disabled by default in
    # conhost. We must explicitly enable Virtual Terminal Processing,
    # otherwise rich prints raw `[90m[INFO][0m` literals on the screen.
    if sys.platform == "win32":
        # Trick: os.system("") initializes VT100 mode without running anything.
        try:
            os.system("")
        except Exception:
            pass
        # colorama is the bullet-proof fallback for older / hosted shells.
        try:
            import colorama  # type: ignore
            if hasattr(colorama, "just_fix_windows_console"):
                colorama.just_fix_windows_console()
            else:
                colorama.init()
        except Exception:
            pass

    args = parse_args()
    try:
        sys.exit(asyncio.run(_main_async(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
