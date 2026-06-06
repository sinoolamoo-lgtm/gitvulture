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
    p.add_argument("--log-file", help="Write full plain-text log to file")
    p.add_argument("--json-log", help="Write structured JSON-lines log to file")

    # AI gating
    p.add_argument("--no-ai", action="store_true",
                   help="Disable all LLM calls (mechanical-only mode)")
    p.add_argument("--no-escalate", action="store_true",
                   help="Stop after standard 7-phase scan (skip L1-L16 ladder)")
    p.add_argument("--offensive", action="store_true",
                   help="Allow active probes (SQLi payloads, default-creds POST)")

    # HTTP
    p.add_argument("--no-bypass-403", action="store_true",
                   help="Disable 403 bypass tricks")
    p.add_argument("--insecure", action="store_true",
                   help="Ignore SSL cert errors (hostname mismatch, self-signed)")
    p.add_argument("--rotate-ua", action="store_true",
                   help="Rotate User-Agent on every request")
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
    return p.parse_args(argv)


async def _main_async(args) -> int:
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

    if not args.target:
        console.print("[red]error:[/red] target URL is required (or use --list-targets)")
        return 2

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
    ai_enabled = not args.no_ai and bool(os.environ.get("EMERGENT_LLM_KEY"))
    if args.no_ai:
        log.info("AI disabled (--no-ai): running mechanical-only")
        # Hide the key from ALL downstream code (escalation reads env directly)
        os.environ.pop("EMERGENT_LLM_KEY", None)
    elif not os.environ.get("EMERGENT_LLM_KEY"):
        log.warning("EMERGENT_LLM_KEY missing — AI stages will be skipped")
    escalate = not args.no_escalate

    opts = ScanOptions(
        target_url=args.target.rstrip("/"),
        output_dir=out_dir,
        ai_triage=ai_enabled,
        verify_secrets=args.verify_secrets,
        insecure_ssl=args.insecure,
        bypass_403=not args.no_bypass_403,
        ua_rotate=args.rotate_ua,
        proxy=args.proxy,
        proxy_list=proxies,
        rate_limit=args.rate_limit,
        concurrency=args.concurrency,
        timeout=args.timeout,
        escalate=escalate,
        offensive=args.offensive,
        s3_hints=args.s3_bucket,
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
    result = await run_scan(opts)

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
    if args.json:
        console.print_json(json.dumps(result.to_dict(), default=str))
    log.close()
    return 0


def main():
    args = parse_args()
    try:
        sys.exit(asyncio.run(_main_async(args)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
