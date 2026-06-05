"""CLI entry point."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

from rich.console import Console

from . import banner
from .core.dumper import GitDumper
from .http_client import HttpClient
from .logger import init_logger
from .reporters import write_html, write_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gitexpose",
        description="Advanced Git Directory Exposure Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  gitexpose -u https://target.tld/                 # full scan + dump
  gitexpose -u https://1.2.3.4/ -o ./loot -vv      # verbose, custom output
  gitexpose -u https://t.tld/ --proxy http://127.0.0.1:8080 --insecure
  gitexpose -u https://t.tld/ --header "Authorization: Bearer X" --cookies "s=1"
""",
    )
    p.add_argument("-u", "--url", required=True, help="Target base URL (e.g. https://target.tld/)")
    p.add_argument("-o", "--output", default="./gitexpose_loot", help="Output directory")
    p.add_argument("-c", "--concurrency", type=int, default=16, help="Concurrent requests")
    p.add_argument("-t", "--timeout", type=float, default=15.0, help="Request timeout (s)")
    p.add_argument("--retries", type=int, default=3, help="HTTP retries on 5xx/timeout")
    p.add_argument("--rate-limit", type=float, default=0.0, help="Per-worker delay (s)")
    p.add_argument("--proxy", help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--rotate-ua", action="store_true", help="Rotate User-Agent per request")
    p.add_argument("--user-agent", help="Override User-Agent header")
    p.add_argument("-H", "--header", action="append", default=[], help="Extra header (repeatable)")
    p.add_argument("--cookies", help="Cookie header value")
    p.add_argument("--auth", help="HTTP basic auth user:pass")

    # Verbosity
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v debug, -vv trace, -vvv payload")
    p.add_argument("-q", "--quiet", action="store_true", help="Only critical/error/success")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--log-file", help="Write plain-text log to file")
    p.add_argument("--json-log", help="Write structured JSON-Lines log to file")

    # Phase toggles
    p.add_argument("--no-extras", action="store_true", help="Skip extra-file probing (.env, backups…)")
    p.add_argument("--no-packs", action="store_true", help="Skip pack file processing")
    p.add_argument("--no-secrets", action="store_true", help="Skip secret scanning")
    p.add_argument("--no-restore", action="store_true", help="Skip worktree restoration")

    # Authorization gating
    p.add_argument("--i-have-permission", action="store_true",
                   help="Acknowledge you are authorized to test the target")
    p.add_argument("--scope", action="append", default=[],
                   help="Whitelist host/IP (repeat). Abort if target outside.")

    # Reports
    p.add_argument("--report-json", help="Path to JSON report")
    p.add_argument("--report-html", help="Path to HTML report")

    return p


def parse_headers(raw: list[str]) -> dict:
    out: dict[str, str] = {}
    for h in raw:
        if ":" not in h:
            continue
        k, _, v = h.partition(":")
        out[k.strip()] = v.strip()
    return out


async def amain(args: argparse.Namespace) -> int:
    console = Console(no_color=args.no_color)
    banner.print_banner(console)
    banner.legal_warning(console)

    log = init_logger(
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color,
        log_file=Path(args.log_file) if args.log_file else None,
        json_log_file=Path(args.json_log) if args.json_log else None,
    )

    # Scope check
    parsed = urlparse(args.url)
    target_host = parsed.hostname or ""
    if args.scope and target_host not in args.scope:
        log.critical(f"Target host {target_host} is not in --scope whitelist {args.scope}")
        return 2
    if not args.i_have_permission:
        log.warning(
            "You have not passed --i-have-permission. Make sure you are "
            "authorized to test this target."
        )

    extra_headers = parse_headers(args.header)
    if args.user_agent:
        extra_headers["User-Agent"] = args.user_agent

    auth = None
    if args.auth and ":" in args.auth:
        u, _, pw = args.auth.partition(":")
        auth = (u, pw)

    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    log.info(f"output directory: {out_dir}")

    async with HttpClient(
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit=args.rate_limit,
        proxy=args.proxy,
        verify_tls=not args.insecure,
        extra_headers=extra_headers,
        rotate_ua=args.rotate_ua,
        cookies=args.cookies,
        auth=auth,
    ) as client:
        dumper = GitDumper(
            target=args.url,
            out_dir=out_dir,
            client=client,
            skip_extras=args.no_extras,
            skip_packs=args.no_packs,
            skip_secrets=args.no_secrets,
            skip_restore=args.no_restore,
        )
        stats = await dumper.run()

    if args.report_json:
        write_json(stats, Path(args.report_json))
        log.success(f"JSON report → {args.report_json}")
    if args.report_html:
        write_html(stats, Path(args.report_html))
        log.success(f"HTML report → {args.report_html}")

    # Always emit a JSON next to output
    auto_report = out_dir / "gitexpose_report.json"
    write_json(stats, auto_report)
    log.success(f"summary report → {auto_report}")

    log.close()
    return 0 if stats.git_root else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(amain(args))
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
