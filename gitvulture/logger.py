"""Sqlmap-style live verbose logger for GitVulture.

This is the single source of truth for runtime output. Every component (HTTP
client, recon, ref discovery, object engine, escalation, AI triage) routes
its messages through this logger so the user sees one continuous, timestamped
narrative — exactly like sqlmap.

Severity matrix
---------------
CRITICAL  – fatal condition (red bg, always shown)
ERROR     – recoverable error (red, always shown)
WARNING   – heads-up (yellow, always shown)
INFO      – default progress line (cyan, always shown)
SUCCESS   – positive milestone (green plus sign, always shown)
PHASE     – horizontal rule between phases (magenta, always shown)
DEBUG     – per-request / per-object detail, shown from -v
TRACE     – internal state, shown from -vv
PAYLOAD   – outgoing URL/method before request, shown from -vvv

Each line is formatted as:
    [hh:mm:ss] [LEVEL] symbol message
exactly like sqlmap's own log lines, e.g.:
    [12:34:56] [INFO] resuming back-end DBMS 'mysql'
"""
from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, TextIO

from rich.console import Console
from rich.theme import Theme


def _windows_ansi_works() -> bool:
    """Best-effort detection: does this Windows terminal accept ANSI?

    Returns True if either:
      - WT_SESSION env var is set (Windows Terminal — always ANSI-capable), or
      - ANSICON / ConEmuANSI are set, or
      - colorama.just_fix_windows_console() exists and succeeds, or
      - The console mode includes ENABLE_VIRTUAL_TERMINAL_PROCESSING.
    On any failure, return False so the caller falls back to plain print().
    """
    import os
    if os.environ.get("WT_SESSION") or os.environ.get("ANSICON") or \
       os.environ.get("ConEmuANSI") == "ON":
        return True
    try:
        import colorama  # type: ignore
        if hasattr(colorama, "just_fix_windows_console"):
            colorama.just_fix_windows_console()
        else:
            colorama.init(autoreset=False, strip=False, convert=True)
        return True
    except Exception:
        pass
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        STD_OUTPUT_HANDLE = -11
        ENABLE_VT = 0x0004
        h = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(h, mode.value | ENABLE_VT)
        return True
    except Exception:
        return False

LEVEL_STYLES = {
    "CRITICAL": "bold white on red",
    "ERROR":    "bold red",
    "WARNING":  "yellow",
    "INFO":     "cyan",
    "SUCCESS":  "bold green",
    "PHASE":    "bold magenta",
    "DEBUG":    "magenta",
    "TRACE":    "bright_black",
    "PAYLOAD":  "blue",
}

LEVEL_SYMBOL = {
    "CRITICAL": "[!]",
    "ERROR":    "[x]",
    "WARNING":  "[!]",
    "INFO":     "[*]",
    "SUCCESS":  "[+]",
    "PHASE":    "[#]",
    "DEBUG":    "[.]",
    "TRACE":    "[~]",
    "PAYLOAD":  "[>]",
}

# Minimum levels shown at each -v count
VERBOSE_GATES = {
    0: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "PHASE"},
    1: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "PHASE", "DEBUG"},
    2: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "PHASE",
        "DEBUG", "TRACE"},
    3: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "PHASE",
        "DEBUG", "TRACE", "PAYLOAD"},
}


class Logger:
    """Thread-safe colored logger + optional log/JSON-lines sinks.

    Has TWO output backends:
      * rich  (pretty colours, used when terminal supports ANSI)
      * plain (bare print() + flush=True, used when rich/ANSI is unreliable
              - typically on old Windows CMD, redirected stdout, CI logs)

    The plain backend is the *guaranteed-to-work-everywhere* path. If the
    user passes --plain or auto-detect says ANSI is unsupported, we use it.
    """

    # Strip rich markup like [bold]x[/bold] for the plain backend
    _MARKUP_RE = None  # lazy

    def __init__(
        self,
        verbose: int = 0,
        quiet: bool = False,
        no_color: bool = False,
        log_file: Optional[Path] = None,
        json_log_file: Optional[Path] = None,
        plain: bool = False,
    ) -> None:
        self.verbose = max(0, min(3, verbose))
        self.quiet = quiet
        self.start_time = time.monotonic()
        self._lock = threading.Lock()
        self._allowed = VERBOSE_GATES[self.verbose]

        # ------------------------------------------------------------ plain?
        # Auto-promote to plain on Windows when neither colorama nor VT mode
        # could give us ANSI support. This is the safety net that makes the
        # tool look alive even on the most hostile terminal.
        if not plain and sys.platform == "win32" and not no_color:
            plain = not _windows_ansi_works()
        self.plain = plain

        if self.plain:
            self.console = None  # marker
        else:
            theme = Theme(
                {f"lvl.{k.lower()}": v for k, v in LEVEL_STYLES.items()}
            )
            self.console = Console(
                theme=theme,
                no_color=no_color,
                force_terminal=None if no_color else True,
                force_interactive=False,
                highlight=False,
                soft_wrap=False,
            )

        self._log_fp: Optional[TextIO] = None
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            self._log_fp = open(log_file, "a", encoding="utf-8")
        self._json_fp: Optional[TextIO] = None
        if json_log_file:
            json_log_file.parent.mkdir(parents=True, exist_ok=True)
            self._json_fp = open(json_log_file, "a", encoding="utf-8")

        # Live counters
        self.stats: dict[str, int] = {
            "requests": 0, "ok": 0, "not_found": 0, "redirects": 0,
            "errors": 0, "bypass_hits": 0, "bytes": 0,
            "objects": 0, "secrets": 0, "ai_calls": 0,
        }

        # Heartbeat ticker (sqlmap-style "alive" pulse)
        self._hb_stop: Optional[threading.Event] = None
        self._hb_thread: Optional[threading.Thread] = None
        self._last_output_at: float = time.monotonic()

    # ------------------------------------------------------------------ #
    @classmethod
    def _strip_markup(cls, s: str) -> str:
        """Remove rich markup like [bold red]...[/bold red] for plain output.

        We must preserve genuinely-literal brackets (rich escapes them as `\\[`).
        Algorithm: temporarily replace `\\[` and `\\]` with placeholders, strip
        markup tags, restore placeholders as bare `[` `]`.
        """
        if cls._MARKUP_RE is None:
            import re
            cls._MARKUP_RE = re.compile(r"\[/?[a-zA-Z0-9_# ]+\]")
        ESC_OPEN = "\x00GVO\x00"
        ESC_CLOSE = "\x00GVC\x00"
        s = s.replace("\\[", ESC_OPEN).replace("\\]", ESC_CLOSE)
        s = cls._MARKUP_RE.sub("", s)
        return s.replace(ESC_OPEN, "[").replace(ESC_CLOSE, "]")

    def _print(self, msg: str) -> None:
        """Single write site that hits both backends safely."""
        if self.plain or self.console is None:
            # Bare print() — bullet-proof, line-buffered when stdout is
            # line_buffering=True (which CLI main() ensures).
            print(self._strip_markup(msg), flush=True)
        else:
            try:
                self.console.print(msg, markup=True, highlight=False)
            except Exception:
                # If rich blows up at runtime, fall back to plain for ALL
                # subsequent calls so the user never sees a silent freeze.
                self.plain = True
                print(self._strip_markup(msg), flush=True)

    # ------------------------------------------------------------------ #
    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _emit(self, level: str, message: str, **extra: Any) -> None:
        if self.quiet and level not in {"CRITICAL", "ERROR", "SUCCESS", "PHASE"}:
            return
        if level not in self._allowed:
            self._write_sinks(level, message, extra)
            return
        with self._lock:
            ts = self._ts()
            sym = LEVEL_SYMBOL[level]
            style = LEVEL_STYLES[level]
            tag = "INFO" if level == "SUCCESS" else level
            self._print(
                f"[bright_black]\\[{ts}][/bright_black] "
                f"[{style}]\\[{tag}][/{style}] {sym} {message}"
            )
            self._last_output_at = time.monotonic()
            self._write_sinks(level, message, extra)

    def _write_sinks(self, level: str, message: str, extra: dict) -> None:
        if self._log_fp:
            self._log_fp.write(
                f"[{datetime.now().isoformat(timespec='seconds')}] [{level}] {message}\n"
            )
            self._log_fp.flush()
        if self._json_fp:
            self._json_fp.write(json.dumps({
                "ts": datetime.now().isoformat(),
                "level": level, "message": message, **extra,
            }, ensure_ascii=False) + "\n")
            self._json_fp.flush()

    # ------------------------------------------------------------------ #
    # Public severity API
    def critical(self, msg: str, **kw):
        self._emit("CRITICAL", msg, **kw)

    def error(self, msg: str, **kw):
        self.stats["errors"] += 1
        self._emit("ERROR", msg, **kw)

    def warning(self, msg: str, **kw):
        self._emit("WARNING", msg, **kw)

    def info(self, msg: str, **kw):
        self._emit("INFO", msg, **kw)

    def success(self, msg: str, **kw):
        self._emit("SUCCESS", msg, **kw)

    def debug(self, msg: str, **kw):
        self._emit("DEBUG", msg, **kw)

    def trace(self, msg: str, **kw):
        self._emit("TRACE", msg, **kw)

    def payload(self, msg: str, **kw):
        self._emit("PAYLOAD", msg, **kw)

    def phase(self, name: str) -> None:
        """Big horizontal rule between phases."""
        with self._lock:
            if self.plain or self.console is None:
                bar = "=" * 78
                print(bar, flush=True)
                print(f"  PHASE :: {name}", flush=True)
                print(bar, flush=True)
            else:
                try:
                    self.console.rule(f"[bold magenta]{name}[/bold magenta]",
                                      style="bright_black")
                except Exception:
                    self.plain = True
                    print(f"=== PHASE :: {name} ===", flush=True)
            self._last_output_at = time.monotonic()
        self._write_sinks("PHASE", name, {})

    def kv(self, key: str, value: str) -> None:
        with self._lock:
            self._print(
                f"    [bright_black]{key:>22}[/bright_black]  [white]{value}[/white]"
            )
            self._last_output_at = time.monotonic()

    # ------------------------------------------------------------------ #
    # HTTP transaction (called from every request site)
    def http(self, method: str, url: str, status: int,
             size: int = 0, bypass: Optional[str] = None) -> None:
        self.stats["requests"] += 1
        self.stats["bytes"] += size
        if status == 0:
            color, label = "red", "ERR"
        elif 200 <= status < 300:
            self.stats["ok"] += 1
            if bypass:
                self.stats["bypass_hits"] += 1
            color, label = "green", str(status)
        elif 300 <= status < 400:
            self.stats["redirects"] += 1
            color, label = "yellow", str(status)
        elif status == 404:
            self.stats["not_found"] += 1
            color, label = "bright_black", "404"
        else:
            color, label = "red", str(status)

        # Build human line
        url_short = url if len(url) <= 88 else url[:85] + "..."
        tag = f" [magenta][{bypass}][/magenta]" if bypass else ""
        line = f"[{color}]{label}[/{color}] {method:<4} {url_short}{tag}  [dim]{size}B[/dim]"
        # Errors / >=400 are visible by default at -v ≥ 0 only as DEBUG
        if status == 0 or status >= 500:
            self.debug(line)
        elif 200 <= status < 300 or bypass:
            # Success or any bypass hit: visible from -v
            self.debug(line)
        elif self.verbose >= 1:
            self.debug(line)
        else:
            self._write_sinks("DEBUG",
                              f"{label} {method} {url} {size}B {bypass or ''}", {})

    # ------------------------------------------------------------------ #
    def secret_hit(self, rule: str, file_path: str, redacted: str,
                   severity: str = "high") -> None:
        self.stats["secrets"] += 1
        sev_color = {"critical": "bold red",
                     "high": "red",
                     "medium": "yellow",
                     "low": "white"}.get(severity, "white")
        self._emit("SUCCESS",
                   f"[bold red]SECRET[/bold red] [{sev_color}]{severity}[/{sev_color}] "
                   f"{rule}  [white]{file_path}[/white]  → [yellow]{redacted}[/yellow]")

    def ai(self, msg: str) -> None:
        self.stats["ai_calls"] += 1
        self._emit("INFO", f"[bold blue]AI[/bold blue] {msg}")

    # ------------------------------------------------------------------ #
    def stats_panel(self) -> None:
        elapsed = time.monotonic() - self.start_time
        with self._lock:
            if self.plain or self.console is None:
                print("", flush=True)
                print("=" * 78, flush=True)
                print("  session stats", flush=True)
                print("=" * 78, flush=True)
                for k, v in self.stats.items():
                    print(f"    {k:>14}  {v}", flush=True)
                print(f"    {'elapsed':>14}  {elapsed:.2f}s", flush=True)
                print("", flush=True)
            else:
                self.console.print()
                self.console.rule("[bold magenta]session stats[/bold magenta]",
                                  style="magenta")
                for k, v in self.stats.items():
                    self.console.print(
                        f"    [bright_black]{k:>14}[/bright_black]  [bold]{v}[/bold]"
                    )
                self.console.print(
                    f"    [bright_black]{'elapsed':>14}[/bright_black]  [bold]{elapsed:.2f}s[/bold]"
                )
                self.console.print()

    def close(self) -> None:
        self.stop_heartbeat()
        if self._log_fp:
            self._log_fp.close()
        if self._json_fp:
            self._json_fp.close()

    # ------------------------------------------------------------------ #
    # Heartbeat ticker — emits a "still alive" pulse whenever there has
    # been silence for > `interval` seconds. This is what makes sqlmap's
    # output feel responsive even during slow probes. Without it, users
    # think the tool is frozen.
    def start_heartbeat(self, interval: float = 2.0) -> None:
        if self._hb_thread is not None:
            return
        self._hb_stop = threading.Event()
        self._last_output_at = time.monotonic()

        def _tick() -> None:
            assert self._hb_stop is not None
            while not self._hb_stop.wait(interval):
                # Respect quiet mode — heartbeat is purely cosmetic
                if self.quiet:
                    continue
                now = time.monotonic()
                # Only beat if there was actual silence
                if now - self._last_output_at < interval * 0.9:
                    continue
                elapsed = now - self.start_time
                with self._lock:
                    self._print(
                        f"[bright_black]\\[{self._ts()}][/bright_black] "
                        f"[bright_black]\\[TICK][/bright_black] [.] "
                        f"{self.stats['requests']} req · "
                        f"{self.stats['ok']} ok · "
                        f"{self.stats['bypass_hits']} bypass · "
                        f"{self.stats['objects']} obj · "
                        f"elapsed {elapsed:.1f}s"
                    )
                    self._last_output_at = now

        self._hb_thread = threading.Thread(
            target=_tick, name="gv-heartbeat", daemon=True
        )
        self._hb_thread.start()

    def stop_heartbeat(self) -> None:
        if self._hb_stop is not None:
            self._hb_stop.set()
        self._hb_thread = None
        self._hb_stop = None


# ---------------------------------------------------------------------- #
# Module-level singleton (configured once from CLI)
_LOGGER: Optional[Logger] = None


def init_logger(**kwargs: Any) -> Logger:
    global _LOGGER
    _LOGGER = Logger(**kwargs)
    return _LOGGER


def get_logger() -> Logger:
    global _LOGGER
    if _LOGGER is None:
        _LOGGER = Logger()
    return _LOGGER
