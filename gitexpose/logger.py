"""
Sqlmap-style colored verbose logger.

Critique vs. competition:
- git-dumper uses plain print() with no levels and no timestamps.
- GitTools/Dumper uses bash `echo` without structure.
- We expose 5 levels (CRITICAL/ERROR/WARN/INFO/SUCCESS) + 3 verbose tiers
  (DEBUG/TRACE/PAYLOAD), live stats, and a structured JSON log sink so output
  can be tailed by other tools.
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

LEVEL_COLORS = {
    "CRITICAL": "bold white on red",
    "ERROR": "bold red",
    "WARNING": "yellow",
    "INFO": "cyan",
    "SUCCESS": "bold green",
    "DEBUG": "magenta",
    "TRACE": "bright_black",
    "PAYLOAD": "blue",
}

LEVEL_TAGS = {
    "CRITICAL": "CRITICAL",
    "ERROR": "ERROR",
    "WARNING": "WARNING",
    "INFO": "INFO",
    "SUCCESS": "INFO",  # sqlmap prints success as plus
    "DEBUG": "DEBUG",
    "TRACE": "TRACE",
    "PAYLOAD": "PAYLOAD",
}

LEVEL_SYMBOLS = {
    "CRITICAL": "[!]",
    "ERROR": "[x]",
    "WARNING": "[!]",
    "INFO": "[*]",
    "SUCCESS": "[+]",
    "DEBUG": "[#]",
    "TRACE": "[.]",
    "PAYLOAD": "[>]",
}

# Verbosity gating: minimum level shown for given -v count
# 0 = default, 1 = -v, 2 = -vv, 3 = -vvv
VERBOSE_MATRIX = {
    0: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS"},
    1: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "DEBUG"},
    2: {"CRITICAL", "ERROR", "WARNING", "INFO", "SUCCESS", "DEBUG", "TRACE"},
    3: {
        "CRITICAL",
        "ERROR",
        "WARNING",
        "INFO",
        "SUCCESS",
        "DEBUG",
        "TRACE",
        "PAYLOAD",
    },
}


class Logger:
    """Thread-safe colored logger with verbose tiers + JSON sink."""

    def __init__(
        self,
        verbose: int = 0,
        quiet: bool = False,
        no_color: bool = False,
        log_file: Optional[Path] = None,
        json_log_file: Optional[Path] = None,
    ) -> None:
        self.verbose = max(0, min(3, verbose))
        self.quiet = quiet
        self.start_time = time.monotonic()
        self._lock = threading.Lock()
        self._allowed = VERBOSE_MATRIX[self.verbose]

        theme = Theme({f"lvl.{k.lower()}": v for k, v in LEVEL_COLORS.items()})
        self.console = Console(
            theme=theme,
            no_color=no_color,
            stderr=False,
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
            "requests": 0,
            "ok": 0,
            "not_found": 0,
            "errors": 0,
            "bytes": 0,
            "objects": 0,
            "secrets": 0,
        }

    # ------------------------------------------------------------------ helpers

    def _ts(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _emit(self, level: str, message: str, **extra: Any) -> None:
        if self.quiet and level not in {"CRITICAL", "ERROR", "SUCCESS"}:
            return
        if level not in self._allowed:
            # Still log to file even when filtered from stdout
            self._write_file(level, message, extra)
            return

        with self._lock:
            ts = self._ts()
            sym = LEVEL_SYMBOLS[level]
            tag = LEVEL_TAGS[level]
            style = LEVEL_COLORS[level]
            # sqlmap-like: [hh:mm:ss] [INFO] message
            self.console.print(
                f"[bright_black]\\[{ts}][/bright_black] "
                f"[{style}]\\[{tag}][/{style}] {sym} {message}",
                markup=True,
                highlight=False,
            )
            self._write_file(level, message, extra)

    def _write_file(self, level: str, message: str, extra: dict) -> None:
        if self._log_fp:
            self._log_fp.write(f"[{datetime.now().isoformat()}] [{level}] {message}\n")
            self._log_fp.flush()
        if self._json_fp:
            payload = {
                "ts": datetime.now().isoformat(),
                "level": level,
                "message": message,
                **extra,
            }
            self._json_fp.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._json_fp.flush()

    # ------------------------------------------------------------------ public

    def critical(self, msg: str, **kw: Any) -> None:
        self._emit("CRITICAL", msg, **kw)

    def error(self, msg: str, **kw: Any) -> None:
        self.stats["errors"] += 1
        self._emit("ERROR", msg, **kw)

    def warning(self, msg: str, **kw: Any) -> None:
        self._emit("WARNING", msg, **kw)

    def info(self, msg: str, **kw: Any) -> None:
        self._emit("INFO", msg, **kw)

    def success(self, msg: str, **kw: Any) -> None:
        self._emit("SUCCESS", msg, **kw)

    def debug(self, msg: str, **kw: Any) -> None:
        self._emit("DEBUG", msg, **kw)

    def trace(self, msg: str, **kw: Any) -> None:
        self._emit("TRACE", msg, **kw)

    def payload(self, msg: str, **kw: Any) -> None:
        self._emit("PAYLOAD", msg, **kw)

    def http(self, method: str, url: str, status: int, size: int = 0) -> None:
        """Log a single HTTP transaction (visible from -v)."""
        self.stats["requests"] += 1
        self.stats["bytes"] += size
        if status == 200:
            self.stats["ok"] += 1
            color = "green"
        elif status == 404:
            self.stats["not_found"] += 1
            color = "bright_black"
        elif 300 <= status < 400:
            color = "yellow"
        else:
            color = "red"
        # Always log to file; gate on verbose for stdout
        msg = f"[{color}]{status}[/{color}]  {method:<5} {url}  ([dim]{size}B[/dim])"
        if self.verbose >= 1 or status >= 500:
            self.debug(msg)
        else:
            # still write to file
            self._write_file("DEBUG", f"{status} {method} {url} {size}B", {})

    def banner_line(self, text: str) -> None:
        with self._lock:
            self.console.rule(f"[bold cyan]{text}[/bold cyan]", style="cyan")

    def kv(self, key: str, value: str) -> None:
        with self._lock:
            self.console.print(f"    [bright_black]{key:>20}[/bright_black]  {value}")

    def stats_panel(self) -> None:
        elapsed = time.monotonic() - self.start_time
        with self._lock:
            self.console.print()
            self.console.rule("[bold magenta]session stats[/bold magenta]", style="magenta")
            for k, v in self.stats.items():
                self.console.print(f"    [bright_black]{k:>12}[/bright_black]  [bold]{v}[/bold]")
            self.console.print(f"    [bright_black]{'elapsed':>12}[/bright_black]  [bold]{elapsed:.2f}s[/bold]")
            self.console.print()

    def close(self) -> None:
        if self._log_fp:
            self._log_fp.close()
        if self._json_fp:
            self._json_fp.close()


# Global singleton, configured from CLI
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
