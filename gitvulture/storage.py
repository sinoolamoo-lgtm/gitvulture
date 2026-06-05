"""Sqlmap-style organized output storage.

Layout (default base: ~/.gitvulture/output)
-------------------------------------------
~/.gitvulture/
└── output/
    ├── <host1>/                       # one folder per target host
    │   ├── latest -> 20260605-181412/ # symlink to last scan
    │   ├── 20260605-141200/           # one folder per scan run (UTC timestamp)
    │   │   ├── .git/                  # reconstructed repo
    │   │   ├── recovered_blobs/
    │   │   ├── recovered_source/
    │   │   ├── gitvulture-report.json
    │   │   ├── target.txt             # plain target URL
    │   │   └── log.txt                # human-readable run log
    │   └── 20260605-181412/
    └── <host2>/
        └── ...
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse


def default_base_dir() -> Path:
    """Return the base output directory (env override → home dir)."""
    env = os.environ.get("GITVULTURE_HOME")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".gitvulture"


def slugify_host(target_url: str) -> str:
    """Convert a target URL into a filesystem-safe folder name (host:port)."""
    parsed = urlparse(target_url)
    host = parsed.hostname or "unknown-host"
    if parsed.port and parsed.port not in (80, 443):
        host = f"{host}_{parsed.port}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", host)


def new_scan_dir(target_url: str, base: Optional[Path] = None) -> Path:
    """Create and return a fresh scan directory under base/output/<host>/<ts>/.

    Also updates the `latest` symlink and writes a `target.txt` stub.
    """
    base = (base or default_base_dir()).expanduser()
    host_dir = base / "output" / slugify_host(target_url)
    host_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    scan_dir = host_dir / ts
    # Avoid collision when two scans land in the same second
    suffix = 0
    while scan_dir.exists():
        suffix += 1
        scan_dir = host_dir / f"{ts}-{suffix}"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "target.txt").write_text(target_url + "\n")
    # Update latest symlink
    latest = host_dir / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            latest.unlink()
        latest.symlink_to(scan_dir.name)
    except (OSError, NotImplementedError):
        # Windows / restricted FS — write a tiny pointer file instead
        (host_dir / "latest.txt").write_text(scan_dir.name + "\n")
    return scan_dir


def list_targets(base: Optional[Path] = None) -> list[dict]:
    """Return a sorted summary of every target/scan stored under base/output/."""
    base = (base or default_base_dir()).expanduser()
    out: list[dict] = []
    output_root = base / "output"
    if not output_root.exists():
        return out
    for host_dir in sorted(output_root.iterdir()):
        if not host_dir.is_dir():
            continue
        scans = []
        for scan_dir in sorted(host_dir.iterdir(), reverse=True):
            if not scan_dir.is_dir() or scan_dir.name == "latest":
                continue
            scans.append({
                "name": scan_dir.name,
                "path": str(scan_dir),
                "size_kb": _dir_size_kb(scan_dir),
                "has_report": (scan_dir / "gitvulture-report.json").exists(),
            })
        if scans:
            out.append({
                "host": host_dir.name,
                "scans": scans,
                "latest": scans[0]["name"],
            })
    return out


def _dir_size_kb(p: Path) -> int:
    total = 0
    for f in p.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                pass
    return total // 1024
