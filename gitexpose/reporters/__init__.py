"""Report writers."""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

from ..core.dumper import DumpStats


def _to_jsonable(obj):
    if is_dataclass(obj):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    return obj


def write_json(stats: DumpStats, path: Path) -> None:
    payload = {
        "generated_at": datetime.now().isoformat(),
        "stats": _to_jsonable(stats),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def write_html(stats: DumpStats, path: Path) -> None:
    rows = ""
    for h in stats.secret_hits:
        rows += (
            f"<tr><td>{h.rule_id}</td><td>{h.description}</td>"
            f"<td>{h.file}:{h.line}</td><td><code>{_html(h.match)}</code></td>"
            f"<td>{h.entropy}</td></tr>\n"
        )
    extras = "".join(f"<li><code>{_html(x)}</code></li>" for x in stats.extras_found)
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>GitExpose Report</title>
<style>
body {{ font-family: ui-sans-serif, system-ui; background:#0b1020; color:#e7ecff; padding:24px; }}
h1 {{ color:#7cf0ff; }}
table {{ border-collapse:collapse; width:100%; margin-top:12px; }}
td,th {{ border:1px solid #2a3158; padding:6px 10px; font-size:13px; }}
th {{ background:#13193b; text-align:left; }}
code {{ color:#ffb86c; }}
.kv {{ display:grid; grid-template-columns: 220px 1fr; gap:6px 16px; max-width:780px; }}
.kv div:nth-child(odd) {{ color:#9aa8d8; }}
.tag {{ display:inline-block; background:#1f2a55; color:#7cf0ff; padding:2px 8px; border-radius:6px; font-size:11px; }}
</style></head>
<body>
<h1>GitExpose Report</h1>
<p class="tag">generated {datetime.now().isoformat(timespec='seconds')}</p>
<div class="kv">
  <div>Target</div><div><code>{_html(stats.target_base_url)}</code></div>
  <div>Detected .git</div><div><code>{_html(stats.git_root)}</code></div>
  <div>Detection method</div><div>{_html(stats.detection_method)}</div>
  <div>Directory listing</div><div>{stats.listing_enabled}</div>
  <div>HEAD SHA</div><div><code>{_html(stats.head_sha or '-')}</code></div>
  <div>Refs discovered</div><div>{stats.refs_discovered}</div>
  <div>Packs discovered</div><div>{stats.packs_discovered}</div>
  <div>Objects (loose)</div><div>{stats.objects_downloaded}</div>
  <div>Objects (from packs)</div><div>{stats.objects_from_packs}</div>
  <div>Files restored from HEAD</div><div>{stats.head_files_restored}</div>
  <div>Bytes downloaded</div><div>{stats.bytes_total:,}</div>
  <div>Duration</div><div>{stats.duration_seconds}s</div>
</div>
<h2>Secrets ({stats.secrets_found})</h2>
<table><tr><th>Rule</th><th>Description</th><th>Location</th><th>Match</th><th>Entropy</th></tr>
{rows}
</table>
<h2>Extras ({len(stats.extras_found)})</h2>
<ul>{extras}</ul>
</body></html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html)


def _html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
