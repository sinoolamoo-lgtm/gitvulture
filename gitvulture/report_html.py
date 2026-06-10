"""HTML one-page report consolidating every artifact (spec backlog item).

Reads every JSON / MD output written by the various phases and produces
`<out>/report.html` — a self-contained page (no external CSS/JS, no
network deps) suitable for sharing with engagement stakeholders.

Sections (each rendered only if its source artifact exists):
- Header   : target, scan time, phase counts
- Stats    : http requests, bypass hits, objects, secrets, sast sinks, ...
- Secrets  : table from secrets.json
- SAST     : table from sast.json grouped by severity
- Endpoints + Live diff
- Git pivots
- JWT analysis
- Cloud capabilities
- WebDAV
- Origin discovery
- Scope-audit summary (first/last 50 decisions + denied count)
"""
from __future__ import annotations

import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Optional


def _load_json(path: Path) -> Optional[dict | list]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _esc(x) -> str:
    return _html.escape(str(x), quote=True)


_CSS = """
:root{--bg:#0f1419;--fg:#e6e6e6;--mute:#8a9199;--accent:#7dd3fc;
       --crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,Segoe UI,sans-serif;
     margin:0;padding:0 24px;line-height:1.5;}
header{padding:32px 0 24px;border-bottom:1px solid #2a3138;}
header h1{margin:0 0 4px;font-size:28px}
header .meta{color:var(--mute);font-size:13px;font-family:ui-monospace,monospace;}
nav{position:sticky;top:0;background:rgba(15,20,25,0.95);padding:12px 0;
    border-bottom:1px solid #2a3138;z-index:10;backdrop-filter:blur(8px);}
nav a{color:var(--accent);margin-right:18px;text-decoration:none;font-size:13px}
nav a:hover{text-decoration:underline}
section{margin:32px 0;}
h2{font-size:20px;border-bottom:2px solid #2a3138;padding-bottom:6px;margin:0 0 16px;}
h3{font-size:15px;color:var(--accent);margin:18px 0 6px;}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px;}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid #1f2630;
      vertical-align:top}
th{color:var(--mute);font-weight:600;font-size:11px;text-transform:uppercase;
   letter-spacing:0.5px;background:#161b22;}
tr:hover td{background:#161b22;}
.sev-critical{color:var(--crit);font-weight:600;}
.sev-high    {color:var(--high);font-weight:600;}
.sev-medium  {color:var(--med);}
.sev-low     {color:var(--low);}
.sev-hint    {color:var(--mute);}
code,.mono{font-family:ui-monospace,SF Mono,Menlo,monospace;background:#161b22;
           padding:1px 5px;border-radius:3px;font-size:12px;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;
       background:#1f2937;border:1px solid #374151;}
.badge.live  {background:#7f1d1d;border-color:#dc2626;color:#fee2e2;}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
           gap:12px;margin:16px 0;}
.stat{background:#161b22;padding:14px;border-radius:6px;border:1px solid #1f2630;}
.stat .num{font-size:22px;font-weight:600;color:var(--accent);}
.stat .lbl{font-size:11px;color:var(--mute);text-transform:uppercase;letter-spacing:0.5px;}
footer{padding:32px 0 24px;border-top:1px solid #2a3138;color:var(--mute);
       font-size:11px;text-align:center;}
.banner{background:#7f1d1d;color:#fee2e2;padding:10px 14px;border-radius:4px;
        margin:12px 0;font-size:13px;}
.opsec{background:#451a03;color:#fed7aa;padding:10px 14px;border-radius:4px;
       font-size:13px;margin:12px 0;}
"""


def _section_secrets(data: dict) -> str:
    if not data:
        return ""
    findings = data.get("findings", [])
    sev_count = data.get("summary", {}).get("by_severity", {})
    crit_high = sev_count.get("critical", 0) + sev_count.get("high", 0)
    parts = [f'<section id="secrets"><h2>🔑 Secrets ({len(findings)})</h2>']
    if crit_high:
        parts.append(
            f'<div class="banner">⚠ {crit_high} critical/high-severity '
            f'credentials recovered — see <code>secrets/files/</code></div>'
        )
    if findings:
        parts.append('<table><tr><th>Severity</th><th>Rule</th><th>File</th>'
                     '<th>Line</th><th>Match</th><th>Commit</th></tr>')
        for f in findings[:300]:
            sev = f.get("severity", "info")
            parts.append(
                f'<tr><td class="sev-{sev}">{_esc(sev)}</td>'
                f'<td><code>{_esc(f.get("rule_id",""))}</code></td>'
                f'<td><code>{_esc(f.get("file_path",""))}</code></td>'
                f'<td>{_esc(f.get("line_no",""))}</td>'
                f'<td><code>{_esc(f.get("redacted","")[:60])}</code></td>'
                f'<td><code>{_esc((f.get("commit_sha") or "")[:12])}</code></td></tr>'
            )
        parts.append("</table>")
    parts.append("</section>")
    return "\n".join(parts)


def _section_sast(data: dict) -> str:
    if not data:
        return ""
    sinks = data.get("sinks", [])
    parts = [f'<section id="sast"><h2>⚠ SAST sinks ({len(sinks)})</h2>']
    if sinks:
        parts.append('<table><tr><th>Severity</th><th>Rule</th><th>File:Line</th>'
                     '<th>Route</th><th>Live</th></tr>')
        for s in sinks[:300]:
            live = s.get("live", "unknown")
            badge = '<span class="badge live">LIVE</span>' if live == "yes" \
                else f'<span class="badge">{_esc(live)}</span>'
            route = f'<code>{_esc(s.get("method",""))}{" " if s.get("route") else ""}'\
                    f'{_esc(s.get("route") or "")}</code>'
            parts.append(
                f'<tr><td class="sev-{s.get("severity","")}">{_esc(s.get("severity",""))}</td>'
                f'<td><code>{_esc(s.get("rule_id",""))}</code></td>'
                f'<td><code>{_esc(s.get("file",""))}:{_esc(s.get("line",""))}</code></td>'
                f'<td>{route}</td><td>{badge}</td></tr>'
            )
        parts.append("</table>")
    parts.append("</section>")
    return "\n".join(parts)


def _section_endpoints(data: list, live_data: Optional[dict]) -> str:
    if not data:
        return ""
    live_count = (live_data or {}).get("summary", {}).get("reachable", 0)
    parts = [
        f'<section id="endpoints"><h2>🌐 Endpoints ({len(data)} discovered, '
        f'{live_count} live)</h2>'
    ]
    parts.append('<table><tr><th>Method</th><th>Path</th><th>Framework</th>'
                 '<th>Source files</th><th>Reachable</th></tr>')
    for e in data[:300]:
        reach = e.get("reachable")
        marker = ('<span class="badge live">LIVE</span>' if reach
                  else '<span class="badge">?</span>')
        files = ", ".join(f"<code>{_esc(s)}</code>"
                          for s in (e.get("source_files") or [])[:3])
        parts.append(
            f'<tr><td>{_esc(e.get("method"))}</td>'
            f'<td><code>{_esc(e.get("path"))}</code></td>'
            f'<td>{_esc(e.get("framework",""))}</td>'
            f'<td>{files}</td><td>{marker}</td></tr>'
        )
    parts.append("</table></section>")
    return "\n".join(parts)


def _section_jwt(data: list) -> str:
    if not data:
        return ""
    cracked = [a for a in data if a.get("cracked_with")]
    parts = [f'<section id="jwt"><h2>🔓 JWT analysis ({len(data)})</h2>']
    if cracked:
        parts.append(
            f'<div class="banner">🔥 {len(cracked)} JWT(s) CRACKED with '
            f'recovered secrets — operator can now forge arbitrary tokens.</div>'
        )
    if data:
        parts.append('<table><tr><th>alg</th><th>payload</th><th>cracked</th></tr>')
        for a in data[:50]:
            parts.append(
                f'<tr><td><code>{_esc(a.get("alg","?"))}</code></td>'
                f'<td><code>{_esc(json.dumps(a.get("payload",{}))[:120])}</code></td>'
                f'<td><code>{_esc(a.get("cracked_with",""))}</code></td></tr>'
            )
        parts.append("</table>")
    parts.append("</section>")
    return "\n".join(parts)


def _section_kv(title: str, body_lines: list[str], anchor: str) -> str:
    if not body_lines:
        return ""
    return (f'<section id="{anchor}"><h2>{_html.escape(title)}</h2>'
            + "<ul>" + "".join(f"<li>{ln}</li>" for ln in body_lines) + "</ul></section>")


def write_html_report(output_dir: Path, scan_meta: Optional[dict] = None) -> Path:
    """Build the consolidated HTML report. Returns its path."""
    output_dir = Path(output_dir)

    # Load every artifact
    secrets = _load_json(output_dir / "secrets" / "secrets.json")
    sast    = _load_json(output_dir / "sast" / "sast.json")
    endpoints = _load_json(output_dir / "endpoints.json") or []
    live_diff = _load_json(output_dir / "live-diff.json")
    git_pivots = _load_json(output_dir / "git-pivots.json")
    jwt = _load_json(output_dir / "jwt-analysis.json") or []
    cloud = _load_json(output_dir / "cloud-capabilities.json") or []
    webdav = _load_json(output_dir / "webdav.json")
    origin = _load_json(output_dir / "origin-discovery.json")

    # Scope audit summary
    audit_lines: list[dict] = []
    audit_path = output_dir / "scope-audit.jsonl"
    if audit_path.exists():
        try:
            for ln in audit_path.read_text(encoding="utf-8").splitlines():
                if ln.strip():
                    audit_lines.append(json.loads(ln))
        except (OSError, json.JSONDecodeError):
            pass
    audit_denied = sum(1 for r in audit_lines if r.get("decision") == "deny")

    target = (scan_meta or {}).get("target", "(unknown)")
    started = (scan_meta or {}).get("started_at", datetime.now().isoformat())

    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        f"<title>GitVulture report — {_esc(target)}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<header>",
        "<h1>GitVulture report</h1>",
        f"<div class='meta'>target: <code>{_esc(target)}</code> · "
        f"scanned: <code>{_esc(started)}</code></div>",
        '<div class="opsec">⚠ Live-verification side effects logged on target '
        '(CloudTrail, GitHub audit, Stripe dashboard, …)</div>',
        "</header>",
        "<nav>",
        ' · '.join(f'<a href="#{a}">{n}</a>' for a, n in [
            ("stats","stats"), ("secrets","secrets"), ("sast","sast"),
            ("endpoints","endpoints"), ("jwt","jwt"), ("cloud","cloud"),
            ("webdav","webdav"), ("pivots","pivots"), ("origin","origin"),
            ("audit","scope-audit"),
        ]),
        "</nav>",
    ]

    # Stats grid
    stats_pairs = [
        ("Secrets", (secrets or {}).get("summary", {}).get("total", 0)),
        ("SAST sinks", len((sast or {}).get("sinks", []) or [])),
        ("Endpoints", len(endpoints or [])),
        ("Live routes", (live_diff or {}).get("summary", {}).get("reachable", 0)),
        ("JWT tokens", len(jwt or [])),
        ("JWT cracked", sum(1 for a in (jwt or []) if a.get("cracked_with"))),
        ("Cloud caps", len(cloud or [])),
        ("Scope decisions", len(audit_lines)),
        ("Scope denies", audit_denied),
    ]
    parts.append('<section id="stats"><h2>📊 Summary</h2><div class="stat-grid">')
    for lbl, n in stats_pairs:
        parts.append(f'<div class="stat"><div class="num">{n}</div>'
                     f'<div class="lbl">{_esc(lbl)}</div></div>')
    parts.append("</div></section>")

    parts.append(_section_secrets(secrets or {}))
    parts.append(_section_sast(sast or {}))
    parts.append(_section_endpoints(endpoints or [], live_diff))
    parts.append(_section_jwt(jwt or []))

    if cloud:
        rows = []
        for c in cloud:
            perm_str = json.dumps(c.get("permissions", {}), default=str)[:300]
            rows.append(f'<code>{_esc(c.get("provider",""))}</code> · '
                        f'<code>{_esc(c.get("key_id",""))}</code> → '
                        f'<code>{_esc(perm_str)}</code>')
        parts.append(_section_kv("☁ Cloud capabilities", rows, "cloud"))

    if webdav:
        rows = [f"writable: <strong>{webdav.get('writable')}</strong>",
                f"methods: <code>{_esc(', '.join(webdav.get('supported_methods', [])))}</code>",
                f"discovered paths: {len(webdav.get('discovered_paths', []))}"]
        if webdav.get("canary_verified"):
            rows.append(f"<strong>canary verified at:</strong> <code>"
                        f"{_esc(webdav.get('canary_path',''))}</code>")
        parts.append(_section_kv("📡 WebDAV", rows, "webdav"))

    if git_pivots:
        rows = []
        for k in ("submodules", "alternates", "lfs_endpoints",
                  "sourcemaps", "internal_hosts", "hooks"):
            v = git_pivots.get(k, [])
            if v:
                rows.append(f"<code>{k}</code>: {len(v)}")
        parts.append(_section_kv("🔗 Git pivots", rows, "pivots"))

    if origin:
        rows = [
            f"target hostname: <code>{_esc(origin.get('target_hostname',''))}</code>",
            f"candidates: {len(origin.get('candidates',[]))}",
            f"<strong>verified:</strong> {len(origin.get('verified',[]))}",
        ]
        for c in origin.get("verified", [])[:5]:
            rows.append(f"  → <code>{_esc(c.get('host'))}:{_esc(c.get('port'))}</code> "
                        f"(similarity={c.get('similarity','?')})")
        parts.append(_section_kv("🌍 Origin discovery", rows, "origin"))

    if audit_lines:
        deny_lines = [r for r in audit_lines if r.get("decision") == "deny"][:25]
        rows = [f"total decisions: <strong>{len(audit_lines)}</strong>",
                f"denies: {audit_denied}"]
        if deny_lines:
            rows.append("first denies:")
            for r in deny_lines:
                rows.append(f"  <code>{_esc(r.get('method'))} "
                            f"{_esc(r.get('url'))[:120]}</code> — "
                            f"<em>{_esc(r.get('reason'))}</em>")
        parts.append(_section_kv("🛡 Scope audit", rows, "audit"))

    parts.append(
        f'<footer>generated by gitvulture · {_html.escape(datetime.now().isoformat())}</footer>'
        "</body></html>"
    )

    html_path = output_dir / "report.html"
    html_path.write_text("\n".join(p for p in parts if p), encoding="utf-8")
    return html_path
