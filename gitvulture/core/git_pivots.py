"""C9 — Git-native pivots from the recovered repository (spec §6.4 / C9).

Mines a recovered `.git/` tree for assets that lead to additional attack
surface:

1. `.gitmodules`     → upstream submodule URLs (additional repos to target)
2. `.git/hooks/*`    → shell scripts that may contain creds or paths
3. `.gitattributes`  → may reveal Git LFS endpoints
4. `objects/info/alternates` → references another on-disk repo
5. `.js.map` files inside recovered_source/ → original (pre-minification)
   source + sourceURL hints leading to internal hostnames
6. Hostname extraction from config files (`config.php`, `.env`, `*.yml`,
   `*.json`) → input to D2 (subdomain expansion)

All discoveries are emitted as artifacts the operator can act on; this
module is pure parsing — no network requests.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class GitPivots:
    submodules: list[dict] = field(default_factory=list)  # {path, url, branch}
    hooks: list[dict] = field(default_factory=list)        # {name, snippet}
    alternates: list[str] = field(default_factory=list)
    lfs_endpoints: list[str] = field(default_factory=list)
    sourcemaps: list[dict] = field(default_factory=list)   # {map_file, src_count, hint_urls}
    internal_hosts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# .gitmodules
# ---------------------------------------------------------------------------
_GITMODULES_BLOCK = re.compile(
    r'\[submodule\s+"([^"]+)"\](.*?)(?=\[submodule|\Z)',
    re.DOTALL,
)
_GITMODULES_KV = re.compile(r'^\s*([a-zA-Z_]+)\s*=\s*(.+?)\s*$', re.MULTILINE)


def parse_gitmodules(text: str) -> list[dict]:
    out = []
    for m in _GITMODULES_BLOCK.finditer(text):
        name = m.group(1)
        body = m.group(2)
        entry = {"name": name}
        for kv in _GITMODULES_KV.finditer(body):
            entry[kv.group(1).lower()] = kv.group(2)
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# sourcemaps
# ---------------------------------------------------------------------------
def parse_sourcemap(text: str) -> Optional[dict]:
    """Extract original sources + sourceRoot from a JSON source map."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    sources = data.get("sources", []) or []
    if not isinstance(sources, list):
        sources = []
    src_root = data.get("sourceRoot", "") or ""
    # Heuristic: pull URLs that look like internal infra
    hint_urls = []
    for s in sources[:200]:
        if not isinstance(s, str):
            continue
        if s.startswith("webpack://") or "node_modules" in s:
            continue
        if re.match(r"^https?://", s):
            hint_urls.append(s)
    return {
        "src_count": len(sources),
        "src_root": src_root,
        "hint_urls": hint_urls[:50],
    }


# ---------------------------------------------------------------------------
# internal hostname extractor
# ---------------------------------------------------------------------------
_HOST_RE = re.compile(
    r'\b(?:https?://|[A-Z_]+=)([a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+(?::\d+)?)\b',
    re.IGNORECASE,
)
_INTERNAL_TLDS = {
    ".local", ".internal", ".corp", ".lan", ".intranet", ".test", ".invalid",
}
_INTERESTING_KEYWORDS = (
    "internal", "staging", "stage", "dev", "qa", "uat", "admin", "console",
    "intranet", "private", "backend", "api-internal", "vpc", "k8s",
)


def extract_hosts_from_text(text: str, primary_host: str) -> set[str]:
    """Return hostnames that look like internal/staging infra (not the primary host)."""
    out: set[str] = set()
    for m in _HOST_RE.finditer(text):
        host = m.group(1).lower()
        host_only = host.split(":", 1)[0]
        if host_only == primary_host:
            continue
        # Filter obvious public CDNs / SDKs we don't care about
        if any(h in host_only for h in (
            "cloudflare", "cdn.jsdelivr", "googleapis", "google-analytics",
            "fontawesome", "bootstrap", "jquery", "gstatic", "cloudfront",
        )):
            continue
        # Only keep interesting ones (heuristic)
        if any(host_only.endswith(t) for t in _INTERNAL_TLDS):
            out.add(host_only)
        elif any(k in host_only for k in _INTERESTING_KEYWORDS):
            out.add(host_only)
    return out


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------
def run_git_pivots(
    git_dir: Path,
    recovered_dir: Path,
    primary_host: str = "",
    log=None,
) -> GitPivots:
    """Walk the recovered .git/ + recovered_source/ and harvest pivots."""
    pivots = GitPivots()

    # 1. .gitmodules
    gm = recovered_dir / ".gitmodules"
    if gm.exists():
        try:
            pivots.submodules = parse_gitmodules(gm.read_text(encoding="utf-8", errors="ignore"))
            if log and pivots.submodules:
                log.success(f"C9: {len(pivots.submodules)} submodule(s) found")
        except Exception as e:
            if log:
                log.trace(f"C9 .gitmodules parse: {e}")

    # 2. hooks
    hooks_dir = git_dir / "hooks"
    if hooks_dir.exists() and hooks_dir.is_dir():
        for h in hooks_dir.iterdir():
            if not h.is_file() or h.name.endswith(".sample"):
                continue
            try:
                snippet = h.read_text(encoding="utf-8", errors="ignore")[:2000]
                pivots.hooks.append({"name": h.name, "snippet": snippet})
            except OSError:
                pass

    # 3. alternates
    alt = git_dir / "objects" / "info" / "alternates"
    if alt.exists():
        try:
            content = alt.read_text(encoding="utf-8", errors="ignore")
            pivots.alternates = [
                line.strip() for line in content.splitlines() if line.strip()
            ]
        except OSError:
            pass

    # 4. Git LFS endpoints (from .gitattributes or .lfsconfig)
    for fname in (".gitattributes", ".lfsconfig"):
        f = recovered_dir / fname
        if f.exists():
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r'url\s*=\s*(\S+)', txt):
                    pivots.lfs_endpoints.append(m.group(1))
            except OSError:
                pass

    # 5. sourcemaps
    if recovered_dir.exists():
        for sm in recovered_dir.rglob("*.js.map"):
            try:
                txt = sm.read_text(encoding="utf-8", errors="ignore")
                parsed = parse_sourcemap(txt)
                if parsed:
                    parsed["map_file"] = str(sm.relative_to(recovered_dir))
                    pivots.sourcemaps.append(parsed)
            except (OSError, UnicodeDecodeError):
                pass

    # 6. internal hostnames from config files
    if recovered_dir.exists() and primary_host:
        candidates: set[str] = set()
        # Iterate config-shaped files only — full scan would be too slow
        patterns = ["*.env", "*.env.*", "*.yml", "*.yaml", "*.json",
                    "*.ini", "*.conf", "*.cfg", "*.toml", "config.php"]
        for pat in patterns:
            for f in recovered_dir.rglob(pat):
                if any(skip in f.parts for skip in
                       ("node_modules", "vendor", ".git", "tests")):
                    continue
                try:
                    txt = f.read_text(encoding="utf-8", errors="ignore")
                except (OSError, UnicodeDecodeError):
                    continue
                if len(txt) > 200_000:
                    continue
                candidates.update(extract_hosts_from_text(txt, primary_host))
        pivots.internal_hosts = sorted(candidates)
        if log and pivots.internal_hosts:
            log.success(
                f"C9: {len(pivots.internal_hosts)} internal/staging "
                f"hostname(s) extracted from configs"
            )

    return pivots


def write_pivots_report(pivots: GitPivots, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "submodules": pivots.submodules,
        "hooks": pivots.hooks,
        "alternates": pivots.alternates,
        "lfs_endpoints": pivots.lfs_endpoints,
        "sourcemaps": pivots.sourcemaps,
        "internal_hosts": pivots.internal_hosts,
    }
    (output_dir / "git-pivots.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )
    md = ["# Git-native pivots (C9)", ""]
    if pivots.submodules:
        md.append("## Submodules")
        md.append("")
        for s in pivots.submodules:
            md.append(f"- **{s.get('name')}** — `{s.get('url')}` "
                      f"(branch: `{s.get('branch','')}`)")
        md.append("")
    if pivots.alternates:
        md.append("## objects/info/alternates")
        md.append("")
        for a in pivots.alternates:
            md.append(f"- `{a}`")
        md.append("")
    if pivots.lfs_endpoints:
        md.append("## Git LFS endpoints")
        md.append("")
        for url in pivots.lfs_endpoints:
            md.append(f"- `{url}`")
        md.append("")
    if pivots.sourcemaps:
        md.append(f"## Source maps ({len(pivots.sourcemaps)})")
        md.append("")
        for s in pivots.sourcemaps[:20]:
            md.append(f"- `{s['map_file']}` — {s['src_count']} sources, "
                      f"sourceRoot=`{s.get('src_root','')}`")
            for url in s.get("hint_urls", [])[:5]:
                md.append(f"    - hint: `{url}`")
        md.append("")
    if pivots.internal_hosts:
        md.append("## Internal / staging hostnames")
        md.append("")
        for h in pivots.internal_hosts:
            md.append(f"- `{h}`")
        md.append("")
    if pivots.hooks:
        md.append("## .git/hooks/*")
        md.append("")
        for h in pivots.hooks:
            md.append(f"### {h['name']}")
            md.append("```")
            md.append(h["snippet"][:500])
            md.append("```")
            md.append("")
    if not any([pivots.submodules, pivots.alternates, pivots.lfs_endpoints,
                pivots.sourcemaps, pivots.internal_hosts, pivots.hooks]):
        md.append("_No git-native pivots discovered._")
    (output_dir / "git-pivots.md").write_text("\n".join(md), encoding="utf-8")
