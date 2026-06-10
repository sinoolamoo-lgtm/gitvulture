"""L3 — endpoint discovery from recovered source code.

Parses framework-specific route declarations across the recovered source
tree and produces an `endpoints_by_file` map for SAST sink linking (spec
§4.6 — single source of truth for the file→endpoint join).

Supported frameworks (regex-based, no AST — deliberately simple for v1):
- PHP    : Laravel `Route::*`, raw `Route::*`, Slim, Symfony annotations
- Python : Flask `@app.route`, FastAPI `@router.*`, Django `urls.py`
- JS/TS  : Express `app.get/post/...`, NestJS `@Get/@Post/...`
- Java   : Spring `@RequestMapping/@GetMapping/@PostMapping/...`
- Ruby   : `routes.rb` get/post/put/etc.
- Go     : `mux.HandleFunc`, `gin.GET/POST/...`, `r.HandleFunc`

This is intentionally lossy — better to return some routes (≥60% as
acceptance spec §9.3 requires) than zero. Sinks that don't link fall back
to `live=unknown` per spec §4.6.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Endpoint:
    id: str                       # stable hash of method+normalized_url
    method: str
    path: str                     # e.g. "/api/users/:id"
    source_files: list[str] = field(default_factory=list)  # files declaring it
    framework: str = ""
    reachable: Optional[bool] = None  # populated later by C8 LiveDiff


# ---------------------------------------------------------------------------
# Regex catalog
# ---------------------------------------------------------------------------
# Each rule = (regex with method+path groups, framework label)

_PHP_LARAVEL = re.compile(
    r"""Route::(?P<method>get|post|put|patch|delete|any|match|resource)
        \s*\(\s*['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE | re.VERBOSE,
)
_PHP_ROUTER_ADD = re.compile(
    r"""\$routes?->(?:add|map)\s*\(\s*['"](?P<method>get|post|put|patch|delete)['"]\s*,\s*['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE,
)
_PHP_SLIM = re.compile(
    r"""\$app->(?P<method>get|post|put|patch|delete|any|map)
        \s*\(\s*['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE | re.VERBOSE,
)

_PY_FLASK = re.compile(
    r"""@(?:app|bp|blueprint)\.route\s*\(\s*['"](?P<path>[^'"]+)['"]
        (?:\s*,\s*methods\s*=\s*\[(?P<methods>[^\]]+)\])?""",
    re.IGNORECASE | re.VERBOSE,
)
_PY_FASTAPI = re.compile(
    r"""@(?:app|router|api)\.(?P<method>get|post|put|patch|delete|head|options)
        \s*\(\s*['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE | re.VERBOSE,
)
_PY_DJANGO = re.compile(
    r"""(?:path|re_path|url)\s*\(\s*r?['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE,
)

_JS_EXPRESS = re.compile(
    r"""(?:app|router|r)\.(?P<method>get|post|put|patch|delete|use|all|options|head)
        \s*\(\s*['"`](?P<path>[^'"`]+)['"`]""",
    re.IGNORECASE | re.VERBOSE,
)
_JS_NESTJS = re.compile(
    r"""@(?P<method>Get|Post|Put|Patch|Delete|Head|Options|All)
        \s*\(\s*['"`](?P<path>[^'"`]+)['"`]""",
    re.VERBOSE,
)

_JAVA_SPRING_MAPPING = re.compile(
    r"""@(?P<method>GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)
        \s*\(\s*(?:value\s*=\s*)?['"](?P<path>[^'"]+)['"]""",
    re.VERBOSE,
)

_RUBY = re.compile(
    r"""^\s*(?P<method>get|post|put|patch|delete|match)\s+['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE | re.MULTILINE,
)

_GO_GIN = re.compile(
    r'\.(?P<method>GET|POST|PUT|PATCH|DELETE|Any|HEAD|OPTIONS)'
    r'\s*\(\s*"(?P<path>[^"]+)"',
)
_GO_MUX = re.compile(
    r'HandleFunc\s*\(\s*"(?P<path>[^"]+)"\s*,',
)


_FILE_RULES: list[tuple[str, list[tuple[re.Pattern, str, str]]]] = [
    # (suffix, [(regex, framework, default_method)])
    (".php", [
        (_PHP_LARAVEL,    "laravel", ""),
        (_PHP_ROUTER_ADD, "ci/yii",  ""),
        (_PHP_SLIM,       "slim",    ""),
    ]),
    (".py", [
        (_PY_FASTAPI, "fastapi", ""),
        (_PY_FLASK,   "flask",   "GET"),
        (_PY_DJANGO,  "django",  "GET"),
    ]),
    (".js",  [(_JS_EXPRESS, "express", ""), (_JS_NESTJS, "nestjs", "")]),
    (".ts",  [(_JS_EXPRESS, "express", ""), (_JS_NESTJS, "nestjs", "")]),
    (".tsx", [(_JS_NESTJS, "nestjs", "")]),
    (".java",[(_JAVA_SPRING_MAPPING, "spring", "")]),
    (".rb",  [(_RUBY, "rails", "")]),
    (".go",  [(_GO_GIN, "gin", ""), (_GO_MUX, "mux", "GET")]),
]


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------
def _normalize_route(path: str) -> str:
    """Normalize framework-specific patterns to a canonical form.

    `:id`, `{id}`, `<int:id>` → `:id` (we keep the param marker as `:id`)
    Multiple slashes collapsed. Leading slash enforced.
    """
    # Django: <int:id> / <id>
    path = re.sub(r"<(?:[a-z_]+:)?([a-zA-Z_][a-zA-Z0-9_]*)>", r":\1", path)
    # FastAPI / Express / etc.: {id}
    path = re.sub(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", r":\1", path)
    # Collapse //
    while "//" in path:
        path = path.replace("//", "/")
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


def _endpoint_id(method: str, path: str) -> str:
    """Stable id for an endpoint (used by SAST link + future graph)."""
    import hashlib
    h = hashlib.sha256(f"{method.upper()} {path}".encode()).hexdigest()
    return f"ep_{h[:12]}"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def discover_endpoints(
    recovered_dir: Path,
    log=None,
) -> tuple[list[Endpoint], dict[str, list[dict]]]:
    """Walk recovered_dir, parse route declarations, return:

      endpoints       : list[Endpoint]
      endpoints_by_file: {file_path → [{id, method, path, framework}, ...]}

    The second map is what SAST consumes for sink linking.
    """
    if not recovered_dir.exists():
        return [], {}

    endpoints: dict[tuple[str, str], Endpoint] = {}
    by_file: dict[str, list[dict]] = {}
    files_scanned = 0

    # Skip obviously irrelevant dirs
    SKIP_DIRS = {"node_modules", "vendor", "bower_components", ".git",
                 "tests", "test", "spec", "fixtures", "__pycache__"}

    for path in recovered_dir.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        rules = next((r for s, r in _FILE_RULES if s == suffix), None)
        if not rules:
            continue
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        # Cap absurdly large files (minified JS, etc.)
        if len(text) > 2_000_000:
            continue

        rel = str(path.relative_to(recovered_dir))
        for regex, framework, default_method in rules:
            for m in regex.finditer(text):
                gd = m.groupdict()
                # Determine method
                method = (gd.get("method") or default_method or "GET").upper()
                if method in ("ANY", "USE", "ALL", "MATCH", "RESOURCE",
                              "REQUESTMAPPING"):
                    method = "GET"
                elif method == "GETMAPPING":
                    method = "GET"
                elif method == "POSTMAPPING":
                    method = "POST"
                elif method == "PUTMAPPING":
                    method = "PUT"
                elif method == "DELETEMAPPING":
                    method = "DELETE"
                elif method == "PATCHMAPPING":
                    method = "PATCH"
                # Flask: methods= attribute
                if gd.get("methods"):
                    method_list = re.findall(r"['\"]([A-Z]+)['\"]",
                                             gd["methods"].upper())
                    if method_list:
                        method = method_list[0]
                raw_path = gd.get("path") or ""
                if not raw_path or raw_path.startswith("javascript:"):
                    continue
                norm = _normalize_route(raw_path)
                key = (method, norm)
                ep = endpoints.get(key)
                if ep is None:
                    ep = Endpoint(
                        id=_endpoint_id(method, norm),
                        method=method, path=norm,
                        framework=framework,
                    )
                    endpoints[key] = ep
                if rel not in ep.source_files:
                    ep.source_files.append(rel)
                by_file.setdefault(rel, []).append({
                    "id": ep.id,
                    "method": method,
                    "path": norm,
                    "framework": framework,
                })

    eps = list(endpoints.values())
    if log:
        log.success(
            f"L3 endpoint discovery: {len(eps)} endpoints across "
            f"{len(by_file)} files ({files_scanned} source files scanned)"
        )
    return eps, by_file


def write_endpoints_report(
    endpoints: list[Endpoint],
    output_dir: Path,
) -> None:
    """Write `<out>/endpoints.json` and `endpoints.md`."""
    import json
    output_dir.mkdir(parents=True, exist_ok=True)

    data = [
        {
            "id": e.id, "method": e.method, "path": e.path,
            "framework": e.framework,
            "source_files": e.source_files,
            "reachable": e.reachable,
        }
        for e in endpoints
    ]
    (output_dir / "endpoints.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8",
    )

    md = ["# Discovered endpoints", "",
          f"Total: **{len(endpoints)}**", ""]
    by_fw: dict[str, list[Endpoint]] = {}
    for e in endpoints:
        by_fw.setdefault(e.framework or "?", []).append(e)
    for fw, items in sorted(by_fw.items()):
        md.append(f"## {fw} ({len(items)})")
        md.append("")
        md.append("| Method | Path | Source files |")
        md.append("|--------|------|--------------|")
        for e in items[:200]:  # cap per framework
            files = ", ".join(f"`{f}`" for f in e.source_files[:3])
            if len(e.source_files) > 3:
                files += f" (+{len(e.source_files) - 3})"
            md.append(f"| {e.method} | `{e.path}` | {files} |")
        if len(items) > 200:
            md.append(f"... and {len(items) - 200} more")
        md.append("")
    (output_dir / "endpoints.md").write_text("\n".join(md), encoding="utf-8")
