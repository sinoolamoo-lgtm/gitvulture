"""SAST engine wrapping semgrep (spec §4 / C1).

Runs a curated rule pack against `recovered_source/`, dangling blobs, and
the C8 diff set, then links each sink to a live endpoint via L3's
discovered_endpoints map.

Engine: semgrep CLI as subprocess. If unavailable → loud warning + skip
(per spec §4.1, never silent install).

Output layout (spec §4.9):
    <out>/sast/
        sast.md           grouped by severity
        sast.json         machine-readable
        by-endpoint.md    sinks pivoted by endpoint (Phase 9 input)
        parse_errors.log
"""
from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SastSink:
    rule_id: str
    severity: str
    description: str
    file: str
    line: int
    function: str = ""
    source: str = ""
    sanitizer: Optional[str] = None
    sink: str = ""
    snippet: str = ""
    commit_first_seen: Optional[str] = None
    route: Optional[str] = None
    method: Optional[str] = None
    live: str = "unknown"
    endpoint_id: Optional[str] = None
    confidence: str = "file-path-fallback"


@dataclass
class SastReport:
    sinks: list[SastSink] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    semgrep_version: Optional[str] = None
    rules_run: int = 0


# ---------------------------------------------------------------------------
# Embedded ruleset — keep tiny (15 high-signal rules per spec §4.2 hybrid
# pattern path). Power users override via --sast-rules.
# ---------------------------------------------------------------------------
EMBEDDED_RULES_YAML = """
rules:
  - id: php-mysqli-sql-injection
    pattern-either:
      - pattern: mysqli_query($CONN, "..." . $X . "...")
      - pattern: $DB->query("..." . $X . "...")
    message: SQL injection via string concatenation into mysqli_query
    severity: ERROR
    languages: [php]
    metadata: { category: sqli }

  - id: php-shell-exec-taint
    pattern-either:
      - pattern: shell_exec($X)
      - pattern: exec($X)
      - pattern: system($X)
      - pattern: passthru($X)
    message: Command execution sink with potential taint
    severity: ERROR
    languages: [php]
    metadata: { category: cmdi }

  - id: php-unserialize
    pattern: unserialize($X)
    message: PHP unserialize() — deserialization gadget chain risk
    severity: ERROR
    languages: [php]
    metadata: { category: deserialization }

  - id: php-include-taint
    pattern-either:
      - pattern: include($X)
      - pattern: include_once($X)
      - pattern: require($X)
      - pattern: require_once($X)
    message: Dynamic file include — LFI/RFI risk
    severity: WARNING
    languages: [php]
    metadata: { category: path-traversal }

  - id: python-pickle-loads
    pattern-either:
      - pattern: pickle.loads(...)
      - pattern: pickle.load(...)
    message: pickle deserialization — arbitrary code execution
    severity: ERROR
    languages: [python]
    metadata: { category: deserialization }

  - id: python-sql-fstring
    pattern-either:
      - pattern: cursor.execute(f"...{$X}...")
      - pattern: $C.execute(f"...{$X}...")
    message: SQL injection via f-string into cursor.execute
    severity: ERROR
    languages: [python]
    metadata: { category: sqli }

  - id: python-subprocess-shell
    pattern-either:
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: subprocess.call(..., shell=True, ...)
      - pattern: subprocess.Popen(..., shell=True, ...)
      - pattern: os.system($X)
    message: Subprocess with shell=True or os.system — command injection
    severity: ERROR
    languages: [python]
    metadata: { category: cmdi }

  - id: python-yaml-load
    pattern-either:
      - pattern: yaml.load($X)
      - pattern: yaml.load($X, Loader=yaml.Loader)
    message: yaml.load without SafeLoader — code execution
    severity: WARNING
    languages: [python]
    metadata: { category: deserialization }

  - id: js-eval-call
    pattern-either:
      - pattern: eval(...)
      - pattern: new Function($X, ...)
    message: Dynamic code evaluation
    severity: ERROR
    languages: [javascript, typescript]
    metadata: { category: cmdi }

  - id: js-child-process-exec
    pattern-either:
      - pattern: child_process.exec(...)
      - pattern: $CP.exec(...)
    message: child_process.exec — command injection risk
    severity: ERROR
    languages: [javascript, typescript]
    metadata: { category: cmdi }

  - id: java-runtime-exec
    pattern: Runtime.getRuntime().exec(...)
    message: Runtime.exec — command injection risk
    severity: ERROR
    languages: [java]
    metadata: { category: cmdi }

  - id: java-object-input-stream
    pattern: new ObjectInputStream(...).readObject()
    message: Java deserialization — gadget chain risk
    severity: ERROR
    languages: [java]
    metadata: { category: deserialization }

  - id: generic-weak-hash
    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
      - pattern: MessageDigest.getInstance("MD5")
      - pattern: MessageDigest.getInstance("SHA-1")
    message: Weak hash used (possibly for passwords)
    severity: WARNING
    languages: [python, java]
    metadata: { category: weak-crypto }

  - id: generic-debug-flag
    pattern-either:
      - pattern: debug = True
      - pattern: $APP.debug = True
      - pattern: 'DEBUG = True'
      - pattern: 'app.config["DEBUG"] = True'
    message: Debug flag enabled — possible information leak
    severity: WARNING
    languages: [python, php, javascript]
    metadata: { category: debug }

  - id: open-redirect
    pattern-either:
      - pattern: redirect($_GET[$X])
      - pattern: redirect($_POST[$X])
      - pattern: redirect(request.args.get(...))
      - pattern: header("Location: " . $_GET[$X])
    message: Open redirect — unvalidated URL in redirect
    severity: WARNING
    languages: [php, python]
    metadata: { category: open-redirect }
"""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def semgrep_available() -> Optional[str]:
    """Return semgrep version if installed, else None."""
    binary = shutil.which("semgrep")
    if not binary:
        return None
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=10,
        )
        return out.stdout.strip() or "unknown"
    except Exception:
        return None


def _write_rules_file(rules_yaml: str, tmpdir: Path) -> Path:
    p = tmpdir / "gitvulture-rules.yml"
    p.write_text(rules_yaml, encoding="utf-8")
    return p


def _run_semgrep(
    target_dir: Path,
    rules_path: Path,
    timeout_s: int = 600,
    extra_excludes: Optional[list[str]] = None,
) -> tuple[dict, list[str]]:
    """Run semgrep on target_dir → (json_output, parse_errors[])."""
    excludes = ["node_modules/", "vendor/", "bower_components/",
                ".git/", "tests/", "test/", "spec/", "fixtures/",
                "examples/", "*.min.js", "*.min.css"]
    if extra_excludes:
        excludes.extend(extra_excludes)
    cmd = [
        "semgrep", "scan",
        "--config", str(rules_path),
        "--json",
        "--quiet",
        "--metrics=off",
        "--jobs", "4",
        "--timeout", "30",
        "--max-target-bytes", "10000000",  # 10 MB
    ]
    for ex in excludes:
        cmd += ["--exclude", ex]
    cmd.append(str(target_dir))

    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return {}, [f"semgrep timeout after {timeout_s}s"]

    parse_errors = []
    if out.returncode not in (0, 1):
        # semgrep returns 1 when findings are present — normal.
        parse_errors.append(
            f"semgrep exit={out.returncode}: {out.stderr[:500]}"
        )

    try:
        data = json.loads(out.stdout) if out.stdout.strip() else {}
    except json.JSONDecodeError as e:
        parse_errors.append(f"semgrep JSON parse: {e}")
        data = {}

    return data, parse_errors


def _link_to_endpoint(sink: SastSink, endpoints_by_file: dict) -> None:
    """Populate route / method / live / confidence on a sink from L3's map.

    Single-source-of-truth join per spec §4.6 — does NOT re-derive routes.
    """
    hits = endpoints_by_file.get(sink.file, [])
    if hits:
        ep = hits[0]
        sink.route = ep.get("path")
        sink.method = ep.get("method", "GET")
        sink.endpoint_id = ep.get("id")
        sink.live = "probable"
        sink.confidence = "file-path-fallback"
        # Promote to "yes" if L3 confirmed the URL was reachable
        if ep.get("reachable"):
            sink.live = "yes"
            sink.confidence = "exact"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def run_sast(
    recovered_dir: Path,
    output_dir: Path,
    endpoints_by_file: Optional[dict] = None,
    rules_yaml: Optional[str] = None,
    log=None,
) -> SastReport:
    """Run SAST and write report files. Returns the report."""
    sast_dir = output_dir / "sast"
    sast_dir.mkdir(parents=True, exist_ok=True)

    version = semgrep_available()
    if not version:
        msg = (
            "semgrep not installed — SAST skipped. Install via:\n"
            "    pip install semgrep\n"
            "Then re-run with the same arguments. Or pass --sast-autoinstall."
        )
        if log:
            log.warn(msg)
        (sast_dir / "sast.md").write_text(
            "# SAST skipped\n\nsemgrep not installed.\n", encoding="utf-8",
        )
        return SastReport(parse_errors=["semgrep-not-installed"])

    if log:
        log.info(f"semgrep {version} starting on {recovered_dir}")

    rules_path = _write_rules_file(rules_yaml or EMBEDDED_RULES_YAML, sast_dir)
    raw, parse_errors = _run_semgrep(recovered_dir, rules_path)

    report = SastReport(
        semgrep_version=version,
        parse_errors=parse_errors,
    )

    # Convert semgrep results to SastSink
    sev_map = {"ERROR": "critical", "WARNING": "medium", "INFO": "hint"}
    endpoints_by_file = endpoints_by_file or {}
    for hit in raw.get("results", []):
        rel_path = hit.get("path", "")
        # Make file path relative to recovered_dir for nicer output
        try:
            rel_path = str(Path(rel_path).relative_to(recovered_dir))
        except (ValueError, TypeError):
            pass
        start = hit.get("start", {})
        extra = hit.get("extra", {})
        meta = extra.get("metadata", {}) if isinstance(extra, dict) else {}
        sink = SastSink(
            rule_id=hit.get("check_id", "unknown"),
            severity=sev_map.get(extra.get("severity", ""), "medium"),
            description=extra.get("message", ""),
            file=rel_path,
            line=int(start.get("line", 0) or 0),
            snippet=str(extra.get("lines", ""))[:300],
            sink=meta.get("category", ""),
        )
        _link_to_endpoint(sink, endpoints_by_file)
        report.sinks.append(sink)

    report.rules_run = len(raw.get("paths", {}).get("scanned", [])) or report.rules_run

    if log:
        log.success(f"SAST: {len(report.sinks)} sinks across "
                    f"{len(set(s.file for s in report.sinks))} files")

    # ------------- writers
    _write_outputs(report, sast_dir)
    if parse_errors:
        (sast_dir / "parse_errors.log").write_text(
            "\n".join(parse_errors), encoding="utf-8",
        )
    return report


def _write_outputs(report: SastReport, sast_dir: Path) -> None:
    # JSON
    payload = {
        "semgrep_version": report.semgrep_version,
        "total_sinks": len(report.sinks),
        "by_severity": {
            s: sum(1 for k in report.sinks if k.severity == s)
            for s in ("critical", "high", "medium", "low", "hint", "info")
        },
        "sinks": [s.__dict__ for s in report.sinks],
    }
    (sast_dir / "sast.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8",
    )

    # Markdown (human report)
    md = ["# SAST findings", ""]
    md.append(f"**Total**: {len(report.sinks)} · "
              f"semgrep `{report.semgrep_version}`")
    md.append("")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "hint"):
        c = payload["by_severity"].get(sev, 0)
        if c:
            md.append(f"| {sev} | {c} |")
    md.append("")
    if not report.sinks:
        md.append("_No sinks detected._")
    else:
        grouped = defaultdict(list)
        for s in report.sinks:
            grouped[s.severity].append(s)
        for sev in ("critical", "high", "medium", "low", "hint"):
            items = grouped.get(sev, [])
            if not items:
                continue
            md.append(f"## {sev.upper()} ({len(items)})")
            md.append("")
            for s in items:
                live_badge = {"yes": "🔴 LIVE",
                              "probable": "🟡 PROBABLE",
                              "unknown": "⚫ UNKNOWN"}.get(s.live, s.live)
                md.append(f"### `{s.rule_id}`  — {s.description}")
                md.append(f"- **File**: `{s.file}:{s.line}`")
                if s.route:
                    md.append(f"- **Route**: `{s.method} {s.route}`  {live_badge}")
                if s.snippet:
                    md.append("- **Snippet**:")
                    md.append("  ```")
                    md.append(f"  {s.snippet[:200]}")
                    md.append("  ```")
                md.append("")
    (sast_dir / "sast.md").write_text("\n".join(md), encoding="utf-8")

    # By-endpoint pivot (Phase 9 input)
    md2 = ["# SAST findings by endpoint", ""]
    endpoint_groups = defaultdict(list)
    for s in report.sinks:
        if s.route:
            endpoint_groups[(s.method, s.route)].append(s)
    if not endpoint_groups:
        md2.append("_No sinks linked to live endpoints._")
    else:
        for (m, r), items in sorted(endpoint_groups.items()):
            md2.append(f"## {m} {r}  ({len(items)} sinks)")
            md2.append("")
            for s in items:
                md2.append(f"- `{s.rule_id}` [{s.severity}] @ {s.file}:{s.line}")
            md2.append("")
    (sast_dir / "by-endpoint.md").write_text("\n".join(md2), encoding="utf-8")
