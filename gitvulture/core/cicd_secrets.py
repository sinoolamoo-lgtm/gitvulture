"""C6 — CI/CD secrets harvesting (spec §6.4 / C6).

Parses CI/CD config files in `recovered_source/` to extract:
- Hardcoded environment variables (DB_PASSWORD, API_KEY, etc.)
- OIDC `aud` / `sub` claims (cloud-takeover via OIDC misconfiguration)
- Referenced secret NAMES (not values) → tells operator which secrets to
  target via the CI/CD platform itself

Supported config formats:
- GitHub Actions    : `.github/workflows/*.yml`
- GitLab CI         : `.gitlab-ci.yml`
- CircleCI          : `.circleci/config.yml`
- Bitbucket         : `bitbucket-pipelines.yml`
- Jenkins           : `Jenkinsfile`
- Travis            : `.travis.yml`
- Azure Pipelines   : `azure-pipelines.yml`

Pure parsing — no network. Emits a structured artifact list.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CICDArtifact:
    platform: str           # github_actions / gitlab_ci / ...
    file: str               # relative path inside recovered_source/
    kind: str               # "env_literal" / "secret_ref" / "oidc_aud" / ...
    name: str               # var name (e.g. "DB_PASSWORD")
    value: str = ""         # populated only for `env_literal`
    context: str = ""       # surrounding line for grep-context
    severity: str = "medium"


@dataclass
class CICDReport:
    artifacts: list[CICDArtifact] = field(default_factory=list)
    files_scanned: int = 0


# Detect literal credentials inline in YAML (rare but devastating)
_INLINE_SECRET = re.compile(
    r'^\s*([A-Z][A-Z0-9_]{2,})\s*:\s*[\'"]?([^\s\'"#\n][^\'"#\n]{4,}?)[\'"]?\s*$',
    re.MULTILINE,
)
# GitHub: ${{ secrets.NAME }} / ${{ vars.NAME }}
_GH_SECRET_REF = re.compile(
    r'\$\{\{\s*(secrets|vars|inputs)\.([A-Z][A-Z0-9_]+)\s*\}\}'
)
# GitLab CI: $VAR / $VAR$ / ${VAR}
_GL_VAR_REF = re.compile(r'\$\{?([A-Z][A-Z0-9_]{2,})\}?')
# OIDC trigger fields (audience / subject claim)
_OIDC_AUD = re.compile(r'audience\s*:\s*[\'"]?([^\s\'"]+)[\'"]?', re.I)
# id-token: write permission
_ID_TOKEN_WRITE = re.compile(r'id-token\s*:\s*write', re.I)

# Patterns that DO look like real secret values (not just env-name refs)
_LOOKS_LIKE_SECRET = re.compile(
    r'^(?:[A-Za-z0-9+/=]{20,}|sk_[a-z]+_[A-Za-z0-9]{20,}|'
    r'xox[abprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16})$'
)


# ---------------------------------------------------------------------------
# Platform detection from path
# ---------------------------------------------------------------------------
def _detect_platform(rel_path: str) -> str:
    rel = rel_path.lower().replace("\\", "/")
    if "/.github/workflows/" in rel or rel.startswith(".github/workflows/"):
        return "github_actions"
    if rel.endswith(".gitlab-ci.yml") or rel.endswith("/.gitlab-ci.yml"):
        return "gitlab_ci"
    if "/.circleci/config" in rel or rel.startswith(".circleci/config"):
        return "circleci"
    if rel.endswith("bitbucket-pipelines.yml"):
        return "bitbucket"
    if rel.endswith("jenkinsfile") or rel.endswith("/jenkinsfile"):
        return "jenkins"
    if rel.endswith(".travis.yml"):
        return "travis"
    if rel.endswith("azure-pipelines.yml"):
        return "azure"
    return ""


# ---------------------------------------------------------------------------
# Per-file parser (single regex pass; YAML schema-aware would be nicer but
# we don't want a yaml dep just for this).
# ---------------------------------------------------------------------------
def _parse_file(rel_path: str, text: str, platform: str) -> list[CICDArtifact]:
    out: list[CICDArtifact] = []

    # 1. Inline literal secrets (high-confidence pattern only)
    for m in _INLINE_SECRET.finditer(text):
        name, value = m.group(1), m.group(2).strip()
        # Filter common false positives
        if name in ("ON", "RUNS", "USES", "WITH", "WORKING_DIRECTORY",
                    "DEFAULT_BRANCH", "TIMEOUT_MINUTES", "STAGE",
                    "TIMEOUT", "TYPE", "SHELL", "STAGES"):
            continue
        if value.startswith(("${", "$(", "{{", "<<")):
            continue
        if len(value) < 6 or value.lower() in ("true", "false", "yes", "no",
                                               "main", "master", "ubuntu",
                                               "latest", "self-hosted"):
            continue
        sev = "high" if _LOOKS_LIKE_SECRET.match(value) else "medium"
        out.append(CICDArtifact(
            platform=platform, file=rel_path, kind="env_literal",
            name=name, value=value[:200], context=m.group(0).strip()[:200],
            severity=sev,
        ))

    # 2. Referenced secret NAMES (no value leak, but reveals attack surface)
    if platform == "github_actions":
        seen_names: set[tuple[str, str]] = set()
        for m in _GH_SECRET_REF.finditer(text):
            kind_kw, name = m.group(1), m.group(2)
            if (kind_kw, name) in seen_names:
                continue
            seen_names.add((kind_kw, name))
            out.append(CICDArtifact(
                platform=platform, file=rel_path,
                kind=f"secret_ref:{kind_kw}", name=name,
                context=m.group(0), severity="info",
            ))
    elif platform == "gitlab_ci":
        seen: set[str] = set()
        for m in _GL_VAR_REF.finditer(text):
            n = m.group(1)
            if n in seen:
                continue
            seen.add(n)
            # Filter shell builtins / common patterns
            if n in ("CI", "PWD", "HOME", "USER", "PATH", "SHELL",
                     "PS1", "PS2"):
                continue
            out.append(CICDArtifact(
                platform=platform, file=rel_path,
                kind="secret_ref:var", name=n,
                context=m.group(0), severity="info",
            ))

    # 3. OIDC cloud-takeover indicators
    if _ID_TOKEN_WRITE.search(text):
        for m in _OIDC_AUD.finditer(text):
            out.append(CICDArtifact(
                platform=platform, file=rel_path, kind="oidc_aud",
                name=m.group(1), context=m.group(0),
                severity="high",
            ))
        # If id-token:write present but no audience captured, still flag it
        if not _OIDC_AUD.search(text):
            out.append(CICDArtifact(
                platform=platform, file=rel_path, kind="oidc_id_token_write",
                name="(any)",
                context="id-token: write (no explicit audience captured)",
                severity="medium",
            ))

    return out


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------
def run_cicd_scan(recovered_dir: Path, log=None) -> CICDReport:
    """Walk recovered_dir, find CI/CD config files, extract artifacts."""
    report = CICDReport()
    if not recovered_dir.exists():
        return report

    candidate_files: list[Path] = []
    # Targeted glob (fast)
    for pat in (
        ".github/workflows/*.yml", ".github/workflows/*.yaml",
        ".gitlab-ci.yml", ".gitlab-ci.yaml",
        ".circleci/config.yml", "bitbucket-pipelines.yml",
        "Jenkinsfile", ".travis.yml", "azure-pipelines.yml",
        "azure-pipelines.yaml",
    ):
        candidate_files.extend(recovered_dir.rglob(pat))
    # Dedup
    candidate_files = list({p.resolve() for p in candidate_files})

    for p in candidate_files:
        try:
            rel = str(p.relative_to(recovered_dir))
        except ValueError:
            rel = str(p)
        platform = _detect_platform(rel)
        if not platform:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        if len(text) > 500_000:
            continue
        report.files_scanned += 1
        report.artifacts.extend(_parse_file(rel, text, platform))

    if log:
        log.success(
            f"C6: {report.files_scanned} CI/CD files scanned, "
            f"{len(report.artifacts)} artifact(s) extracted"
        )
    return report


def write_cicd_report(report: CICDReport, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "files_scanned": report.files_scanned,
        "by_kind": {},
        "by_severity": {},
        "artifacts": [a.__dict__ for a in report.artifacts],
    }
    for a in report.artifacts:
        payload["by_kind"][a.kind] = payload["by_kind"].get(a.kind, 0) + 1
        payload["by_severity"][a.severity] = payload["by_severity"].get(a.severity, 0) + 1

    (output_dir / "cicd-secrets.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8",
    )

    md = ["# CI/CD secrets harvest (C6)", "",
          f"Files scanned: **{report.files_scanned}** · "
          f"Artifacts extracted: **{len(report.artifacts)}**", ""]
    if report.artifacts:
        # Group by severity
        for sev in ("critical", "high", "medium", "low", "info"):
            items = [a for a in report.artifacts if a.severity == sev]
            if not items:
                continue
            md.append(f"## {sev.upper()} ({len(items)})")
            md.append("")
            md.append("| Platform | File | Kind | Name | Context |")
            md.append("|----------|------|------|------|---------|")
            for a in items[:200]:
                md.append(
                    f"| {a.platform} | `{a.file}` | {a.kind} | "
                    f"`{a.name}` | `{a.context[:120]}` |"
                )
            md.append("")
    else:
        md.append("_No CI/CD config files found in recovered source._")
    (output_dir / "cicd-secrets.md").write_text(
        "\n".join(md), encoding="utf-8",
    )
