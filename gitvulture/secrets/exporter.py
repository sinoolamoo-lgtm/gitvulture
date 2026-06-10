"""Export discovered secrets into a dedicated, easy-to-find folder.

After Phase 5 (Secret Hunt) the orchestrator calls `export_secrets()` which
creates a clean, predictable layout next to the main report:

    output/<host>/<ts>/
    └── secrets/
        ├── README.txt          ← humans read this first
        ├── secrets.json        ← machine-readable (one record per finding)
        ├── secrets.md          ← grouped by severity, copy/paste friendly
        ├── secrets.txt         ← one finding per line — grep / awk friendly
        └── files/              ← FULL copies of high-signal files
            ├── .env
            ├── id_rsa
            └── config/database.yml

This is the "single source of truth" for the user. The main JSON report still
contains everything, but the user no longer has to grep it — secrets live in
their own folder.
"""
from __future__ import annotations

import json
import os
import shutil
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .patterns import Finding

# Files we copy WHOLE into secrets/files/ because finding a regex hit inside
# them is a strong indicator the whole file is sensitive.
_WHOLE_FILE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".npmrc", ".pypirc", ".netrc", ".gitconfig", ".aws/credentials",
    "credentials", "credentials.json", "secrets.json", "secrets.yml",
    "secrets.yaml", "database.yml", "database.yaml", "wp-config.php",
    "settings.py", "local_settings.py", "id_rsa", "id_ed25519", "id_dsa",
    "id_ecdsa",
}
_WHOLE_FILE_SUFFIXES = {".pem", ".key", ".pfx", ".p12", ".jks", ".keystore"}


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _should_copy_whole_file(rel_path: str) -> bool:
    p = Path(rel_path)
    if p.name in _WHOLE_FILE_NAMES:
        return True
    if p.suffix.lower() in _WHOLE_FILE_SUFFIXES:
        return True
    # Hidden dotfiles that look like config
    if p.name.startswith(".env"):
        return True
    return False


def export_secrets(
    output_dir: Path,
    findings: Iterable[Finding],
    recovered_root: Path,
) -> Path:
    """Write the dedicated secrets/ folder. Returns its absolute path."""
    findings = list(findings)
    sec_dir = output_dir / "secrets"
    sec_dir.mkdir(parents=True, exist_ok=True)
    files_dir = sec_dir / "files"

    # ---------------------------------------------------------------- JSON
    payload = {
        "summary": {
            "total": len(findings),
            "by_severity": {
                s: sum(1 for f in findings if f.severity == s)
                for s in ("critical", "high", "medium", "low", "info")
            },
            "by_rule": {},
        },
        "findings": [asdict(f) for f in findings],
    }
    by_rule = defaultdict(int)
    for f in findings:
        by_rule[f.rule_id] += 1
    payload["summary"]["by_rule"] = dict(by_rule)

    (sec_dir / "secrets.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8"
    )

    # ---------------------------------------------------------------- TXT (grep-able)
    lines = [
        "# severity | rule_id | file:line | redacted | commit",
    ]
    for f in sorted(findings, key=lambda x: (_SEV_ORDER.get(x.severity, 9),
                                             x.file_path)):
        commit = (f.commit_sha or "")[:12]
        lines.append(
            f"{f.severity:<8} | {f.rule_id:<24} | "
            f"{f.file_path}:{f.line_no} | {f.redacted} | {commit}"
        )
    (sec_dir / "secrets.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ---------------------------------------------------------------- MD (human)
    md = ["# Secrets discovered", ""]
    md.append(f"**Total findings:** {len(findings)}")
    md.append("")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        c = payload["summary"]["by_severity"].get(sev, 0)
        if c:
            md.append(f"| {sev} | {c} |")
    md.append("")
    if not findings:
        md.append("_No secrets were detected in the recovered repository._")
    else:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            grouped[f.severity].append(f)
        for sev in ("critical", "high", "medium", "low", "info"):
            items = grouped.get(sev, [])
            if not items:
                continue
            md.append(f"## {sev.upper()} ({len(items)})")
            md.append("")
            for f in items:
                commit = f"commit `{f.commit_sha[:12]}`" if f.commit_sha else "working tree"
                md.append(f"### `{f.rule_id}` — {f.description}")
                md.append(f"- **File:** `{f.file_path}:{f.line_no}` ({commit})")
                md.append(f"- **Source:** {f.source}")
                md.append(f"- **Match (redacted):** `{f.redacted}`")
                md.append("- **Context line:**")
                md.append("  ```")
                md.append(f"  {f.line.strip()[:200]}")
                md.append("  ```")
                if f.extra.get("verified"):
                    md.append("- **🔥 Verified live against API**")
                md.append("")
    (sec_dir / "secrets.md").write_text("\n".join(md), encoding="utf-8")

    # ---------------------------------------------------------------- copy whole files
    copied: list[str] = []
    seen_paths: set[str] = set()
    for f in findings:
        if f.file_path in seen_paths:
            continue
        seen_paths.add(f.file_path)
        if not _should_copy_whole_file(f.file_path):
            continue
        src = recovered_root / f.file_path
        if not src.exists() or not src.is_file():
            continue
        dst = files_dir / f.file_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dst)
            copied.append(f.file_path)
        except Exception:
            pass

    # ---------------------------------------------------------------- README
    readme = [
        "GitVulture — secrets/ folder",
        "=" * 40,
        "",
        "This folder is the single source of truth for every credential, key,",
        "or token recovered from the target's exposed .git repository.",
        "",
        "Files in this folder:",
        "  secrets.json   machine-readable, one record per finding",
        "  secrets.md     human report grouped by severity (open this first)",
        "  secrets.txt    one finding per line — pipe through grep/awk",
        "  files/         VERBATIM copies of high-signal files (.env, .pem, ...)",
        "",
        f"Total findings : {len(findings)}",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        c = payload["summary"]["by_severity"].get(sev, 0)
        if c:
            readme.append(f"  {sev:>8} : {c}")
    if copied:
        readme.append("")
        readme.append("Whole files copied to secrets/files/:")
        for p in copied:
            readme.append(f"  - {p}")
    (sec_dir / "README.txt").write_text("\n".join(readme) + "\n", encoding="utf-8")

    # ------------------------------------------------------------ E3: secure perms
    # Every file under secrets/ may contain raw key material. Lock it down so
    # it isn't world-readable on multi-user hosts. On Windows os.chmod is a
    # no-op for the permission bits we care about — Windows ACLs are out of
    # scope here, document in README that the operator must restrict the
    # folder themselves.
    import stat
    if os.name == "posix":
        for path in sec_dir.rglob("*"):
            if path.is_file():
                try:
                    path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
                except OSError:
                    pass
        try:
            sec_dir.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 0700
            files_dir.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR) if files_dir.exists() else None
        except OSError:
            pass

    return sec_dir
