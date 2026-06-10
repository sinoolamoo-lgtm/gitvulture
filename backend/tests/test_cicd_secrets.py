"""Unit tests for C6 CI/CD secrets harvester."""
from __future__ import annotations

from pathlib import Path

import pytest

from gitvulture.core.cicd_secrets import (
    _detect_platform,
    _parse_file,
    run_cicd_scan,
    write_cicd_report,
)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
class TestPlatformDetection:
    def test_github_actions(self):
        assert _detect_platform(".github/workflows/deploy.yml") == "github_actions"
        assert _detect_platform("a/b/.github/workflows/ci.yaml") == "github_actions"

    def test_gitlab_ci(self):
        assert _detect_platform(".gitlab-ci.yml") == "gitlab_ci"
        assert _detect_platform("sub/.gitlab-ci.yml") == "gitlab_ci"

    def test_jenkins(self):
        assert _detect_platform("Jenkinsfile") == "jenkins"
        assert _detect_platform("sub/Jenkinsfile") == "jenkins"

    def test_bitbucket(self):
        assert _detect_platform("bitbucket-pipelines.yml") == "bitbucket"

    def test_circleci(self):
        assert _detect_platform(".circleci/config.yml") == "circleci"

    def test_travis(self):
        assert _detect_platform(".travis.yml") == "travis"

    def test_azure(self):
        assert _detect_platform("azure-pipelines.yml") == "azure"

    def test_unknown(self):
        assert _detect_platform("README.md") == ""
        assert _detect_platform("src/main.py") == ""


# ---------------------------------------------------------------------------
# Per-file parser
# ---------------------------------------------------------------------------
class TestParser:
    def test_github_inline_literal_aws_key(self):
        text = """
name: deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
        arts = _parse_file(".github/workflows/deploy.yml", text, "github_actions")
        names = {a.name for a in arts if a.kind == "env_literal"}
        assert "AWS_ACCESS_KEY_ID" in names
        # The AWS access key id matches the _LOOKS_LIKE_SECRET pattern → high severity
        akia = [a for a in arts if a.name == "AWS_ACCESS_KEY_ID"][0]
        assert akia.severity == "high"

    def test_github_secret_ref(self):
        text = """
jobs:
  build:
    steps:
      - run: echo ${{ secrets.GITHUB_TOKEN }}
      - run: echo ${{ vars.MY_VAR }}
"""
        arts = _parse_file(".github/workflows/x.yml", text, "github_actions")
        refs = [a for a in arts if a.kind.startswith("secret_ref")]
        names = {a.name for a in refs}
        assert "GITHUB_TOKEN" in names
        assert "MY_VAR" in names

    def test_github_oidc_id_token_write(self):
        text = """
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          audience: sts.amazonaws.com
          role-to-assume: arn:aws:iam::1234:role/x
"""
        arts = _parse_file(".github/workflows/oidc.yml", text, "github_actions")
        kinds = {a.kind for a in arts}
        assert "oidc_aud" in kinds
        aud = [a for a in arts if a.kind == "oidc_aud"][0]
        assert "sts.amazonaws.com" in aud.name
        assert aud.severity == "high"

    def test_github_oidc_id_token_write_no_audience(self):
        text = """
permissions:
  id-token: write
"""
        arts = _parse_file(".github/workflows/x.yml", text, "github_actions")
        kinds = {a.kind for a in arts}
        assert "oidc_id_token_write" in kinds

    def test_gitlab_var_ref(self):
        text = """
deploy:
  script:
    - echo $DEPLOY_KEY
    - echo ${PROD_DB_PASSWORD}
"""
        arts = _parse_file(".gitlab-ci.yml", text, "gitlab_ci")
        names = {a.name for a in arts if a.kind == "secret_ref:var"}
        assert "DEPLOY_KEY" in names
        assert "PROD_DB_PASSWORD" in names
        # PATH/HOME etc should be filtered
        assert "PATH" not in names
        assert "HOME" not in names

    def test_filters_false_positive_yaml_keywords(self):
        # ON, RUNS, USES etc should be filtered
        text = """
ON: push
RUNS: ubuntu-latest
"""
        arts = _parse_file(".github/workflows/x.yml", text, "github_actions")
        assert not any(a.kind == "env_literal" for a in arts)

    def test_filters_template_placeholders(self):
        text = """
DB_PASS: ${SECRET}
API_KEY: ${{ secrets.X }}
"""
        arts = _parse_file(".github/workflows/x.yml", text, "github_actions")
        literals = [a for a in arts if a.kind == "env_literal"]
        assert not literals

    def test_dedup_secret_refs(self):
        text = """
- echo ${{ secrets.TOKEN }}
- echo ${{ secrets.TOKEN }}
- echo ${{ secrets.TOKEN }}
"""
        arts = _parse_file(".github/workflows/x.yml", text, "github_actions")
        refs = [a for a in arts if a.kind.startswith("secret_ref")]
        assert len(refs) == 1


# ---------------------------------------------------------------------------
# End-to-end scan over a synthetic repo
# ---------------------------------------------------------------------------
class TestScan:
    def test_run_cicd_scan_finds_artifacts(self, tmp_path: Path):
        # Build a synthetic recovered_source tree
        gh = tmp_path / ".github" / "workflows"
        gh.mkdir(parents=True)
        (gh / "deploy.yml").write_text(
            "name: deploy\n"
            "permissions:\n  id-token: write\n"
            "env:\n  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
            "jobs:\n  d:\n    steps:\n      - run: echo ${{ secrets.NPM_TOKEN }}\n"
        )
        (tmp_path / ".gitlab-ci.yml").write_text(
            "deploy:\n  script:\n    - echo $PROD_DEPLOY_KEY\n"
        )
        (tmp_path / "Jenkinsfile").write_text(
            "pipeline { environment { DB_PASSWORD = 'realpassword123' } }\n"
        )

        report = run_cicd_scan(tmp_path)
        assert report.files_scanned == 3
        assert len(report.artifacts) > 0

        platforms = {a.platform for a in report.artifacts}
        assert "github_actions" in platforms
        assert "gitlab_ci" in platforms

        kinds = {a.kind for a in report.artifacts}
        assert "env_literal" in kinds
        assert any(k.startswith("secret_ref") for k in kinds)

    def test_run_cicd_scan_empty_dir(self, tmp_path: Path):
        # No CI/CD files at all
        (tmp_path / "main.py").write_text("print('hi')\n")
        report = run_cicd_scan(tmp_path)
        assert report.files_scanned == 0
        assert report.artifacts == []

    def test_run_cicd_scan_missing_dir(self, tmp_path: Path):
        # Directory doesn't exist
        report = run_cicd_scan(tmp_path / "nope")
        assert report.files_scanned == 0
        assert report.artifacts == []

    def test_write_cicd_report(self, tmp_path: Path):
        gh = tmp_path / "src" / ".github" / "workflows"
        gh.mkdir(parents=True)
        (gh / "x.yml").write_text(
            "env:\n  SECRET_TOKEN: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        )
        out_dir = tmp_path / "out"
        report = run_cicd_scan(tmp_path / "src")
        write_cicd_report(report, out_dir)

        assert (out_dir / "cicd-secrets.json").exists()
        assert (out_dir / "cicd-secrets.md").exists()

        import json
        data = json.loads((out_dir / "cicd-secrets.json").read_text())
        assert "files_scanned" in data
        assert "artifacts" in data
        assert data["files_scanned"] >= 1
