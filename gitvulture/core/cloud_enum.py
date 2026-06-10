"""C3 — Cloud permission enumeration (spec §6.4 / C3).

Phase 6 verifies that a key is alive. C3 asks: *what can the key DO?*
For each verified key, hit a small set of read-only API endpoints to
enumerate effective permissions.

All probes are GET / safe describe-list operations only. No state changes.
Operator can see the resulting capability map and pick next escalation.

Supports:
- AWS keys      : STS GetCallerIdentity, IAM ListAttachedUserPolicies,
                  S3 ListBuckets, Lambda ListFunctions (read-only).
                  (Uses boto3 if installed; falls back to manual SigV4
                  for STS only when boto3 missing.)
- GitHub PAT    : /user, /user/repos?per_page=1, /user/orgs,
                  /user/installations
- GitLab token  : /api/v4/user, /api/v4/projects?membership=true
- Slack token   : auth.test, conversations.list?limit=1
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field

import httpx


@dataclass
class CloudCapability:
    key_id: str                  # the secret id (rule_id + redacted)
    provider: str                # aws / github / gitlab / slack / ...
    permissions: dict = field(default_factory=dict)
    error: str = ""


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------
async def enumerate_github(token: str) -> dict:
    """Hit a handful of read-only API endpoints to map the PAT's scope."""
    out: dict = {"endpoints": {}}
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "gitvulture-c3",
    }
    async with httpx.AsyncClient(timeout=15, http2=True) as cli:
        for ep in (
            "/user",
            "/user/repos?per_page=1",
            "/user/orgs",
            "/user/installations",
        ):
            try:
                r = await cli.get(f"https://api.github.com{ep}", headers=headers)
                out["endpoints"][ep] = {
                    "status": r.status_code,
                    "summary": _summarize_github(ep, r),
                }
                if ep == "/user" and r.status_code == 200:
                    out["account"] = r.json().get("login", "")
                if ep == "/user" and "X-OAuth-Scopes" in r.headers:
                    out["scopes"] = r.headers["X-OAuth-Scopes"]
            except Exception as e:
                out["endpoints"][ep] = {"error": str(e)[:200]}
    return out


def _summarize_github(ep: str, r) -> str:
    if r.status_code != 200:
        return f"HTTP {r.status_code}"
    try:
        data = r.json()
    except Exception:
        return "OK (non-JSON)"
    if isinstance(data, list):
        return f"{len(data)} items"
    if isinstance(data, dict) and "login" in data:
        return f"login={data['login']}"
    return "OK"


# ---------------------------------------------------------------------------
# GitLab
# ---------------------------------------------------------------------------
async def enumerate_gitlab(token: str, base: str = "https://gitlab.com") -> dict:
    out: dict = {"endpoints": {}}
    headers = {"PRIVATE-TOKEN": token, "User-Agent": "gitvulture-c3"}
    async with httpx.AsyncClient(timeout=15, http2=True) as cli:
        for ep in (
            "/api/v4/user",
            "/api/v4/projects?membership=true&per_page=1",
            "/api/v4/personal_access_tokens/self",
        ):
            try:
                r = await cli.get(f"{base}{ep}", headers=headers)
                summary = "OK" if r.status_code == 200 else f"HTTP {r.status_code}"
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if isinstance(data, dict) and "username" in data:
                            summary = f"user={data['username']}"
                            out["account"] = data["username"]
                            out["scopes"] = data.get("scopes", [])
                    except Exception:
                        pass
                out["endpoints"][ep] = {"status": r.status_code, "summary": summary}
            except Exception as e:
                out["endpoints"][ep] = {"error": str(e)[:200]}
    return out


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
async def enumerate_slack(token: str) -> dict:
    out: dict = {"endpoints": {}}
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": "gitvulture-c3"}
    async with httpx.AsyncClient(timeout=15, http2=True) as cli:
        for ep in ("/api/auth.test", "/api/conversations.list?limit=1"):
            try:
                r = await cli.get(f"https://slack.com{ep}", headers=headers)
                summary = "OK"
                if r.status_code == 200:
                    try:
                        j = r.json()
                        summary = f"ok={j.get('ok')} team={j.get('team', '')}"
                        if ep == "/api/auth.test" and j.get("ok"):
                            out["account"] = j.get("user", "")
                            out["team"] = j.get("team", "")
                    except Exception:
                        pass
                out["endpoints"][ep] = {"status": r.status_code, "summary": summary}
            except Exception as e:
                out["endpoints"][ep] = {"error": str(e)[:200]}
    return out


# ---------------------------------------------------------------------------
# AWS (requires aws_access_key_id + aws_secret_access_key as a tuple)
# ---------------------------------------------------------------------------
async def enumerate_aws(access_key: str, secret_key: str) -> dict:
    """Best-effort: uses boto3 if installed; otherwise reports unsupported."""
    out: dict = {"endpoints": {}}
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError
    except ImportError:
        out["error"] = "boto3 not installed — pip install boto3 to enable AWS C3"
        return out

    cfg = Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 1})
    session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )

    # STS — who am I?
    sts = session.client("sts", config=cfg)
    try:
        caller = await asyncio.to_thread(sts.get_caller_identity)
        out["account"] = caller.get("Account", "")
        out["arn"] = caller.get("Arn", "")
        out["endpoints"]["sts:GetCallerIdentity"] = "OK"
    except ClientError as e:
        out["endpoints"]["sts:GetCallerIdentity"] = f"DENIED ({e.response['Error']['Code']})"

    # IAM — list our own user policies (often blocked but worth trying)
    iam = session.client("iam", config=cfg)
    try:
        u = await asyncio.to_thread(iam.get_user)
        username = u["User"]["UserName"]
        out["iam_user"] = username
        pol = await asyncio.to_thread(
            iam.list_attached_user_policies, UserName=username,
        )
        out["iam_attached_policies"] = [
            p["PolicyName"] for p in pol.get("AttachedPolicies", [])
        ]
        out["endpoints"]["iam:GetUser"] = "OK"
    except ClientError as e:
        out["endpoints"]["iam:GetUser"] = (
            f"DENIED ({e.response['Error']['Code']})"
        )

    # S3 — list buckets
    s3 = session.client("s3", config=cfg)
    try:
        b = await asyncio.to_thread(s3.list_buckets)
        out["s3_buckets"] = [x["Name"] for x in b.get("Buckets", [])]
        out["endpoints"]["s3:ListBuckets"] = (
            f"OK ({len(out['s3_buckets'])} buckets)"
        )
    except ClientError as e:
        out["endpoints"]["s3:ListBuckets"] = (
            f"DENIED ({e.response['Error']['Code']})"
        )

    # Lambda — list functions (us-east-1 default)
    lam = session.client("lambda", region_name="us-east-1", config=cfg)
    try:
        fns = await asyncio.to_thread(lam.list_functions, MaxItems=10)
        out["lambda_functions"] = [
            f["FunctionName"] for f in fns.get("Functions", [])
        ]
        out["endpoints"]["lambda:ListFunctions"] = "OK"
    except ClientError as e:
        out["endpoints"]["lambda:ListFunctions"] = (
            f"DENIED ({e.response['Error']['Code']})"
        )

    return out


# ---------------------------------------------------------------------------
# Public entry: dispatch verified findings to provider-specific enumerators.
# ---------------------------------------------------------------------------
async def enumerate_verified_keys(
    findings: list,    # list[Finding]; we use rule_id + match + extra
    log=None,
) -> list[CloudCapability]:
    out: list[CloudCapability] = []

    # Group AWS pairs (access_key + secret_key often appear together)
    aws_access = [f for f in findings if f.rule_id == "aws-access-key-id"]
    aws_secret = [f for f in findings if f.rule_id == "aws-secret-access-key"]

    # Pair access+secret heuristically by file proximity
    aws_pairs = []
    used_secrets = set()
    for a in aws_access:
        match_s = None
        for s in aws_secret:
            if id(s) in used_secrets:
                continue
            if s.file_path == a.file_path:
                match_s = s
                break
        if match_s:
            aws_pairs.append((a, match_s))
            used_secrets.add(id(match_s))

    for a, s in aws_pairs:
        cap = CloudCapability(
            key_id=f"{a.redacted}+{s.redacted}",
            provider="aws",
        )
        try:
            cap.permissions = await enumerate_aws(a.match, s.match)
        except Exception as e:
            cap.error = str(e)[:300]
        out.append(cap)
        if log:
            log.info(f"C3 AWS: {cap.permissions.get('arn', cap.permissions.get('error', '?'))}")

    # GitHub PATs
    for f in findings:
        if f.rule_id in ("github-pat", "github-oauth"):
            cap = CloudCapability(key_id=f.redacted, provider="github")
            try:
                cap.permissions = await enumerate_github(f.match)
            except Exception as e:
                cap.error = str(e)[:300]
            out.append(cap)
            if log:
                log.info(f"C3 GitHub: account={cap.permissions.get('account', '?')}")

    # GitLab
    for f in findings:
        if f.rule_id == "gitlab-pat":
            cap = CloudCapability(key_id=f.redacted, provider="gitlab")
            try:
                cap.permissions = await enumerate_gitlab(f.match)
            except Exception as e:
                cap.error = str(e)[:300]
            out.append(cap)

    # Slack
    for f in findings:
        if f.rule_id in ("slack-bot-token", "slack-user-token"):
            cap = CloudCapability(key_id=f.redacted, provider="slack")
            try:
                cap.permissions = await enumerate_slack(f.match)
            except Exception as e:
                cap.error = str(e)[:300]
            out.append(cap)

    return out


def write_capability_report(capabilities: list[CloudCapability], output_dir):
    from pathlib import Path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "key_id": c.key_id, "provider": c.provider,
            "permissions": c.permissions, "error": c.error,
        }
        for c in capabilities
    ]
    (output_dir / "cloud-capabilities.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8",
    )
    md = ["# Cloud capability enumeration (C3)", "",
          f"Verified keys enumerated: **{len(capabilities)}**", ""]
    for c in capabilities:
        md.append(f"## {c.provider}: `{c.key_id}`")
        if c.error:
            md.append(f"- error: `{c.error}`")
        for k, v in c.permissions.items():
            md.append(f"- **{k}**: `{v}`" if not isinstance(v, dict)
                      else f"- **{k}**:")
            if isinstance(v, dict):
                for kk, vv in v.items():
                    md.append(f"    - {kk}: `{vv}`")
        md.append("")
    if not capabilities:
        md.append("_No verified keys to enumerate._")
    (output_dir / "cloud-capabilities.md").write_text(
        "\n".join(md), encoding="utf-8",
    )
