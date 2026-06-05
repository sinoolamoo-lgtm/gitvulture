"""AI-powered triage using the Emergent LLM Key (Claude Sonnet 4.5).

The LLM never executes anything against the target. It only receives a
*pre-filtered, redacted* summary of findings and returns a natural-language
analysis with severity rating and suggested next steps.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any

from emergentintegrations.llm.chat import LlmChat, UserMessage

SYSTEM_PROMPT = """You are an elite offensive-security analyst embedded in the
GitVulture tool. You are given:

1. The reconnaissance result of an exposed .git directory.
2. A list of commits, branches and dangling objects recovered.
3. A list of detected secrets (REDACTED where possible).

Your job:
- Identify the highest-impact leaks.
- Explain in 2-4 sentences what a real attacker could do RIGHT NOW with this data.
- For each TOP finding, propose precise EXPLOITATION STEPS (login URLs to try,
  endpoints to hit, services to access). Keep it operational.
- Detect known CTF / lab patterns (PortSwigger Web Security Academy, HackTheBox,
  TryHackMe) and suggest the lab-specific solving path.

Return STRICT JSON with this schema:
{
  "executive_summary": "<2-4 sentences>",
  "risk_score": <int 0-100>,
  "lab_pattern": "<portswigger|hackthebox|tryhackme|none>",
  "top_findings": [
    {
      "title": "...",
      "severity": "critical|high|medium|low",
      "what_attacker_can_do": "...",
      "exploitation_steps": ["step 1", "step 2", ...]
    }
  ],
  "next_actions": ["..."]
}
No prose outside the JSON.
"""


async def triage(
    target_url: str,
    recon_summary: dict[str, Any],
    repo_summary: dict[str, Any],
    findings_summary: list[dict[str, Any]],
    *,
    session_id: str,
    model: str = "claude-sonnet-4-6",
) -> dict[str, Any]:
    """Call the LLM and return parsed JSON. Falls back to an empty dict on error."""
    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not api_key:
        return {"error": "EMERGENT_LLM_KEY not configured"}

    payload = {
        "target": target_url,
        "recon": recon_summary,
        "repo": repo_summary,
        "findings": findings_summary[:50],  # keep the prompt bounded
    }

    chat = LlmChat(
        api_key=api_key,
        session_id=session_id,
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", model)

    user = UserMessage(
        text=(
            "Analyze the following GitVulture scan output and return strict JSON:\n"
            f"```json\n{json.dumps(payload, default=str, indent=2)[:25000]}\n```"
        )
    )

    # Non-streaming, single-shot
    try:
        resp = await chat.send_message(user)
    except Exception as e:
        return {"error": f"LLM call failed: {e}"}

    raw = resp if isinstance(resp, str) else getattr(resp, "text", str(resp))
    # Find the first JSON object in the response
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start : end + 1])
        except Exception:
            pass
    return {"error": "could not parse LLM JSON", "raw": raw[:2000]}


def summarize_findings_for_llm(findings: list) -> list[dict[str, Any]]:
    """Trim findings into a small, redacted payload safe to send to the LLM."""
    out = []
    for f in findings:
        d = f if isinstance(f, dict) else asdict(f)
        out.append({
            "rule_id": d.get("rule_id"),
            "severity": d.get("severity"),
            "description": d.get("description"),
            "redacted_value": d.get("redacted") or d.get("match"),
            # We DO send the raw match for the highest-severity items so the LLM
            # can produce concrete exploit instructions (e.g., "log in with X").
            "raw_value": d.get("match") if d.get("severity") in ("critical", "high") else None,
            "file_path": d.get("file_path"),
            "commit_sha": (d.get("commit_sha") or "")[:12],
            "source": d.get("source"),
            "verified": d.get("extra", {}).get("verified"),
        })
    return out
