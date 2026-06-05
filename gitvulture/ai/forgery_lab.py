"""AI Forgery Lab (L15) — proof-of-impact generator.

Given recovered source code (e.g. `licgen.php`, `auth.py`, JWT signing utils)
plus recovered private keys, ask Claude Sonnet 4.5 to:
  1. Read the algorithm logic in the recovered source.
  2. Produce a SELF-CONTAINED Python script that uses the leaked private
     key to forge a valid artefact (license, JWT, cookie, etc.).
  3. Include verification instructions ("run this script, paste output
     into the lab's License field at /admin").

The script is saved to disk and surfaced in the report. The engine
never executes it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from emergentintegrations.llm.chat import LlmChat, UserMessage


SYSTEM_PROMPT = """You are an offensive-security developer building a proof-of-
impact artefact. You are given:

  * Recovered SOURCE CODE files from a leaked .git directory (especially
    license generators, auth logic, token signers).
  * One or more leaked PRIVATE KEYS (PEM format).
  * The target URL and the application context.

Your job: produce a single, self-contained Python 3 script that, when run,
forges a fully-valid artefact (license, JWT, signed cookie, etc.) that the
target application would accept. The script must:

  - Import only standard library + `cryptography` (already installed).
  - Take the private key inline (paste the full PEM block).
  - Print the forged artefact to stdout.
  - Include a clear `# USAGE:` comment block at the top with step-by-step
    instructions on how to deliver the artefact to the application
    (URL to submit, form field name, expected response).
  - Use the EXACT signing algorithm and payload format you inferred from
    the source code. Cite the source filenames in comments.

Return STRICT JSON:
{
  "language": "python",
  "filename": "forge_<short_name>.py",
  "script": "<the full script as a string>",
  "delivery_steps": ["step 1", "step 2", ...],
  "expected_impact": "<one-paragraph description>",
  "confidence": "high|medium|low"
}
No prose outside the JSON.
"""


async def generate_forgery(
    target_url: str,
    source_dir: Path,
    private_keys: list[Path],
    additional_context: dict,
    *,
    session_id: str,
    out_dir: Path,
) -> Optional[dict]:
    api_key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not api_key:
        return {"error": "EMERGENT_LLM_KEY not set"}

    # Gather recovered source files that look relevant to crypto/auth/license
    relevant_kw = ("lic", "auth", "jwt", "token", "sign", "crypt", "key",
                    "session", "secret", "rsa")
    snippets: list[dict] = []
    if source_dir.exists():
        for p in source_dir.rglob("*"):
            if not p.is_file() or p.stat().st_size > 200_000:
                continue
            name = p.name.lower()
            if not any(k in name for k in relevant_kw):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")[:12000]
            except Exception:
                continue
            snippets.append({"path": str(p.relative_to(source_dir)),
                              "preview": text})

    # Inline the private keys
    key_blocks: list[dict] = []
    for k in private_keys[:3]:
        try:
            pem = k.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        key_blocks.append({"path": str(k.relative_to(source_dir)) if k.is_relative_to(source_dir) else k.name,
                            "pem": pem})

    payload = {
        "target": target_url,
        "context": additional_context,
        "source_snippets": snippets[:12],
        "private_keys": key_blocks,
    }

    chat = LlmChat(
        api_key=api_key,
        session_id=session_id,
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", "claude-sonnet-4-6")

    user = UserMessage(text=(
        "Build the forgery proof-of-impact script for the following target. "
        "Use the source snippets to infer the exact algorithm. Return the "
        "STRICT JSON object only.\n\n```json\n"
        + json.dumps(payload, default=str, indent=2)[:28000]
        + "\n```"
    ))

    try:
        resp = await chat.send_message(user)
    except Exception as e:
        return {"error": f"LLM call failed: {e}"}

    raw = resp if isinstance(resp, str) else getattr(resp, "text", str(resp))
    s = raw.find("{")
    e = raw.rfind("}")
    if s < 0 or e <= s:
        return {"error": "could not parse LLM JSON", "raw": raw[:1500]}
    try:
        result = json.loads(raw[s : e + 1])
    except Exception:
        return {"error": "JSON decode error", "raw": raw[:1500]}

    # Save the script to disk
    fname = result.get("filename") or "forge.py"
    script = result.get("script") or ""
    if script:
        out_path = out_dir / "forgery" / fname
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(script)
        result["saved_to"] = str(out_path)
    return result
