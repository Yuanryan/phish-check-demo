"""Provider-agnostic LLM client.

One public function, `analyze_email(parsed, rule_hits)`, builds a structured prompt
from the normalized email + fired rules, dispatches to the provider auto-detected from
the API key prefix, validates the result against LLM_OUTPUT_SCHEMA, and returns a dict.

Design goals (from the SOW): the LLM MUST return structured JSON, and the demo MUST run
end-to-end with zero config (mock fallback when no key is present). Any provider error
falls back to the deterministic mock so a live demo never dies mid-presentation.
"""

import json
import logging
import os
from typing import Dict, List

from pydantic import ValidationError

from .schema import LLM_OUTPUT_SCHEMA, LLMVerdict, RISK_TYPES

logger = logging.getLogger("phishcheck.llm")

_SYSTEM_PROMPT = (
    "You are a phishing-triage engine for a corporate email security tool. "
    "Given a parsed email and the static rules that already fired, judge the "
    "phishing risk. Output ONLY structured JSON: an integer risk score 0-100, a "
    "risk_type from the allowed set, 1-5 concise structured reasons (each with a "
    "short label, a one-sentence detail, and a severity), and a one-line summary. "
    "Weigh the rule findings but apply your own semantic judgement of social "
    "engineering, impersonation, and pretext."
)


def detect_provider() -> str:
    """Return 'anthropic', 'openai', or 'mock' based on the LLM_API_KEY prefix."""
    key = os.environ.get("LLM_API_KEY", "").strip()
    if not key:
        return "mock"
    if key.startswith("sk-ant-"):  # check Anthropic FIRST — its keys also start with sk-
        return "anthropic"
    if key.startswith(("sk-proj-", "sk-")):
        return "openai"
    return "mock"


def _build_user_prompt(parsed: Dict, rule_hits: List[Dict]) -> str:
    """Render the normalized email + rule findings into a compact prompt."""
    urls = parsed.get("urls") or []
    url_lines = "\n".join(
        f"  - text={u.get('text','')!r} -> href={u.get('href','')!r}" for u in urls[:10]
    ) or "  (none)"
    rule_lines = "\n".join(
        f"  - [{h.get('severity','?')}] {h.get('label','')}: {h.get('detail','')}"
        for h in rule_hits
    ) or "  (no static rules fired)"

    body = (parsed.get("body_text") or "")[:4000]
    return (
        f"FROM: {parsed.get('from_display','')} <{parsed.get('from_addr','')}>\n"
        f"REPLY-TO: {parsed.get('reply_to','')}\n"
        f"RETURN-PATH: {parsed.get('return_path','')}\n"
        f"SUBJECT: {parsed.get('subject','')}\n"
        f"AUTH RESULTS: {parsed.get('auth_results') or {}}\n"
        f"LINKS:\n{url_lines}\n"
        f"STATIC RULES FIRED:\n{rule_lines}\n\n"
        f"BODY (truncated):\n{body}\n\n"
        f"Allowed risk_type values: {RISK_TYPES}"
    )


def analyze_email(parsed: Dict, rule_hits: List[Dict]) -> Dict:
    """Return a verdict dict matching LLM_OUTPUT_SCHEMA, plus a 'provider' field."""
    provider = detect_provider()
    prompt = _build_user_prompt(parsed, rule_hits)

    try:
        if provider == "anthropic":
            data = _analyze_anthropic(prompt)
        elif provider == "openai":
            data = _analyze_openai(prompt)
        else:
            data = _analyze_mock(parsed, rule_hits)
    except Exception as exc:  # noqa: BLE001 - never let a provider error kill the demo
        logger.warning("LLM provider %s failed (%s); falling back to mock", provider, exc)
        provider = "mock"
        data = _analyze_mock(parsed, rule_hits)

    # Validate against the schema; on any drift, fall back to the mock so the
    # "structured JSON only" promise stays true even if a provider misbehaves.
    try:
        LLMVerdict.model_validate(data)
    except ValidationError as exc:
        logger.warning("LLM output failed schema validation (%s); using mock", exc)
        provider = "mock"
        data = _analyze_mock(parsed, rule_hits)

    data["provider"] = provider
    return data


# --- Provider adapters (SDKs imported lazily so a missing one never breaks startup) ---
def _analyze_anthropic(prompt: str) -> Dict:
    import anthropic

    client = anthropic.Anthropic(api_key=os.environ["LLM_API_KEY"])
    model = os.environ.get("LLM_MODEL", "claude-opus-4-8")
    # messages.parse() forces JSON matching the Pydantic model and validates it.
    # NOTE: no temperature/top_p — those are rejected (400) on Opus 4.8.
    resp = client.messages.parse(
        model=model,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
        output_format=LLMVerdict,
    )
    return resp.parsed_output.model_dump()


def _analyze_openai(prompt: str) -> Dict:
    import openai

    client = openai.OpenAI(api_key=os.environ["LLM_API_KEY"])
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "phish_verdict",
                "schema": LLM_OUTPUT_SCHEMA,
                "strict": True,
            },
        },
    )
    return json.loads(resp.choices[0].message.content)


def _analyze_mock(parsed: Dict, rule_hits: List[Dict]) -> Dict:
    """Deterministic fallback. Derives a verdict from the same signals the rules use,
    so the zero-config demo still produces a plausible, repeatable result."""
    rule_score = min(100, sum(h.get("weight", 0) for h in rule_hits))
    high = [h for h in rule_hits if h.get("severity") == "high"]

    # Vote on risk type: each fired rule contributes its weight to the type it
    # implies, so several aligned credential signals outweigh a lone auth-fail
    # (which alone leans BEC). Falls back to Benign when nothing fired.
    if rule_hits:
        votes: Dict[str, int] = {}
        for h in rule_hits:
            implied = h.get("implies", "Spam")
            votes[implied] = votes.get(implied, 0) + h.get("weight", 0)
        risk_type = max(votes, key=votes.get)
    else:
        risk_type = "Benign"
    if risk_type not in RISK_TYPES:
        risk_type = "Spam"

    # Mirror up to 3 fired rules as reasons; if none fired, say so.
    reasons = [
        {
            "label": h.get("label", "Heuristic finding"),
            "detail": h.get("detail", ""),
            "severity": h.get("severity", "low"),
        }
        for h in rule_hits[:3]
    ]
    if not reasons:
        reasons = [
            {
                "label": "No strong signals",
                "detail": "Static rules found nothing notable in headers, links, or body.",
                "severity": "low",
            }
        ]

    if high:
        summary = "High-confidence phishing indicators detected by static analysis."
        score = max(70, rule_score)
    elif rule_score >= 34:
        summary = "Several suspicious traits found; treat with caution."
        score = rule_score
    else:
        summary = "No significant phishing indicators found."
        score = rule_score

    return {
        "llm_score": int(min(100, max(0, score))),
        "risk_type": risk_type,
        "reasons": reasons,
        "summary": summary,
    }
