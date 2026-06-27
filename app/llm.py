"""Provider-agnostic LLM client.

Primary: Google Gemini 2.5 Flash (structured JSON via response_json_schema).
Fallback: Groq (tries several free-tier models in order when Gemini fails).
Last resort: deterministic mock (zero-config demo).

Any provider error or schema drift falls back down the chain so a live demo
never dies mid-presentation.
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

# Groq free-tier models, best reasoning first. Override with GROQ_MODELS in .env.
GROQ_MODEL_DEFAULTS = [
    "llama-3.3-70b-versatile",   # strongest general reasoning on free tier
    "openai/gpt-oss-120b",       # newer OSS model, good quality
    "llama-3.1-8b-instant",      # fast last resort when rate-limited on larger models
]


def detect_provider() -> str:
    """Return configured primary provider for /health (not which served last request)."""
    if os.environ.get("GEMINI_API_KEY", "").strip():
        return "gemini"
    if os.environ.get("GROQ_API_KEY", "").strip():
        return "groq"
    return "mock"


def _groq_models() -> List[str]:
    raw = os.environ.get("GROQ_MODELS", "").strip()
    if raw:
        return [m.strip() for m in raw.split(",") if m.strip()]
    single = os.environ.get("GROQ_MODEL", "").strip()
    if single:
        return [single]
    return list(GROQ_MODEL_DEFAULTS)


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


def _validate_verdict(data: Dict) -> Dict:
    """Validate and return a clean dict; raises ValidationError on drift."""
    return LLMVerdict.model_validate(data).model_dump()


def analyze_email(parsed: Dict, rule_hits: List[Dict]) -> Dict:
    """Return a verdict dict matching LLM_OUTPUT_SCHEMA, plus a 'provider' field."""
    prompt = _build_user_prompt(parsed, rule_hits)
    provider = "mock"
    data: Dict | None = None

    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if gemini_key:
        try:
            data = _validate_verdict(_analyze_gemini(prompt))
            provider = "gemini"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Gemini failed (%s); trying Groq fallback", exc)

    if data is None and os.environ.get("GROQ_API_KEY", "").strip():
        try:
            data = _validate_verdict(_analyze_groq(prompt))
            provider = "groq"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq fallback failed (%s); using mock", exc)

    if data is None:
        data = _analyze_mock(parsed, rule_hits)
        provider = "mock"
    else:
        try:
            data = _validate_verdict(data)
        except ValidationError as exc:
            logger.warning("LLM output failed schema validation (%s); using mock", exc)
            data = _analyze_mock(parsed, rule_hits)
            provider = "mock"

    data["provider"] = provider
    return data


# --- Provider adapters (SDKs imported lazily so a missing one never breaks startup) ---
def _analyze_gemini(prompt: str) -> Dict:
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=_SYSTEM_PROMPT,
            response_mime_type="application/json",
            response_json_schema=LLM_OUTPUT_SCHEMA,
            temperature=0,
        ),
    )
    return json.loads(resp.text)


def _analyze_groq(prompt: str) -> Dict:
    from groq import Groq

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    json_instruction = (
        _SYSTEM_PROMPT
        + "\n\nRespond with ONLY valid JSON matching this schema exactly:\n"
        + json.dumps(LLM_OUTPUT_SCHEMA, indent=2)
    )
    last_exc: Exception | None = None
    for model in _groq_models():
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": json_instruction},
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0,
                max_tokens=1024,
            )
            content = resp.choices[0].message.content
            if not content:
                raise ValueError("empty response")
            return json.loads(content)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.warning("Groq model %s failed (%s); trying next", model, exc)
    raise last_exc or RuntimeError("No Groq models configured")


def _analyze_mock(parsed: Dict, rule_hits: List[Dict]) -> Dict:
    """Deterministic fallback. Derives a verdict from the same signals the rules use,
    so the zero-config demo still produces a plausible, repeatable result."""
    rule_score = min(100, sum(h.get("weight", 0) for h in rule_hits))
    high = [h for h in rule_hits if h.get("severity") == "high"]

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
