"""Single source of truth for the data contract.

Both the FastAPI response model and the LLM structured-output enforcement reference
the definitions here, so the two can never drift apart.
"""

from typing import List, Literal

from pydantic import BaseModel, Field

# Closed set of risk types. Kept as a constant so rules.py, llm.py and the frontend
# all agree on the exact strings (the UI colors a badge per type).
RISK_TYPES = ["BEC", "Credential Harvest", "Spam", "Malware", "Benign"]
SEVERITIES = ["low", "medium", "high"]
VERDICT_BANDS = ["low", "medium", "high"]

# ---------------------------------------------------------------------------
# The schema the LLM is FORCED to emit. `additionalProperties: false` plus
# `required` on every field is what makes strict / json_schema mode enforce the
# shape. This is the load-bearing "structured JSON, not free text" guarantee.
# ---------------------------------------------------------------------------
LLM_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "llm_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_type": {"type": "string", "enum": RISK_TYPES},
        "reasons": {
            "type": "array",
            "minItems": 1,
            "maxItems": 5,
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string"},
                    "detail": {"type": "string"},
                    "severity": {"type": "string", "enum": SEVERITIES},
                },
                "required": ["label", "detail", "severity"],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
    },
    "required": ["llm_score", "risk_type", "reasons", "summary"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Pydantic mirrors of the schema above. Used to (a) validate LLM output in
# llm.py and (b) type the FastAPI response. messages.parse() can also take
# LLMVerdict directly as its output model.
# ---------------------------------------------------------------------------
class Reason(BaseModel):
    label: str
    detail: str
    severity: Literal["low", "medium", "high"]


class LLMVerdict(BaseModel):
    """Exactly what the LLM must return (validated against LLM_OUTPUT_SCHEMA)."""

    llm_score: int = Field(ge=0, le=100)
    risk_type: Literal["BEC", "Credential Harvest", "Spam", "Malware", "Benign"]
    reasons: List[Reason] = Field(min_length=1, max_length=5)
    summary: str


class ReasonOut(Reason):
    """A reason as surfaced to the client, tagged with its source engine."""

    source: Literal["rule", "llm"]


class AnalyzeRequest(BaseModel):
    raw_email: str


class AnalyzeResponse(BaseModel):
    final_score: int = Field(ge=0, le=100)
    risk_type: Literal["BEC", "Credential Harvest", "Spam", "Malware", "Benign"]
    verdict_band: Literal["low", "medium", "high"]
    summary: str
    reasons: List[ReasonOut]
    provider: Literal["gemini", "groq", "mock"]
    rule_score: int = Field(ge=0, le=100)
    llm_score: int = Field(ge=0, le=100)
    parse_warnings: List[str] = []


def band_for(score: int) -> str:
    """Map a 0-100 score to a verdict band used for gauge coloring."""
    if score < 34:
        return "low"
    if score <= 66:
        return "medium"
    return "high"
