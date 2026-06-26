"""Fuse the static rule score and the LLM score into one auditable verdict.

Isolated into a single pure function so reviewers can answer "how is the number
computed?" in one place. See the plan's fusion policy.
"""

from typing import Dict, List

from .schema import RISK_TYPES, band_for


def fuse(parsed: Dict, rule_hits: List[Dict], rule_score: int, llm: Dict) -> Dict:
    """Combine rule + LLM signals into the final AnalyzeResponse-shaped dict."""
    llm_score = int(llm.get("llm_score", 0))

    # 1-3: weighted blend, slight lean on the LLM for semantic judgement.
    blended = round(0.45 * rule_score + 0.55 * llm_score)

    # 4: high-confidence rule override — a confident heuristic can't be talked
    # down by an over-friendly LLM.
    high_rule = any(h.get("severity") == "high" for h in rule_hits)
    final_score = max(blended, 70) if high_rule else blended

    # 5: clamp.
    final_score = max(0, min(100, int(final_score)))

    # 6: risk type — trust the LLM, but if the rules are loud and the LLM said
    # "Benign", prefer the type implied by the highest-weight fired rule.
    risk_type = llm.get("risk_type", "Benign")
    if rule_score >= 60 and risk_type == "Benign" and rule_hits:
        top = max(rule_hits, key=lambda h: h.get("weight", 0))
        implied = top.get("implies")
        if implied in RISK_TYPES:
            risk_type = implied
    if risk_type not in RISK_TYPES:
        risk_type = "Spam"

    # Merge reasons: rule hits first (tagged 'rule'), then LLM reasons (tagged 'llm').
    reasons = [
        {
            "source": "rule",
            "label": h.get("label", ""),
            "detail": h.get("detail", ""),
            "severity": h.get("severity", "low"),
        }
        for h in rule_hits
    ]
    for r in llm.get("reasons", []):
        reasons.append(
            {
                "source": "llm",
                "label": r.get("label", ""),
                "detail": r.get("detail", ""),
                "severity": r.get("severity", "low"),
            }
        )

    return {
        "final_score": final_score,
        "risk_type": risk_type,
        "verdict_band": band_for(final_score),
        "summary": llm.get("summary", ""),
        "reasons": reasons,
        "provider": llm.get("provider", "mock"),
        "rule_score": int(rule_score),
        "llm_score": int(llm_score),
        "parse_warnings": parsed.get("parse_warnings", []),
    }
