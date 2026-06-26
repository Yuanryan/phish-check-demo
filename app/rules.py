"""Static heuristic rules. Cheap, deterministic, explainable.

Each rule inspects the normalized ParsedEmail dict and returns a RuleHit dict
(or None). run_rules() aggregates fired hits into a 0-100 rule_score. The brand /
TLD / shortener / keyword lists are module-level constants so a reviewer can tune
them in 30 seconds.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .parser import registrable_domain

# --- Tunable knowledge lists -------------------------------------------------
BRAND_TOKENS = {
    # token -> the legitimate registrable domain it should map to
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "m365": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
}
# Brand-ish role words that signal impersonation but have no fixed domain.
ROLE_TOKENS = {"ceo", "cfo", "payroll", "hr", "helpdesk", "it support", "security team"}

HIGH_RISK_TLDS = {
    "zip", "mov", "xyz", "top", "click", "tk", "gq", "ml", "cf", "ga",
    "country", "kim", "work", "support", "rest", "fit",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

KEYWORD_GROUPS = {
    "urgency": [
        "urgent", "immediately", "asap", "right away", "within 24 hours",
        "act now", "expire", "expires", "suspended", "final notice", "last warning",
    ],
    "credential": [
        "verify your account", "verify your identity", "reset your password",
        "update your password", "confirm your password", "login to", "sign in to",
        "unusual activity", "account locked", "re-activate", "validate your account",
    ],
    "financial": [
        "wire transfer", "bank transfer", "invoice", "payment", "remittance",
        "gift card", "bitcoin", "change bank details", "update payment", "overdue",
    ],
}


# --- Helpers -----------------------------------------------------------------
def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _tld_of(domain: str) -> str:
    return domain.rsplit(".", 1)[-1].lower() if "." in domain else ""


def _looks_lookalike(domain: str) -> bool:
    """Cheap homoglyph / typo-squat signal: punycode, or digits substituting letters."""
    if domain.startswith("xn--") or ".xn--" in domain:
        return True
    name = domain.split(".")[0] if "." in domain else domain
    # Digit-for-letter swaps inside an alpha-dominant token (e.g. paypa1, g00gle).
    if re.search(r"[a-z][0-9]|[0-9][a-z]", name) and sum(c.isalpha() for c in name) >= 3:
        return True
    return False


# --- Individual rules --------------------------------------------------------
def rule_auth_results(p: Dict) -> Optional[Dict]:
    auth = p.get("auth_results") or {}
    fails = [m for m, v in auth.items() if v in ("fail", "softfail")]
    if fails:
        return {
            "label": "Authentication failure",
            "detail": "Email failed " + ", ".join(sorted(m.upper() for m in fails))
            + " checks, indicating the sender may be forged.",
            "severity": "high",
            "weight": 35,
            "implies": "BEC",
        }
    if not auth:
        return {
            "label": "No authentication results",
            "detail": "No SPF/DKIM/DMARC results present; sender identity is unverified.",
            "severity": "low",
            "weight": 8,
            "implies": "Spam",
        }
    return None


def rule_replyto_mismatch(p: Dict) -> Optional[Dict]:
    from_dom = registrable_domain(p.get("from_addr"))
    reply_dom = registrable_domain(p.get("reply_to"))
    rp_dom = registrable_domain(p.get("return_path"))
    if not from_dom:
        return None
    mismatches = []
    if reply_dom and reply_dom != from_dom:
        mismatches.append(f"Reply-To ({reply_dom})")
    if rp_dom and rp_dom != from_dom:
        mismatches.append(f"Return-Path ({rp_dom})")
    if mismatches:
        return {
            "label": "Sender domain mismatch",
            "detail": f"From domain ({from_dom}) differs from "
            + " and ".join(mismatches)
            + " — replies would go to a different party.",
            "severity": "high",
            "weight": 30,
            "implies": "BEC",
        }
    return None


def rule_display_name_spoof(p: Dict) -> Optional[Dict]:
    display = (p.get("from_display") or "").lower()
    from_dom = registrable_domain(p.get("from_addr"))
    if not display:
        return None
    for token, legit_dom in BRAND_TOKENS.items():
        if token in display and from_dom and from_dom != legit_dom:
            return {
                "label": "Brand impersonation in display name",
                "detail": f'Display name claims "{token}" but the sending domain is '
                f"{from_dom}, not {legit_dom}.",
                "severity": "high",
                "weight": 25,
                "implies": "Credential Harvest",
            }
    for role in ROLE_TOKENS:
        if role in display:
            return {
                "label": "Authority impersonation in display name",
                "detail": f'Display name invokes "{role}", a common pretext for '
                "business-email-compromise requests.",
                "severity": "medium",
                "weight": 18,
                "implies": "BEC",
            }
    return None


def rule_lookalike_domain(p: Dict) -> Optional[Dict]:
    from_dom = registrable_domain(p.get("from_addr"))
    if not from_dom:
        return None
    tld = _tld_of(from_dom)
    if _looks_lookalike(from_dom):
        return {
            "label": "Lookalike sender domain",
            "detail": f"Sender domain {from_dom} uses character substitution or "
            "punycode resembling a trusted brand.",
            "severity": "medium",
            "weight": 15,
            "implies": "Credential Harvest",
        }
    if tld in HIGH_RISK_TLDS:
        return {
            "label": "Unusual top-level domain",
            "detail": f"Sender uses the .{tld} TLD, which is frequently abused for "
            "phishing.",
            "severity": "low",
            "weight": 15,
            "implies": "Spam",
        }
    return None


def rule_keywords(p: Dict) -> Optional[Dict]:
    haystack = f"{p.get('subject','')} {p.get('body_text','')}".lower()
    hit_groups = []
    for group, terms in KEYWORD_GROUPS.items():
        if any(t in haystack for t in terms):
            hit_groups.append(group)
    if not hit_groups:
        return None
    # 10 for one group, scaling to 20 for all three.
    weight = min(20, 10 + 5 * (len(hit_groups) - 1))
    severity = "high" if len(hit_groups) >= 2 else "medium"
    implies = "BEC" if "financial" in hit_groups else "Credential Harvest"
    return {
        "label": "Social-engineering language",
        "detail": "Body contains "
        + " + ".join(hit_groups)
        + " cues typical of phishing pressure tactics.",
        "severity": severity,
        "weight": weight,
        "implies": implies,
    }


def rule_suspicious_urls(p: Dict) -> Optional[Dict]:
    urls = p.get("urls") or []
    findings = []
    severity = "low"
    for u in urls:
        href = u.get("href", "")
        text = u.get("text", "")
        host = ""
        try:
            host = urlparse(href if "://" in href else "http://" + href).hostname or ""
        except ValueError:
            host = ""
        if host and _is_ip_host(host):
            findings.append(f"raw IP link ({host})")
            severity = "high"
        href_dom = registrable_domain(host)
        if href_dom in URL_SHORTENERS:
            findings.append(f"URL shortener ({href_dom})")
            severity = max(severity, "medium", key=_sev_rank)
        # Anchor text shows a domain different from where the link actually goes.
        text_dom = registrable_domain(text) if ("." in text and " " not in text) else ""
        if text_dom and href_dom and text_dom != href_dom:
            findings.append(f"link text {text_dom} actually points to {href_dom}")
            severity = "high"
    if not findings:
        return None
    return {
        "label": "Deceptive link",
        "detail": "; ".join(dict.fromkeys(findings)) + ".",
        "severity": severity,
        "weight": 25,
        "implies": "Credential Harvest",
    }


def _sev_rank(s: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(s, 0)


_ALL_RULES = [
    rule_auth_results,
    rule_replyto_mismatch,
    rule_display_name_spoof,
    rule_lookalike_domain,
    rule_keywords,
    rule_suspicious_urls,
]


def run_rules(parsed: Dict) -> Tuple[List[Dict], int]:
    """Run every rule. Return (fired_hits, rule_score) where rule_score is 0-100."""
    hits: List[Dict] = []
    for rule in _ALL_RULES:
        try:
            hit = rule(parsed)
        except Exception:  # noqa: BLE001 - a buggy rule must not break the request
            hit = None
        if hit:
            hits.append(hit)
    rule_score = min(100, sum(h.get("weight", 0) for h in hits))
    return hits, rule_score
