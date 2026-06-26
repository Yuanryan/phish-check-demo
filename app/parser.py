"""Parse a raw pasted email into a normalized dict the rules + LLM can consume.

Pure stdlib (`email`, `email.utils`, `html.parser`, `re`). Built to never raise on a
messy paste: anything unparseable degrades to "treat the whole thing as the body" plus
a parse_warning. The /analyze handler must never 500 on weird input.
"""

import email
import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Dict, List, Optional

import tldextract

# Match URLs in plain text. Deliberately loose; we only need host extraction afterward.
_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
# Pull spf=/dkim=/dmarc= verdicts out of an Authentication-Results header.
_AUTH_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permperror)",
    re.IGNORECASE,
)


def registrable_domain(value: Optional[str]) -> str:
    """Return the registrable (eTLD+1) domain for an email address, URL, or host.

    `mail.paypal.com` -> `paypal.com`, `evil.co.uk` -> `evil.co.uk`. Uses tldextract so
    multi-label public suffixes don't cause false mismatches. Empty string if none.
    """
    if not value:
        return ""
    value = value.strip()
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    # Strip scheme/path if a full URL slipped through.
    value = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE)
    value = value.split("/")[0].split("?")[0].strip("<>").strip()
    ext = tldextract.extract(value)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    # Bare host with no public suffix (e.g. a raw IP or "localhost").
    return value.lower()


class _LinkExtractor(HTMLParser):
    """Collect (href, anchor_text) pairs so rules can compare displayed vs real domain."""

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Dict[str, str]] = []
        self._cur_href: Optional[str] = None
        self._cur_text: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            href = dict(attrs).get("href")
            if href:
                self._cur_href = href
                self._cur_text = []

    def handle_data(self, data):
        if self._cur_href is not None:
            self._cur_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._cur_href is not None:
            self.links.append(
                {"href": self._cur_href, "text": "".join(self._cur_text).strip()}
            )
            self._cur_href = None
            self._cur_text = []


class _TextStripper(HTMLParser):
    """Crude HTML -> text fallback when an email is HTML-only."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: List[str] = []

    def handle_data(self, data):
        self._chunks.append(data)

    def text(self) -> str:
        return " ".join(c.strip() for c in self._chunks if c.strip())


def _parse_auth_results(headers: List[str]) -> Dict[str, str]:
    """Reduce one or more Authentication-Results headers to {spf,dkim,dmarc: verdict}."""
    out: Dict[str, str] = {}
    for h in headers:
        for mech, verdict in _AUTH_RE.findall(h or ""):
            # First verdict per mechanism wins (top header is the receiving MTA's).
            out.setdefault(mech.lower(), verdict.lower())
    return out


def parse_email(raw_email: str) -> Dict:
    """Parse raw email text into the normalized ParsedEmail dict.

    Returns a dict with: from_addr, from_display, reply_to, return_path, to, subject,
    date, auth_results, body_text, body_html, urls (list of {href, text}),
    parse_warnings (list[str]).
    """
    warnings: List[str] = []
    raw_email = raw_email or ""

    try:
        msg = Parser(policy=policy.default).parsestr(raw_email)
    except Exception:  # noqa: BLE001 - any malformed input degrades gracefully
        msg = None

    # If parsing yielded nothing useful (no headers at all), treat input as a bare body.
    if msg is None or (not msg.keys()):
        warnings.append("No email headers detected; treating input as message body.")
        return {
            "from_addr": "",
            "from_display": "",
            "reply_to": "",
            "return_path": "",
            "to": "",
            "subject": "",
            "date": "",
            "auth_results": {},
            "body_text": raw_email,
            "body_html": "",
            "urls": _extract_urls_from_text(raw_email),
            "parse_warnings": warnings,
        }

    from_display, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", ""))
    return_path = (msg.get("Return-Path", "") or "").strip().strip("<>")

    auth_headers = msg.get_all("Authentication-Results") or []
    received_spf = msg.get_all("Received-SPF") or []
    auth_results = _parse_auth_results(list(auth_headers) + list(received_spf))
    if not auth_results:
        warnings.append("No SPF/DKIM/DMARC authentication results found in headers.")

    body_text, body_html = _extract_bodies(msg)

    # URLs: prefer real anchors from HTML; otherwise scan plain text.
    urls: List[Dict[str, str]] = []
    if body_html:
        extractor = _LinkExtractor()
        try:
            extractor.feed(body_html)
        except Exception:  # noqa: BLE001
            pass
        urls.extend(extractor.links)
    urls.extend(_extract_urls_from_text(body_text))

    return {
        "from_addr": from_addr,
        "from_display": from_display,
        "reply_to": reply_to,
        "return_path": return_path,
        "to": msg.get("To", "") or "",
        "subject": msg.get("Subject", "") or "",
        "date": msg.get("Date", "") or "",
        "auth_results": auth_results,
        "body_text": body_text,
        "body_html": body_html,
        "urls": _dedupe_urls(urls),
        "parse_warnings": warnings,
    }


def _extract_bodies(msg: email.message.EmailMessage):
    """Return (body_text, body_html). Falls back to stripped HTML if plain is missing."""
    body_text = ""
    body_html = ""
    try:
        plain_part = msg.get_body(preferencelist=("plain",))
        if plain_part is not None:
            body_text = plain_part.get_content()
    except Exception:  # noqa: BLE001
        pass
    try:
        html_part = msg.get_body(preferencelist=("html",))
        if html_part is not None:
            body_html = html_part.get_content()
    except Exception:  # noqa: BLE001
        pass

    if not body_text and body_html:
        stripper = _TextStripper()
        try:
            stripper.feed(body_html)
            body_text = stripper.text()
        except Exception:  # noqa: BLE001
            body_text = body_html

    # Non-multipart plain message: get_body may miss it.
    if not body_text and not body_html and not msg.is_multipart():
        try:
            body_text = msg.get_content()
        except Exception:  # noqa: BLE001
            body_text = ""

    return body_text or "", body_html or ""


def _extract_urls_from_text(text: str) -> List[Dict[str, str]]:
    """Find bare URLs in plain text; anchor text equals the URL itself."""
    return [{"href": u, "text": u} for u in _URL_RE.findall(text or "")]


def _dedupe_urls(urls: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    out = []
    for u in urls:
        key = (u.get("href", ""), u.get("text", ""))
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out
