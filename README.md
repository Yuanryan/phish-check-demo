# PhishCheck — Live Demo (Core Slice)

A minimal end-to-end demo for the **eCloudvalley × NTU PhishCheck Agent** project.

**Paste an email → static rules + one LLM call → risk score + risk type + structured reasons.**

This is the SOW "核心 (一定要做)" slice. The key engineering signal: the LLM returns
**structured JSON** (score + type + reasons), not free text — enforced via json-schema
output mode with a schema-validation safety net.

## What it does

1. **Parse** the raw email (stdlib `email`): From / Reply-To / Return-Path, SPF/DKIM/DMARC
   results, links (href vs anchor text), body.
2. **Static rules** (`app/rules.py`) — 6 cheap heuristics → a `rule_score` (0–100):
   auth failures, From/Reply-To domain mismatch, brand display-name spoofing, lookalike /
   high-risk TLDs, urgency/credential/financial keywords, deceptive URLs.
3. **One LLM call** (`app/llm.py`) — forced to emit structured JSON
   (`{score, risk_type, reasons[]}`), provider auto-detected from the API key prefix,
   with a deterministic **mock fallback** so it runs with zero config.
4. **Fuse** (`app/fusion.py`) — blend rule + LLM scores (with a high-confidence rule
   override) into the final verdict shown in the panel.

## Run it

From inside `phish-check-demo/`:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (use: source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/>, click **Load BEC sample**, click **Check**.

- **Zero-setup:** no `LLM_API_KEY` → the provider pill shows `Mock` and a deterministic
  verdict appears. This is the "runs end-to-end with zero config" guarantee.
- **Real LLM:** copy `.env.example` to `.env`, drop in a key
  (`sk-ant-...` → Claude, `sk-...` → GPT), restart. Same paste now routes through the real
  model — the pill shows `Claude` / `GPT` and reasons become model-generated, in the
  **exact same structured shape**.

## API

`POST /analyze` with `{"raw_email": "<full pasted email>"}` returns:

```jsonc
{
  "final_score": 0-100,
  "risk_type": "BEC | Credential Harvest | Spam | Malware | Benign",
  "verdict_band": "low | medium | high",
  "summary": "...",
  "reasons": [ { "source": "rule|llm", "label", "detail", "severity" } ],
  "provider": "anthropic | openai | mock",
  "rule_score": 0-100,
  "llm_score": 0-100,
  "parse_warnings": []
}
```

Smoke test:

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"raw_email":"From: Boss <ceo@evil.co>\nReply-To: x@other.tld\n\nUrgent wire transfer, verify http://1.2.3.4/login"}'
```

## Layout

```
app/
  schema.py    # LLM_OUTPUT_SCHEMA + Pydantic models (single source of truth)
  parser.py    # raw email -> normalized fields (stdlib email, tldextract)
  rules.py     # 6 static heuristics -> rule_score
  llm.py       # provider auto-detect + adapters + mock + validation
  fusion.py    # blend rule + llm scores -> final verdict
  main.py      # FastAPI: POST /analyze, GET / (serves panel)
static/index.html   # Gmail-style sidebar panel
samples/            # two .eml demo emails (also smoke fixtures)
```

## Not in this slice (Phase 2+)

Headless-browser web agent, real Gmail/Outlook add-ins, domain-age/threat-intel lookups,
persistence, auth. This demo proves the one-line path end to end.
