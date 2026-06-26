"""FastAPI entrypoint: POST /analyze + serves the Gmail-style panel at GET /.

Run with:  uvicorn app.main:app --reload
"""

import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .fusion import fuse
from .llm import analyze_email, detect_provider
from .parser import parse_email
from .rules import run_rules
from .schema import AnalyzeRequest, AnalyzeResponse, band_for

load_dotenv()
logging.basicConfig(level=logging.INFO)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="PhishCheck", description="LLM phishing-risk triage demo")

# Permissive CORS so the panel works even if opened from file:// during a demo.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/health")
def health():
    """Expose which engine the demo will use, without leaking the key."""
    return {"status": "ok", "provider": detect_provider()}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """parse -> static rules -> one LLM call -> fuse -> structured verdict.

    Wrapped so any unexpected error still returns a 200 with a low-risk verdict and a
    parse_warning, rather than showing a broken state during a live demo.
    """
    try:
        parsed = parse_email(req.raw_email)
        rule_hits, rule_score = run_rules(parsed)
        llm = analyze_email(parsed, rule_hits)
        return fuse(parsed, rule_hits, rule_score, llm)
    except Exception as exc:  # noqa: BLE001 - demo must never 500
        logging.exception("analyze failed")
        return AnalyzeResponse(
            final_score=0,
            risk_type="Benign",
            verdict_band=band_for(0),
            summary="Analysis could not be completed.",
            reasons=[],
            provider="mock",
            rule_score=0,
            llm_score=0,
            parse_warnings=[f"Internal error: {exc}"],
        )
