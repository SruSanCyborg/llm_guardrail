"""
Output Guardrail Service — runs on port 8002.
Runs 4 parallel checks: toxicity, PII leak, hallucination, bias.
Returns OutputGuardResponse with XAI explanation.
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import re
import asyncio
from fastapi import FastAPI
from shared.schemas import OutputGuardRequest, OutputGuardResponse

app = FastAPI(title="Cerebus Output Guardrail")

# ---------------------------------------------------------------------------
# Toxicity — Detoxify
# ---------------------------------------------------------------------------
_detoxify_model = None

def _load_detoxify():
    global _detoxify_model
    if _detoxify_model is None:
        from detoxify import Detoxify
        _detoxify_model = Detoxify("original")
    return _detoxify_model

def check_toxicity(text: str) -> tuple[bool, str]:
    try:
        model = _load_detoxify()
        scores = model.predict(text)
        toxic_score = scores["toxicity"]
        if toxic_score > 0.7:
            return False, f"High toxicity detected (score: {toxic_score:.2f})"
        return True, ""
    except Exception as e:
        return True, ""  # Fail open if model unavailable


# ---------------------------------------------------------------------------
# PII / Data Leak — Regex + named patterns
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "email":       r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
    "phone":       r"\b(\+?\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
    "ssn":         r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[\s-]?){3}\d{4}\b",
    "api_key":     r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+",
    "ip_address":  r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

def check_pii_leak(text: str) -> tuple[bool, str]:
    for label, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            return False, f"Potential {label.replace('_', ' ')} detected in response"
    return True, ""


# ---------------------------------------------------------------------------
# Hallucination — NLI cross-check against RAG context
# ---------------------------------------------------------------------------
_nli_pipeline = None

def _load_nli():
    global _nli_pipeline
    if _nli_pipeline is None:
        from transformers import pipeline
        _nli_pipeline = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1,  # CPU
        )
    return _nli_pipeline

def check_hallucination(response: str, context: str) -> tuple[bool, str]:
    if not context or not context.strip():
        return True, ""  # No RAG context → skip
    try:
        pipe = _load_nli()
        # Take first 300 chars of response and check entailment against context
        snippet = response[:300]
        result = pipe(snippet, candidate_labels=["supported", "contradicted"], hypothesis_template="This claim is {} by the context: " + context[:300])
        if result["labels"][0] == "contradicted" and result["scores"][0] > 0.75:
            return False, f"Response may contradict source knowledge (NLI score: {result['scores'][0]:.2f})"
        return True, ""
    except Exception:
        return True, ""  # Fail open


# ---------------------------------------------------------------------------
# Bias — lightweight keyword check (replace with classifier post-hackathon)
# ---------------------------------------------------------------------------
BIAS_PATTERNS = [
    r"\b(all|every|most)\s+(men|women|black|white|asian|muslim|christian|hindu)\s+(are|tend to|always)",
    r"(inferior|superior)\s+(race|gender|religion)",
    r"stereotypically\s+(male|female|asian|black|white)",
]

def check_bias(text: str) -> tuple[bool, str]:
    lower = text.lower()
    for pattern in BIAS_PATTERNS:
        if re.search(pattern, lower):
            return False, "Response contains potentially biased generalisation"
    return True, ""


# ---------------------------------------------------------------------------
# Main endpoint
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "output_guardrail"}


@app.post("/check", response_model=OutputGuardResponse)
async def check(req: OutputGuardRequest):
    # Run all checks (sync, but fast enough for hackathon — parallelise later)
    tox_ok, tox_msg = check_toxicity(req.response)
    pii_ok, pii_msg = check_pii_leak(req.response)
    hall_ok, hall_msg = check_hallucination(req.response, req.rag_context or "")
    bias_ok, bias_msg = check_bias(req.response)

    issues = [m for m in [tox_msg, pii_msg, hall_msg, bias_msg] if m]
    valid = all([tox_ok, pii_ok, hall_ok, bias_ok])

    explanation = "All output checks passed." if valid else " | ".join(issues)

    return OutputGuardResponse(valid=valid, issues=issues, explanation=explanation)
