"""
Input Guardrail Service — runs on port 8001.

POST /analyze  →  InputGuardRequest  →  InputGuardResponse
GET  /health   →  {"status": "ok"}
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import redis.asyncio as aioredis
from fastapi import FastAPI
from contextlib import asynccontextmanager

from shared.schemas import InputGuardRequest, InputGuardResponse, ThreatLabel
from shared.config import REDIS_URL, MULTI_TURN_WINDOW, SECURITY_THRESHOLDS
from classifier import classify
from multiturn import multi_turn_risk_score, get_multiturn_explanation

redis_client: aioredis.Redis = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
    except Exception:
        redis_client = None  # Redis unavailable — graceful degradation
    model_path = os.getenv("INPUT_GUARDRAIL_MODEL_PATH")
    if model_path and os.path.exists(model_path):
        from classifier import load_model
        load_model(model_path)
    yield
    if redis_client:
        await redis_client.aclose()


app = FastAPI(title="Cerebus Input Guardrail", lifespan=lifespan)


async def _get_session_history(session_id: str) -> list[str]:
    if redis_client is None:
        return []
    try:
        key = f"session:{session_id}:history"
        history = await redis_client.lrange(key, -MULTI_TURN_WINDOW, -1)
        return history or []
    except Exception:
        return []


async def _push_to_history(session_id: str, prompt: str):
    if redis_client is None:
        return
    try:
        key = f"session:{session_id}:history"
        await redis_client.rpush(key, prompt)
        await redis_client.ltrim(key, -MULTI_TURN_WINDOW, -1)
        await redis_client.expire(key, 3600)
    except Exception:
        pass


@app.get("/health")
async def health():
    return {"status": "ok", "service": "input_guardrail"}


@app.post("/analyze", response_model=InputGuardResponse)
async def analyze(req: InputGuardRequest):
    explanation = classify(req.prompt)

    history = await _get_session_history(req.session_id)
    mt_score = multi_turn_risk_score(history, req.prompt)

    if mt_score >= 0.55:
        mt_reason = get_multiturn_explanation(history, req.prompt)
        if explanation.label == ThreatLabel.SAFE:
            explanation.label = ThreatLabel.JAILBREAK
            explanation.confidence = max(explanation.confidence, mt_score)
            explanation.reason = mt_reason
            explanation.triggered_patterns.append("multi_turn_escalation")
        else:
            explanation.reason += " " + mt_reason
            explanation.confidence = max(explanation.confidence, mt_score)

    thresholds = SECURITY_THRESHOLDS.get(req.security_mode, SECURITY_THRESHOLDS["normal"])
    is_safe = (
        explanation.label == ThreatLabel.SAFE
        or explanation.confidence < thresholds["flag"]
    )

    await _push_to_history(req.session_id, req.prompt)

    return InputGuardResponse(safe=is_safe, explanation=explanation)
