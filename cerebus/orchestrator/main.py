"""
Orchestrator — single entry point, runs on port 8000.
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from shared.schemas import ChatRequest, ChatResponse, GuardExplanation, ThreatLabel
from shared.config import (
    INPUT_GUARDRAIL_URL, OUTPUT_GUARDRAIL_URL, CORE_LLM_URL,
    REDIS_URL, ADMIN_API_KEY
)

RAG_URL = os.getenv("RAG_URL", "http://localhost:8004")

# Import logger — fail gracefully if DB init fails
try:
    from security_logs.logger import init_db, log_event, get_recent_events, get_stats
    _logger_available = True
except Exception as e:
    print(f"[WARNING] Security logger unavailable: {e}")
    _logger_available = False
    def init_db(): pass
    def log_event(*a, **k): pass
    def get_recent_events(limit=50): return []
    def get_stats(): return {}

# Create http_client at module level so it's always available
http_client = httpx.AsyncClient(timeout=60.0)
redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()
        print("[Orchestrator] Redis connected.")
    except Exception:
        redis_client = None
        print("[Orchestrator] Redis unavailable — rate limiting disabled.")
    try:
        init_db()
    except Exception as e:
        print(f"[Orchestrator] DB init warning: {e}")
    yield
    await http_client.aclose()
    if redis_client:
        await redis_client.aclose()


app = FastAPI(title="Cerebus Orchestrator", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BLOCKED_RESPONSE = "Your request was blocked by Cerebus security policy."
FILTERED_RESPONSE = "This response was filtered by Cerebus output safety checks."


async def _rate_limit(session_id: str) -> bool:
    if redis_client is None:
        return True
    try:
        key = f"rate:{session_id}"
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(key, 60)
        return count <= 10
    except Exception:
        return True


@app.get("/health")
async def health():
    return {"status": "ok", "service": "orchestrator"}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    # Rate limit
    if not await _rate_limit(req.session_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded.")

    # ── Step 1: Input Guardrail ──────────────────────────────────────────────
    try:
        guard_resp = await http_client.post(
            f"{INPUT_GUARDRAIL_URL}/analyze",
            json={
                "prompt": req.prompt,
                "session_id": req.session_id,
                "security_mode": req.security_mode,
            },
        )
        guard_resp.raise_for_status()
        guard_data = guard_resp.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Input guardrail service unavailable.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Input guardrail error: {e}")

    explanation = GuardExplanation(**guard_data["explanation"])

    if not guard_data["safe"]:
        log_event(
            session_id=req.session_id,
            prompt=req.prompt,
            label=explanation.label,
            confidence=explanation.confidence,
            action="BLOCKED",
            explanation=explanation.reason,
            patterns=explanation.triggered_patterns,
        )
        return ChatResponse(response=BLOCKED_RESPONSE, blocked=True, explanation=explanation)

    log_event(
        session_id=req.session_id,
        prompt=req.prompt,
        label=explanation.label,
        confidence=explanation.confidence,
        action="ALLOWED",
        explanation=explanation.reason,
    )

    # ── Step 2: RAG context retrieval ───────────────────────────────────────
    rag_context = ""
    try:
        rag_resp = await http_client.post(
            f"{RAG_URL}/retrieve",
            json={"query": req.prompt, "top_k": 4},
        )
        if rag_resp.status_code == 200:
            rag_context = rag_resp.json().get("context", "")
    except Exception:
        pass  # RAG unavailable → proceed without context

    # ── Step 3: Core LLM ────────────────────────────────────────────────────
    try:
        llm_resp = await http_client.post(
            f"{CORE_LLM_URL}/generate",
            json={
                "prompt": req.prompt,
                "context": rag_context,
                "provider": getattr(req, "provider", "ollama"),
                "model": getattr(req, "model", None),
                "groq_api_key": getattr(req, "groq_api_key", None),
            },
        )
        llm_resp.raise_for_status()
        llm_response = llm_resp.json()["response"]
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Core LLM unavailable. Is Ollama running?")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Core LLM error: {e}")

    # ── Step 3: Output Guardrail ─────────────────────────────────────────────
    try:
        out_resp = await http_client.post(
            f"{OUTPUT_GUARDRAIL_URL}/check",
            json={"response": llm_response, "original_prompt": req.prompt, "rag_context": rag_context or None},
        )
        out_data = out_resp.json()
        if not out_data["valid"]:
            return ChatResponse(
                response=FILTERED_RESPONSE,
                blocked=True,
                explanation=GuardExplanation(
                    label=ThreatLabel.SAFE,
                    confidence=1.0,
                    reason=out_data["explanation"],
                    triggered_patterns=out_data["issues"],
                ),
            )
    except Exception:
        pass  # Output guardrail down → pass through

    return ChatResponse(response=llm_response, blocked=False, explanation=explanation)


@app.get("/logs")
async def logs(x_api_key: str = Header(None), limit: int = 50):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin API key.")
    return get_recent_events(limit)


@app.get("/stats")
async def stats(x_api_key: str = Header(None)):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin API key.")
    return get_stats()
