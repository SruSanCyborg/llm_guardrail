"""
Core LLM Service — Ollama wrapper, runs on port 8003.

POST /generate  →  {"prompt": str, "context": str}  →  {"response": str}
GET  /health    →  {"status": "ok", "model": <model>}
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.config import OLLAMA_BASE_URL, OLLAMA_MODEL

app = FastAPI(title="Cerebus Core LLM (Ollama)")

OLLAMA_GENERATE_URL = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_TAGS_URL = f"{OLLAMA_BASE_URL}/api/tags"


class GenerateRequest(BaseModel):
    prompt: str
    context: str = ""  # RAG-injected context


class GenerateResponse(BaseModel):
    response: str


def _build_prompt(prompt: str, context: str) -> str:
    if context:
        return (
            f"You are a helpful assistant. Use the following context to answer accurately.\n\n"
            f"Context:\n{context}\n\n"
            f"User: {prompt}\nAssistant:"
        )
    return f"You are a helpful assistant.\n\nUser: {prompt}\nAssistant:"


@app.get("/health")
async def health():
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(OLLAMA_TAGS_URL)
            models = [m["name"] for m in r.json().get("models", [])]
            return {"status": "ok", "ollama": "reachable", "available_models": models, "active_model": OLLAMA_MODEL}
        except Exception:
            return {"status": "degraded", "ollama": "unreachable", "active_model": OLLAMA_MODEL}


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest):
    full_prompt = _build_prompt(req.prompt, req.context)

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": full_prompt,
        "stream": False,
        "options": {"temperature": 0.7, "num_predict": 512},
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            r = await client.post(OLLAMA_GENERATE_URL, json=payload)
            r.raise_for_status()
            data = r.json()
            return GenerateResponse(response=data.get("response", "").strip())
        except httpx.ConnectError:
            raise HTTPException(
                status_code=503,
                detail="Ollama is not running. Start it with: ollama serve"
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
