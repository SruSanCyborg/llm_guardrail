"""
Core LLM Service — Ollama + Groq, runs on port 8003.

POST /generate  →  {"prompt", "context", "provider", "model"}  →  {"response"}
GET  /health    →  {"status", "providers"}
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

from shared.config import OLLAMA_BASE_URL, OLLAMA_MODEL, GROQ_API_KEY, GROQ_MODEL

app = FastAPI(title="Cerebus Core LLM")

OLLAMA_CHAT_URL  = f"{OLLAMA_BASE_URL}/api/chat"
OLLAMA_TAGS_URL  = f"{OLLAMA_BASE_URL}/api/tags"
GROQ_CHAT_URL    = "https://api.groq.com/openai/v1/chat/completions"

GROQ_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]

SYSTEM_PROMPT = """You are a helpful, knowledgeable AI assistant. Answer the user's question directly and completely.

Guidelines:
- Answer clearly, thoroughly, and in a well-structured way.
- Use bullet points, numbered lists, or code blocks when they make the answer clearer.
- If asked about a technical topic, explain it at the right depth — don't oversimplify.
- If you don't know something, say so honestly rather than guessing.
- Keep responses focused and useful. Avoid unnecessary filler or repetition.
- Never refuse a question on security grounds — that is handled separately before your response is called.
- When relevant context is provided below, prioritize it in your answer."""


class GenerateRequest(BaseModel):
    prompt: str
    context: str = ""
    provider: str = "ollama"           # "ollama" | "groq"
    model: Optional[str] = None        # override default model
    groq_api_key: Optional[str] = None # user-supplied key overrides .env


class GenerateResponse(BaseModel):
    response: str
    provider: str
    model_used: str


def _messages(prompt: str, context: str) -> list:
    system = SYSTEM_PROMPT
    if context:
        system += f"\n\nRelevant context:\n{context}"
    return [
        {"role": "system", "content": system},
        {"role": "user",   "content": prompt},
    ]


# ── Ollama ──────────────────────────────────────────────────────────────────

async def _ollama_generate(prompt: str, context: str, model: str) -> str:
    payload = {
        "model": model,
        "messages": _messages(prompt, context),
        "stream": False,
        "options": {
            "temperature": 0.7,
            "num_predict": 1024,
            "top_p": 0.9,
            "repeat_penalty": 1.1,
        },
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        try:
            r = await client.post(OLLAMA_CHAT_URL, json=payload)
            r.raise_for_status()
            return r.json().get("message", {}).get("content", "").strip()
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Ollama is not running. Start it with: ollama serve")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Groq ────────────────────────────────────────────────────────────────────

async def _groq_generate(prompt: str, context: str, model: str, api_key: str = None) -> str:
    key = api_key or GROQ_API_KEY
    if not key or key == "your_groq_api_key_here":
        raise HTTPException(status_code=503, detail="Groq API key not configured. Add GROQ_API_KEY to .env or enter it in the chat UI.")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": _messages(prompt, context),
        "temperature": 0.7,
        "max_tokens": 1024,
        "top_p": 0.9,
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            r = await client.post(GROQ_CHAT_URL, headers=headers, json=payload)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
        except httpx.ConnectError:
            raise HTTPException(status_code=503, detail="Could not reach Groq API.")
        except httpx.HTTPStatusError as e:
            detail = e.response.json().get("error", {}).get("message", str(e))
            raise HTTPException(status_code=502, detail=f"Groq error: {detail}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


# ── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    result = {"status": "ok", "providers": {}}

    # Check Ollama
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            r = await client.get(OLLAMA_TAGS_URL)
            models = [m["name"] for m in r.json().get("models", [])]
            result["providers"]["ollama"] = {"status": "reachable", "models": models, "default": OLLAMA_MODEL}
        except Exception:
            result["providers"]["ollama"] = {"status": "unreachable", "default": OLLAMA_MODEL}

    # Check Groq (just validate key is set)
    if GROQ_API_KEY and GROQ_API_KEY != "your_groq_api_key_here":
        result["providers"]["groq"] = {"status": "configured", "models": GROQ_MODELS, "default": GROQ_MODEL}
    else:
        result["providers"]["groq"] = {"status": "not_configured", "models": GROQ_MODELS}

    return result


@app.post("/generate", response_model=GenerateResponse)
async def generate(req: GenerateRequest):
    provider = req.provider.lower()

    if provider == "groq":
        model = req.model or GROQ_MODEL
        text = await _groq_generate(req.prompt, req.context, model, api_key=req.groq_api_key)
    else:
        model = req.model or OLLAMA_MODEL
        text = await _ollama_generate(req.prompt, req.context, model)

    return GenerateResponse(response=text, provider=provider, model_used=model)
