"""
Self-Learning Service — runs on port 8005.

POST /learn      →  {prompt, label, confidence}  →  learn result
GET  /patterns   →  all learned patterns
GET  /stats      →  learning statistics
GET  /similarity →  ?text=...  →  cosine similarity to each threat centroid
GET  /health     →  {status}
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from learner import learn_from_event, load_learned, get_stats, get_threat_similarity, get_events

app = FastAPI(title="Cerebus Self-Learning Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class LearnRequest(BaseModel):
    prompt: str
    label: str
    confidence: float = 0.9


@app.get("/health")
def health():
    s = get_stats()
    return {
        "status": "ok",
        "service": "self_learning",
        "total_learned_patterns": s["total_learned"],
        "retrain_count": s["retrain_count"],
        "embedder": s["embedder_available"],
    }


@app.post("/learn")
async def learn(req: LearnRequest):
    result = learn_from_event(req.prompt, req.label, req.confidence)
    return result


@app.get("/patterns")
def patterns():
    data = load_learned()
    return {k: v for k, v in data.items() if k != "meta"}


@app.get("/stats")
def stats():
    return get_stats()


@app.get("/events")
def events(limit: int = 100):
    """Return recent learning events — what was learned, when, and from what attack."""
    return get_events(limit)


@app.get("/similarity")
def similarity(text: str = Query(..., description="Prompt text to compare against threat centroids")):
    return get_threat_similarity(text)
