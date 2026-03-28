"""
RAG Service — runs on port 8004.

POST /retrieve   →  {"query": str, "top_k": int}  →  chunks + context string
GET  /health     →  index status
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI
from pydantic import BaseModel
from retriever import retrieve, retrieve_as_context, INDEX_PATH

app = FastAPI(title="Cerebus RAG Service")


class RetrieveRequest(BaseModel):
    query: str
    top_k: int = 4


class RetrieveResponse(BaseModel):
    context: str
    chunks: list[dict]
    index_available: bool


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "rag",
        "index_available": INDEX_PATH.exists(),
    }


@app.post("/retrieve", response_model=RetrieveResponse)
async def retrieve_endpoint(req: RetrieveRequest):
    chunks = retrieve(req.query, req.top_k)
    context = retrieve_as_context(req.query, req.top_k)
    return RetrieveResponse(
        context=context,
        chunks=chunks,
        index_available=INDEX_PATH.exists(),
    )
