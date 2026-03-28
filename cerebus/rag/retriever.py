"""
RAG Retriever — loads the FAISS index and retrieves top-K relevant chunks.
"""
import pickle
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

INDEX_PATH = Path(__file__).parent / "faiss.index"
CHUNKS_PATH = Path(__file__).parent / "chunks.pkl"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

_index = None
_chunks = None
_model = None


def _load():
    global _index, _chunks, _model
    if _index is not None:
        return True
    if not INDEX_PATH.exists() or not CHUNKS_PATH.exists():
        return False
    import faiss
    _index = faiss.read_index(str(INDEX_PATH))
    with open(CHUNKS_PATH, "rb") as f:
        _chunks = pickle.load(f)
    _model = SentenceTransformer(EMBEDDING_MODEL)
    print(f"[RAG] Loaded index with {_index.ntotal} vectors.")
    return True


def retrieve(query: str, top_k: int = 4) -> list[dict]:
    """Returns top-K relevant chunks for the query. Empty list if no index."""
    if not _load():
        return []
    query_vec = _model.encode([query]).astype("float32")
    distances, indices = _index.search(query_vec, top_k)
    results = []
    for dist, idx in zip(distances[0], indices[0]):
        if idx < len(_chunks):
            results.append({
                "text": _chunks[idx]["text"],
                "source": _chunks[idx]["source"],
                "score": float(dist),
            })
    return results


def retrieve_as_context(query: str, top_k: int = 4) -> str:
    """Returns retrieved chunks formatted as a single context string."""
    chunks = retrieve(query, top_k)
    if not chunks:
        return ""
    parts = []
    for i, c in enumerate(chunks, 1):
        parts.append(f"[Source {i}: {c['source']}]\n{c['text']}")
    return "\n\n".join(parts)
