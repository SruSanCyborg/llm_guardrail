"""
RAG Indexer — builds a FAISS vector store from documents in the docs/ folder.
Supports .txt and .pdf files.
Run once to build the index: python indexer.py
"""
import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from pathlib import Path
from sentence_transformers import SentenceTransformer
import faiss
import pickle
import numpy as np

DOCS_DIR = Path(__file__).parent / "docs"
INDEX_PATH = Path(__file__).parent / "faiss.index"
CHUNKS_PATH = Path(__file__).parent / "chunks.pkl"

EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHUNK_SIZE = 512       # characters
CHUNK_OVERLAP = 50


def _load_texts() -> list[tuple[str, str]]:
    """Returns list of (filename, text) for all docs."""
    results = []
    for f in DOCS_DIR.iterdir():
        if f.suffix == ".txt":
            results.append((f.name, f.read_text(encoding="utf-8", errors="ignore")))
        elif f.suffix == ".pdf":
            try:
                import pdfplumber
                with pdfplumber.open(f) as pdf:
                    text = "\n".join(p.extract_text() or "" for p in pdf.pages)
                results.append((f.name, text))
            except ImportError:
                print(f"[RAG] pdfplumber not installed, skipping {f.name}")
    return results


def _chunk(text: str, source: str) -> list[dict]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunk = text[start:end].strip()
        if chunk:
            chunks.append({"text": chunk, "source": source})
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


def build_index():
    print("[RAG] Loading documents...")
    texts = _load_texts()
    if not texts:
        print(f"[RAG] No documents found in {DOCS_DIR}. Add .txt or .pdf files.")
        return

    all_chunks = []
    for source, text in texts:
        all_chunks.extend(_chunk(text, source))
    print(f"[RAG] {len(all_chunks)} chunks from {len(texts)} documents.")

    print("[RAG] Generating embeddings...")
    model = SentenceTransformer(EMBEDDING_MODEL)
    embeddings = model.encode([c["text"] for c in all_chunks], show_progress_bar=True)
    embeddings = np.array(embeddings).astype("float32")

    print("[RAG] Building FAISS index...")
    dim = embeddings.shape[1]
    index = faiss.IndexFlatL2(dim)
    index.add(embeddings)

    faiss.write_index(index, str(INDEX_PATH))
    with open(CHUNKS_PATH, "wb") as f:
        pickle.dump(all_chunks, f)

    print(f"[RAG] Index saved → {INDEX_PATH} ({index.ntotal} vectors)")


if __name__ == "__main__":
    build_index()
