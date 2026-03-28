"""
Self-Learning Engine — Heretic-inspired threat direction analysis.

How it works (inspired by Heretic's directional ablation concept):
  Heretic finds "refusal directions" in an LLM's activation space by computing
  (mean embedding of harmful prompts) - (mean embedding of benign prompts),
  then suppresses that direction in the model weights.

  We use the SAME idea but in REVERSE — for DETECTION:
  1. Embed all blocked prompts → compute "threat centroid" per label
  2. Embed new incoming prompts → measure cosine similarity to each centroid
  3. High similarity to a threat centroid = escalate confidence
  4. When 10+ new attacks accumulate → auto-generate regex rules + trigger retrain

Components:
  - Pattern extractor: TF-IDF n-gram analysis on attack text
  - Threat direction: sentence-transformers embeddings + cosine similarity
  - Auto-retraining: triggers DistilBERT fine-tuning with new examples
"""
import re
import json
import math
import pickle
import hashlib
import os
import sys
from datetime import datetime
from typing import List, Tuple, Dict, Optional
from collections import Counter, defaultdict

LEARNED_FILE   = os.path.join(os.path.dirname(__file__), "learned_patterns.json")
VECTORS_FILE   = os.path.join(os.path.dirname(__file__), "threat_vectors.pkl")
RETRAIN_QUEUE  = os.path.join(os.path.dirname(__file__), "retrain_queue.jsonl")
EVENTS_FILE    = os.path.join(os.path.dirname(__file__), "learning_events.jsonl")
RETRAIN_THRESHOLD = 10

# ── STOP WORDS (for n-gram extraction) ──────────────────────────────────────
STOP_WORDS = {
    'a','an','the','and','or','but','in','on','at','to','for','of','with',
    'is','it','i','you','me','my','your','we','they','this','that','what',
    'how','can','will','do','be','are','was','were','have','has','had',
    'please','would','could','should','just','get','want','make','let','now',
    'tell','say','give','show','help','use','like','know','think','need',
    'see','look','find','go','come','back','here','there','where','when',
    'who','which','about','up','out','if','than','then','so','no','not',
    'all','any','some','other','into','also','more','its','their','our',
}

# ── SENTENCE EMBEDDER (lazy load) ───────────────────────────────────────────
_embedder = None

def _get_embedder():
    global _embedder
    if _embedder is None:
        try:
            from sentence_transformers import SentenceTransformer
            _embedder = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception:
            _embedder = False  # mark unavailable
    return _embedder if _embedder is not False else None


# ── LEARNED PATTERNS I/O ─────────────────────────────────────────────────────

def load_learned() -> dict:
    try:
        with open(LEARNED_FILE) as f:
            return json.load(f)
    except Exception:
        return {"PROMPT_INJECTION":[],"JAILBREAK":[],"SENSITIVE_EXTRACTION":[],"HARMFUL_CONTENT":[],"meta":{"total_learned":0,"last_updated":None,"retrain_count":0,"threat_vectors_computed":False}}


def save_learned(data: dict):
    data["meta"]["last_updated"] = datetime.utcnow().isoformat()
    with open(LEARNED_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ── PATTERN EXTRACTION ───────────────────────────────────────────────────────

def _tokenize(text: str) -> List[str]:
    tokens = re.findall(r'\b[a-z]{3,}\b', text.lower())
    return [t for t in tokens if t not in STOP_WORDS]


def _extract_ngrams(text: str, n: int = 2) -> List[str]:
    tokens = _tokenize(text)
    return [' '.join(tokens[i:i+n]) for i in range(len(tokens)-n+1)]


def _ngrams_to_regex(ngram: str) -> str:
    """Convert an extracted n-gram into a safe regex pattern."""
    words = ngram.strip().split()
    escaped = [re.escape(w) for w in words]
    return r'\b' + r'.{0,15}'.join(escaped) + r'\b'


def extract_patterns_from_attack(text: str, existing_patterns: List[str]) -> List[str]:
    """
    Analyse attack text and return new regex patterns not already covered.
    Only generates bigrams and trigrams — never single words — to avoid
    false positives on innocent sentences.
    """
    candidates: List[Tuple[float, str]] = []

    # Bigrams only (minimum meaningful unit)
    for ng in set(_extract_ngrams(text, 2)):
        words = ng.split()
        # Both words must be meaningful (length >= 4) and not already covered
        if all(len(w) >= 4 for w in words):
            pattern = _ngrams_to_regex(ng)
            if not any(words[0] in p and words[1] in p for p in existing_patterns):
                candidates.append((0.8, pattern))

    # Trigrams (strongest signal — very specific)
    for ng in set(_extract_ngrams(text, 3)):
        words = ng.split()
        if all(len(w) >= 3 for w in words):
            pattern = _ngrams_to_regex(ng)
            if not any(words[0] in p for p in existing_patterns):
                candidates.append((1.0, pattern))

    # Deduplicate, validate, take top 4
    seen = set()
    results = []
    for score, pat in sorted(candidates, reverse=True):
        if pat not in seen:
            seen.add(pat)
            try:
                re.compile(pat)
                results.append(pat)
            except re.error:
                pass
        if len(results) >= 4:
            break

    return results


# ── THREAT VECTOR ENGINE (Heretic concept) ───────────────────────────────────

def _load_vectors() -> dict:
    if os.path.exists(VECTORS_FILE):
        with open(VECTORS_FILE, "rb") as f:
            return pickle.load(f)
    return {"centroids": {}, "examples": defaultdict(list)}


def _save_vectors(data: dict):
    with open(VECTORS_FILE, "wb") as f:
        pickle.dump(data, f)


def _cosine_sim(a: list, b: list) -> float:
    dot = sum(x*y for x,y in zip(a,b))
    norm_a = math.sqrt(sum(x*x for x in a))
    norm_b = math.sqrt(sum(x*x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def update_threat_vectors(text: str, label: str):
    """
    Add a new attack embedding to the threat centroid for this label.
    This is the Heretic-inspired part: we compute the mean embedding
    of all attacks per label = the 'threat direction' for that category.
    """
    embedder = _get_embedder()
    if embedder is None:
        return

    try:
        embedding = embedder.encode(text, normalize_embeddings=True).tolist()
        vdata = _load_vectors()
        vdata["examples"][label].append(embedding)

        # Recompute centroid (mean of all embeddings for this label)
        examples = vdata["examples"][label]
        n = len(examples)
        dim = len(examples[0])
        centroid = [sum(e[d] for e in examples) / n for d in range(dim)]
        # Normalize centroid
        norm = math.sqrt(sum(x*x for x in centroid))
        if norm > 0:
            centroid = [x/norm for x in centroid]
        vdata["centroids"][label] = centroid

        _save_vectors(vdata)
    except Exception as e:
        print(f"[SelfLearning] Vector update failed: {e}")


def get_threat_similarity(text: str) -> Dict[str, float]:
    """
    Compute cosine similarity of text embedding against each threat centroid.
    Returns dict of label → similarity score (0-1).
    High similarity means text is semantically close to known attacks of that type.
    """
    embedder = _get_embedder()
    if embedder is None:
        return {}

    try:
        vdata = _load_vectors()
        if not vdata["centroids"]:
            return {}
        embedding = embedder.encode(text, normalize_embeddings=True).tolist()
        return {
            label: round(_cosine_sim(embedding, centroid), 4)
            for label, centroid in vdata["centroids"].items()
        }
    except Exception:
        return {}


# ── RETRAIN QUEUE ─────────────────────────────────────────────────────────────

def queue_for_retrain(text: str, label: str, confidence: float):
    """Add a confirmed attack example to the retrain queue."""
    example = {
        "text": text[:500],  # cap length
        "label": label,
        "confidence": confidence,
        "timestamp": datetime.utcnow().isoformat(),
    }
    with open(RETRAIN_QUEUE, "a") as f:
        f.write(json.dumps(example) + "\n")


def _count_queue() -> int:
    if not os.path.exists(RETRAIN_QUEUE):
        return 0
    with open(RETRAIN_QUEUE) as f:
        return sum(1 for _ in f)


def _load_queue() -> List[dict]:
    if not os.path.exists(RETRAIN_QUEUE):
        return []
    examples = []
    with open(RETRAIN_QUEUE) as f:
        for line in f:
            try:
                examples.append(json.loads(line.strip()))
            except Exception:
                pass
    return examples


def trigger_retrain_if_ready() -> Optional[str]:
    """
    If enough new examples have accumulated, trigger DistilBERT fine-tuning.
    Returns a status message, or None if threshold not reached.
    """
    count = _count_queue()
    if count < RETRAIN_THRESHOLD:
        return None

    examples = _load_queue()
    sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

    try:
        # Import the training script and run with new examples appended
        from input_guardrail.train import TRAIN_DATA, run_training
        combined = TRAIN_DATA + [(e["text"], e["label"]) for e in examples]
        run_training(combined)

        # Clear queue after successful retrain
        open(RETRAIN_QUEUE, "w").close()

        # Update meta
        data = load_learned()
        data["meta"]["retrain_count"] = data["meta"].get("retrain_count", 0) + 1
        save_learned(data)

        return f"Retrained on {len(combined)} examples ({count} new attacks)."
    except Exception as e:
        return f"Retrain queued but failed: {e}"


# ── MAIN LEARN FUNCTION ───────────────────────────────────────────────────────

def _save_event(event: dict):
    """Persist a learning event so the monitor can replay it."""
    with open(EVENTS_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def get_events(limit: int = 100) -> List[dict]:
    """Return recent learning events, newest first."""
    if not os.path.exists(EVENTS_FILE):
        return []
    events = []
    with open(EVENTS_FILE) as f:
        for line in f:
            try:
                events.append(json.loads(line.strip()))
            except Exception:
                pass
    return list(reversed(events[-limit:]))


def learn_from_event(prompt: str, label: str, confidence: float) -> dict:
    """
    Called after every BLOCKED event. Returns a summary of what was learned.
    """
    result = {
        "timestamp": datetime.utcnow().isoformat(),
        "label": label,
        "confidence": confidence,
        "prompt_preview": prompt[:80] + ("…" if len(prompt) > 80 else ""),
        "patterns_added": [],
        "vector_updated": False,
        "retrain_triggered": False,
        "retrain_message": None,
        "threat_similarities": {},
    }

    data = load_learned()
    existing = data.get(label, [])

    # 1. Extract new patterns from this attack
    new_patterns = extract_patterns_from_attack(prompt, existing)
    if new_patterns:
        data[label] = existing + new_patterns
        data["meta"]["total_learned"] = data["meta"].get("total_learned", 0) + len(new_patterns)
        result["patterns_added"] = new_patterns
        save_learned(data)

    # 2. Update threat direction vector (Heretic concept)
    update_threat_vectors(prompt, label)
    result["vector_updated"] = True

    # 3. Compute similarity to all known threat centroids
    result["threat_similarities"] = get_threat_similarity(prompt)

    # 4. Queue for retraining
    queue_for_retrain(prompt, label, confidence)

    # 5. Trigger retrain if threshold reached
    msg = trigger_retrain_if_ready()
    if msg:
        result["retrain_triggered"] = True
        result["retrain_message"] = msg

    # 6. Persist event for monitor replay
    _save_event(result)

    return result


def get_stats() -> dict:
    data = load_learned()
    vdata = _load_vectors()
    queue_count = _count_queue()
    return {
        "learned_patterns": {
            k: len(v) for k, v in data.items() if k != "meta"
        },
        "total_learned": data["meta"].get("total_learned", 0),
        "last_updated": data["meta"].get("last_updated"),
        "retrain_count": data["meta"].get("retrain_count", 0),
        "queue_size": queue_count,
        "retrain_threshold": RETRAIN_THRESHOLD,
        "threat_centroids_available": list(vdata.get("centroids", {}).keys()),
        "examples_per_label": {k: len(v) for k, v in vdata.get("examples", {}).items()},
        "embedder_available": _get_embedder() is not None,
    }
