"""
Input Guardrail — DistilBERT + LoRA classifier with XAI explanations.
Falls back to a keyword-pattern heuristic if model isn't loaded yet
(useful during early dev before fine-tuning is done).
"""
import re
from typing import Tuple, List
from shared.schemas import ThreatLabel, GuardExplanation

# ---------------------------------------------------------------------------
# Pattern-based heuristic (dev fallback & XAI signal source)
# ---------------------------------------------------------------------------

PATTERNS = {
    ThreatLabel.PROMPT_INJECTION: [
        r"ignore (all |previous |prior )?(instructions?|prompts?|rules?)",
        r"disregard (your )?(system|previous)",
        r"you are now",
        r"new (system )?prompt:",
        r"override",
        r"<!--.*inject",
    ],
    ThreatLabel.JAILBREAK: [
        r"\bdan\b",                        # Do Anything Now
        r"jailbreak",
        r"pretend (you are|you're) (not|an? (ai|bot|model))",
        r"as an? (evil|unfiltered|uncensored)",
        r"role.?play",
        r"hypothetically",
        r"base64",
        r"in pig latin",
        r"for (educational|research) purposes only",
    ],
    ThreatLabel.SENSITIVE_EXTRACTION: [
        r"(reveal|show|print|output|repeat|leak) (your )?(system prompt|instructions?|training data)",
        r"what (are|were) (your|the) (instructions?|rules?)",
        r"(api|secret) key",
        r"internal (config|configuration|settings?)",
        r"forget (your )?(previous |prior )?(instructions?|rules?)",
    ],
}


def _pattern_scan(text: str) -> dict[ThreatLabel, List[str]]:
    """Return dict of label → list of matched pattern strings."""
    hits: dict[ThreatLabel, List[str]] = {}
    lower = text.lower()
    for label, patterns in PATTERNS.items():
        matched = [p for p in patterns if re.search(p, lower)]
        if matched:
            hits[label] = matched
    return hits


def _heuristic_classify(text: str) -> Tuple[ThreatLabel, float, List[str]]:
    hits = _pattern_scan(text)
    if not hits:
        return ThreatLabel.SAFE, 0.98, []
    # Pick label with most pattern hits
    label = max(hits, key=lambda l: len(hits[l]))
    # Fix C: count total hits across ALL threat labels for confidence
    # so cross-label attacks (e.g. injection + extraction) get higher scores
    total_hits = sum(len(v) for v in hits.values())
    confidence = min(0.75 + 0.07 * total_hits, 0.97)
    triggered = hits[label]
    return label, confidence, triggered


# ---------------------------------------------------------------------------
# Model-based classifier (loaded lazily after fine-tuning)
# ---------------------------------------------------------------------------

_model = None
_tokenizer = None

ID2LABEL = {0: ThreatLabel.SAFE, 1: ThreatLabel.PROMPT_INJECTION,
            2: ThreatLabel.JAILBREAK, 3: ThreatLabel.SENSITIVE_EXTRACTION}

LABEL_REASONS = {
    ThreatLabel.SAFE: "No malicious patterns detected.",
    ThreatLabel.PROMPT_INJECTION: "Prompt contains instruction-override language attempting to hijack the system prompt.",
    ThreatLabel.JAILBREAK: "Prompt uses social-engineering or encoding techniques to bypass safety filters.",
    ThreatLabel.SENSITIVE_EXTRACTION: "Prompt attempts to extract system instructions, training data, or API secrets.",
}


def load_model(model_path: str):
    """Call this once at startup if a fine-tuned model exists."""
    global _model, _tokenizer
    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    from peft import PeftModel

    print(f"[InputGuardrail] Loading model from {model_path}...")
    _tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
    base = AutoModelForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=4)
    _model = PeftModel.from_pretrained(base, model_path)
    _model.eval()
    print("[InputGuardrail] Model loaded.")


def _model_classify(text: str) -> Tuple[ThreatLabel, float, List[str]]:
    import torch
    inputs = _tokenizer(text, return_tensors="pt",
                        truncation=True, max_length=512)
    with torch.no_grad():
        logits = _model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0].tolist()
    idx = int(torch.argmax(logits))
    label = ID2LABEL[idx]
    confidence = probs[idx]
    # XAI: also run patterns to surface triggered rules even for model path
    hits = _pattern_scan(text)
    triggered = hits.get(label, [])
    return label, confidence, triggered


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify(text: str) -> GuardExplanation:
    if _model is not None:
        label, confidence, triggered = _model_classify(text)
    else:
        label, confidence, triggered = _heuristic_classify(text)

    reason = LABEL_REASONS[label]
    if triggered:
        reason += f" Matched rules: {', '.join(triggered[:3])}."

    return GuardExplanation(
        label=label,
        confidence=round(confidence, 4),
        reason=reason,
        triggered_patterns=triggered,
    )
