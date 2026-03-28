"""
Input Guardrail — DistilBERT + LoRA classifier with XAI explanations.
Falls back to a keyword-pattern heuristic if model isn't loaded yet
(useful during early dev before fine-tuning is done).

Self-learning integration: loads patterns discovered by the Self-Learning
Engine and boosts confidence using threat-direction cosine similarity
(Heretic-inspired vector analysis).
"""
import re
import os
import sys
import json
import threading
import time
from typing import Tuple, List
from shared.schemas import ThreatLabel, GuardExplanation

# ---------------------------------------------------------------------------
# Learned patterns (from Self-Learning Engine) — hot-reloaded every 60s
# ---------------------------------------------------------------------------

LEARNED_FILE = os.path.join(os.path.dirname(__file__), "..", "self_learning", "learned_patterns.json")
_learned_patterns: dict = {}
_learned_lock = threading.Lock()

def _load_learned_patterns():
    global _learned_patterns
    try:
        if os.path.exists(LEARNED_FILE):
            with open(LEARNED_FILE) as f:
                data = json.load(f)
            with _learned_lock:
                _learned_patterns = {k: v for k, v in data.items() if k != "meta"}
    except Exception:
        pass

def _reload_loop():
    while True:
        time.sleep(60)
        _load_learned_patterns()

_load_learned_patterns()
threading.Thread(target=_reload_loop, daemon=True).start()


def _get_learned_for_label(label: ThreatLabel) -> List[str]:
    with _learned_lock:
        return list(_learned_patterns.get(label.value, []))

# ---------------------------------------------------------------------------
# Pattern-based heuristic (dev fallback & XAI signal source)
# ---------------------------------------------------------------------------

PATTERNS = {
    ThreatLabel.HARMFUL_CONTENT: [

        # ── VIOLENCE ───────────────────────────────────────────────────────────
        r"\b(kill|murder|assassinate|shoot|stab|strangle|beat up|torture|slaughter|behead|lynch)\b.{0,40}\b(person|people|someone|him|her|them|man|woman|child|human|family|neighbor|teacher|boss)\b",
        r"\bhow (to|do i|can i|would i).{0,25}(kill|murder|hurt|harm|attack|poison|bomb|shoot|stab|strangle|beat)\b",
        r"\bwant to (kill|murder|hurt|harm|attack|destroy|eliminate|get rid of).{0,40}\b(person|people|someone|him|her|them|my)\b",
        r"\b(best|easiest|quickest|fastest) way to (kill|murder|hurt|harm|attack|eliminate)\b",
        r"\b(plan(ning)?|thinking about|going to) (kill|murder|shoot|stab|attack|hurt)\b",

        # ── WEAPONS ────────────────────────────────────────────────────────────
        r"\b(make|build|create|assemble|construct|buy|get|obtain).{0,25}(bomb|explosive|grenade|landmine|ied|pipe bomb|molotov)\b",
        r"\b(synthesize|produce|manufacture|make).{0,25}(poison|nerve agent|sarin|vx gas|ricin|cyanide|anthrax|bioweapon|chemical weapon)\b",
        r"\b(3d print|print|make|convert|modify).{0,25}(gun|firearm|rifle|pistol|weapon|silencer|suppressor|auto.?fire)\b",
        r"\b(illegal|untraceable|ghost).{0,15}(gun|firearm|weapon|ammo)\b",
        r"\bhow to (get|obtain|buy).{0,20}(gun|weapon|firearm) without.{0,20}(background check|id|license|permit)\b",

        # ── TERRORISM & EXTREMISM ──────────────────────────────────────────────
        r"\b(join|recruit|radicalize|support|fund).{0,20}(isis|al.?qaeda|taliban|terror|terrorist|extremist|jihad)\b",
        r"\b(plan|carry out|execute|organize).{0,20}(terror|terrorist attack|bombing|mass shooting|genocide)\b",
        r"\bhow to (radicalize|recruit|incite).{0,20}(people|others|youth|followers)\b",
        r"\b(white supremac|neo.?nazi|ethnic cleansing|race war|great replacement)\b",
        r"\b(manifesto|propaganda).{0,20}(attack|shooting|terror|violence|kill)\b",

        # ── SELF-HARM & SUICIDE ────────────────────────────────────────────────
        r"\b(suicide|kill myself|end my life|take my (own )?life|want to die)\b",
        r"\b(how to|ways to|best way to).{0,20}(commit suicide|kill myself|end my life|self.?harm|overdose)\b",
        r"\b(cut|cutting|burn|burning).{0,15}(myself|my (arms?|wrists?|legs?|skin))\b",
        r"\b(method|methods|means).{0,20}(suicide|self.?harm|self.?kill)\b",
        r"\b(pills?|medication|drug).{0,20}(overdose|lethal dose|how many to die)\b",

        # ── CHILD SAFETY ───────────────────────────────────────────────────────
        r"\bchild (pornography|porn|sexual abuse|exploitation|grooming|trafficking|nude|naked)\b",
        r"\b(csam|cp).{0,10}(image|video|photo|content|link)\b",
        r"\b(groom|grooming|lure|attract).{0,20}(child|minor|kid|teen|underage)\b",
        r"\bhow to.{0,20}(approach|talk to|meet|get access to).{0,20}(child|minor|kid|underage)\b",
        r"\b(sexual|sex).{0,15}(child|minor|kid|underage|boy|girl).{0,15}(act|content|image|video)\b",

        # ── SEXUAL VIOLENCE ────────────────────────────────────────────────────
        r"\b(rape|sexual assault|molest|molestation|non.?consensual)\b",
        r"\bhow to (drug|sedate|incapacitate).{0,20}(person|someone|woman|man|victim)\b",
        r"\b(roofie|rohypnol|date rape drug).{0,20}(use|give|slip|put in)\b",

        # ── DRUGS & DANGEROUS SUBSTANCES ──────────────────────────────────────
        r"\bhow to (make|cook|synthesize|produce|manufacture).{0,20}(meth|methamphetamine|heroin|cocaine|fentanyl|lsd|mdma|crack)\b",
        r"\b(buy|sell|deal|obtain|get).{0,15}(meth|heroin|cocaine|fentanyl|crack|lsd|mdma|illegal drugs)\b",
        r"\b(darkweb|dark web|tor).{0,20}(buy|get|order|purchase).{0,20}(drugs|weapon|gun|illegal)\b",
        r"\bhow to (get high|overdose on purpose|abuse).{0,20}(prescription|medication|pills?)\b",

        # ── CYBERCRIME ─────────────────────────────────────────────────────────
        r"\bhow to (hack|break into|gain access to|bypass).{0,30}(someone.s|account|computer|network|server|database|camera|phone)\b",
        r"\b(create|write|build|make).{0,20}(malware|ransomware|keylogger|trojan|virus|worm|spyware|botnet|rat)\b",
        r"\b(steal|phish|spoof).{0,20}(credit card|password|login|credentials|identity|bank account)\b",
        r"\bhow to (ddos|dos|flood|take down).{0,20}(website|server|network|service)\b",
        r"\b(skimmer|card skimming|carding|fullz|dumps).{0,20}(buy|sell|use|make)\b",

        # ── HUMAN TRAFFICKING ──────────────────────────────────────────────────
        r"\b(traffic|traffick|smuggle).{0,20}(human|person|people|women|children|migrant|worker)\b",
        r"\bhow to (transport|move|hide|control).{0,20}(trafficked|smuggled).{0,20}(person|people|victim)\b",
        r"\b(forced labor|sex trafficking|modern slavery).{0,20}(how|recruit|control|profit)\b",

        # ── FRAUD & FINANCIAL CRIME ────────────────────────────────────────────
        r"\bhow to (launder|wash|hide).{0,20}(money|cash|funds|proceeds)\b",
        r"\b(create|make|forge|fake).{0,20}(counterfeit|fake).{0,20}(money|currency|id|passport|documents?)\b",
        r"\bhow to (run|set up|operate).{0,20}(scam|ponzi|pyramid scheme|fraud)\b",
        r"\b(steal|commit|do).{0,15}(identity theft|insurance fraud|tax fraud|wire fraud)\b",

        # ── STALKING & HARASSMENT ──────────────────────────────────────────────
        r"\bhow to (track|stalk|follow|locate|find).{0,20}(someone|person|ex|girlfriend|boyfriend|wife|husband) without.{0,20}(knowing|permission)\b",
        r"\b(spy on|surveil|monitor).{0,20}(someone|person|partner|ex).{0,20}(without|secretly|covertly)\b",
        r"\bhow to (dox|doxx|expose).{0,20}(person|someone|user|address|location)\b",
        r"\b(send|make).{0,15}(death threat|threat|threatening).{0,20}(anonymous|untraceable)\b",

        # ── DANGEROUS MEDICAL / HEALTH ─────────────────────────────────────────
        r"\b(lethal|deadly|fatal).{0,15}(dose|amount|quantity).{0,20}(of|for).{0,20}(medication|drug|pill|substance)\b",
        r"\bhow (much|many).{0,20}(pills?|tablets?|medication|tylenol|acetaminophen|ibuprofen).{0,20}(to die|to kill|lethal|overdose)\b",
        r"\bhow to (poison|contaminate|taint).{0,20}(food|water|drink|supply)\b",
        r"\b(fake|forge|falsify).{0,20}(medical|prescription|doctor).{0,20}(record|note|prescription|diagnosis)\b",

        # ── ANIMAL CRUELTY ─────────────────────────────────────────────────────
        r"\bhow to (hurt|harm|torture|kill|abuse).{0,20}(animal|dog|cat|pet)\b",
        r"\b(animal|dog|cat).{0,20}(torture|abuse|cruelty|harm).{0,20}(how|method|way)\b",
    ],
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
    """Return dict of label → list of matched pattern strings (static + learned)."""
    hits: dict[ThreatLabel, List[str]] = {}
    lower = text.lower()
    for label, patterns in PATTERNS.items():
        # Static patterns
        matched = [p for p in patterns if re.search(p, lower)]
        # Learned patterns from Self-Learning Engine
        learned = _get_learned_for_label(label)
        for p in learned:
            try:
                if re.search(p, lower) and p not in matched:
                    matched.append("[learned] " + p)
            except re.error:
                pass
        if matched:
            hits[label] = matched
    return hits


def _heuristic_classify(text: str) -> Tuple[ThreatLabel, float, List[str]]:
    hits = _pattern_scan(text)
    if not hits:
        return ThreatLabel.SAFE, 0.98, []
    # Pick label with most pattern hits
    label = max(hits, key=lambda l: len(hits[l]))
    # Harmful content always gets max confidence — never let it slip through
    if label == ThreatLabel.HARMFUL_CONTENT:
        return label, 0.99, hits[label]
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
            2: ThreatLabel.JAILBREAK, 3: ThreatLabel.SENSITIVE_EXTRACTION,
            4: ThreatLabel.HARMFUL_CONTENT}

LABEL_REASONS = {
    ThreatLabel.SAFE: "No malicious patterns detected.",
    ThreatLabel.PROMPT_INJECTION: "Prompt contains instruction-override language attempting to hijack the system prompt.",
    ThreatLabel.JAILBREAK: "Prompt uses social-engineering or encoding techniques to bypass safety filters.",
    ThreatLabel.SENSITIVE_EXTRACTION: "Prompt attempts to extract system instructions, training data, or API secrets.",
    ThreatLabel.HARMFUL_CONTENT: "Prompt contains requests for violence, self-harm, illegal activity, or other harmful content.",
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
# Threat vector similarity boost (Heretic-inspired)
# ---------------------------------------------------------------------------

def _vector_boost(text: str, label: ThreatLabel, confidence: float) -> Tuple[float, str]:
    """
    Query the Self-Learning Engine's threat centroids.
    If the text is semantically very close to known attacks of this label,
    boost the confidence score. This is the core Heretic concept applied
    to detection: we suppress the refusal direction in Heretic; here we
    AMPLIFY the detection confidence in the threat direction.
    """
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from self_learning.learner import get_threat_similarity
        sims = get_threat_similarity(text)
        if not sims:
            return confidence, ""
        best_label = max(sims, key=sims.get)
        best_sim = sims.get(best_label, 0.0)
        # If high similarity to any threat centroid, boost confidence
        if best_sim >= 0.75:
            boost = (best_sim - 0.75) * 0.4  # up to +0.1 boost
            new_conf = min(confidence + boost, 0.99)
            note = f" Threat-vector similarity {round(best_sim*100)}% to {best_label}."
            return new_conf, note
    except Exception:
        pass
    return confidence, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify(text: str) -> GuardExplanation:
    if _model is not None:
        label, confidence, triggered = _model_classify(text)
    else:
        label, confidence, triggered = _heuristic_classify(text)

    # Apply threat vector similarity boost from self-learning engine
    confidence, vector_note = _vector_boost(text, label, confidence)

    reason = LABEL_REASONS[label]
    if triggered:
        reason += f" Matched rules: {', '.join(t for t in triggered[:3] if not t.startswith('[learned]'))}."
    learned_hits = [t for t in triggered if t.startswith('[learned]')]
    if learned_hits:
        reason += f" Self-learned rules matched: {len(learned_hits)}."
    if vector_note:
        reason += vector_note

    return GuardExplanation(
        label=label,
        confidence=round(confidence, 4),
        reason=reason,
        triggered_patterns=triggered,
    )
