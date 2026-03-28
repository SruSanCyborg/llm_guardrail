from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class ThreatLabel(str, Enum):
    SAFE = "SAFE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    SENSITIVE_EXTRACTION = "SENSITIVE_EXTRACTION"
    HARMFUL_CONTENT = "HARMFUL_CONTENT"


class GuardExplanation(BaseModel):
    label: ThreatLabel
    confidence: float
    reason: str                    # XAI: human-readable reason
    triggered_patterns: List[str]  # XAI: what patterns fired


class ChatRequest(BaseModel):
    prompt: str
    session_id: str
    security_mode: str = "normal"   # "normal" | "strict" | "paranoid"
    provider: str = "ollama"        # "ollama" | "groq"
    model: Optional[str] = None     # override model name
    groq_api_key: Optional[str] = None  # user-supplied Groq key (takes priority over .env)


class ChatResponse(BaseModel):
    response: Optional[str]
    blocked: bool
    explanation: Optional[GuardExplanation] = None  # XAI output


class InputGuardRequest(BaseModel):
    prompt: str
    session_id: str
    security_mode: str = "normal"
    conversation_history: List[str] = []  # Multi-turn: last N prompts


class InputGuardResponse(BaseModel):
    safe: bool
    explanation: GuardExplanation


class OutputGuardRequest(BaseModel):
    response: str
    original_prompt: str
    rag_context: Optional[str] = None


class OutputGuardResponse(BaseModel):
    valid: bool
    issues: List[str]
    explanation: str
