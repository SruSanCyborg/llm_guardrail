import os
from dotenv import load_dotenv

load_dotenv()

# Services
ORCHESTRATOR_PORT = int(os.getenv("ORCHESTRATOR_PORT", 8000))
INPUT_GUARDRAIL_URL = os.getenv("INPUT_GUARDRAIL_URL", "http://localhost:8001")
OUTPUT_GUARDRAIL_URL = os.getenv("OUTPUT_GUARDRAIL_URL", "http://localhost:8002")
CORE_LLM_URL = os.getenv("CORE_LLM_URL", "http://localhost:8003")

# Ollama
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

# Groq
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Security
LOG_DB_PATH = os.getenv("LOG_DB_PATH", "./security_logs/logs.db")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "cerebus-admin-secret")

# Multi-turn: how many previous prompts to include for context analysis
MULTI_TURN_WINDOW = int(os.getenv("MULTI_TURN_WINDOW", 5))

# Thresholds per security mode
SECURITY_THRESHOLDS = {
    "normal":   {"block": 0.85, "flag": 0.70},
    "strict":   {"block": 0.70, "flag": 0.55},
    "paranoid": {"block": 0.55, "flag": 0.40},
}
