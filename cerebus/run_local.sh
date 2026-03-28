#!/bin/bash
# Run all Cerebus services locally WITHOUT Docker (for dev/hackathon)
# Requirements: Python venv activated, Redis running, Ollama running

set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$BASE"

echo "==> Starting Input Guardrail (port 8001)..."
cd "$BASE/input_guardrail"
uvicorn main:app --host 0.0.0.0 --port 8001 --reload &
PIDS+=($!)

echo "==> Starting Output Guardrail (port 8002)..."
cd "$BASE/output_guardrail"
uvicorn main:app --host 0.0.0.0 --port 8002 --reload &
PIDS+=($!)

echo "==> Starting Core LLM / Ollama wrapper (port 8003)..."
cd "$BASE/core_llm"
uvicorn main:app --host 0.0.0.0 --port 8003 --reload &
PIDS+=($!)

sleep 2

echo "==> Starting Orchestrator (port 8000)..."
cd "$BASE/orchestrator"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
PIDS+=($!)

echo ""
echo "✓ All services running."
echo "  Orchestrator → http://localhost:8000"
echo "  API Docs     → http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all."

trap "kill ${PIDS[*]}" SIGINT SIGTERM
wait
