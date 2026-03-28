$BASE = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PYTHONPATH = $BASE
$PYTHON = "$BASE\cerebus_env\Scripts\python.exe"

# Ensure self-learning dependency is installed
& $PYTHON -m pip install sentence-transformers --quiet 2>$null

Write-Host "==> Starting Input Guardrail (port 8001)..."
$p1 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\input_guardrail'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8001" -PassThru

Write-Host "==> Starting Output Guardrail (port 8002)..."
$p2 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\output_guardrail'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8002" -PassThru

Write-Host "==> Starting Core LLM / Ollama wrapper (port 8003)..."
$p3 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\core_llm'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8003" -PassThru

Write-Host "==> Starting RAG Service (port 8004)..."
$p5 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\rag'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8004" -PassThru

Write-Host "==> Starting Self-Learning Engine (port 8005)..."
$p7 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\self_learning'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8005" -PassThru

Start-Sleep -Seconds 3

Write-Host "==> Starting Orchestrator (port 8000)..."
$p4 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='$BASE'; cd '$BASE\orchestrator'; & '$PYTHON' -m uvicorn main:app --host 0.0.0.0 --port 8000" -PassThru

Start-Sleep -Seconds 2

Write-Host "==> Starting Frontend HTTP Server (port 3000)..."
$p6 = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$BASE'; & '$PYTHON' -m http.server 3000" -PassThru

Write-Host ""
Write-Host "============================================"
Write-Host "  All services started!"
Write-Host "  Orchestrator  -> http://localhost:8000"
Write-Host "  Chat App      -> http://localhost:3000/chat/"
Write-Host "  Dashboard     -> http://localhost:3000/dashboard/"
Write-Host ""
Write-Host "  For other devices on the same WiFi:"
Write-Host "  1. Run ipconfig and find your IPv4 address"
Write-Host "  2. Edit config.js - uncomment the LAN line"
Write-Host "     and set your IP there"
Write-Host "  3. Share http://YOUR_IP:3000/chat/ with others"
Write-Host "============================================"
