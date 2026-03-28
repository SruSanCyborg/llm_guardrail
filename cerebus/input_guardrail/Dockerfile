FROM python:3.11-slim
WORKDIR /app
COPY ../requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn transformers torch peft redis pydantic python-dotenv
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
