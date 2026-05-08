# ── Stage 1: build Vue frontend ────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci --prefer-offline
COPY frontend/ ./
RUN npm run build        # outputs to ../app/static/dist via vite.config.js

# ── Stage 2: Python app ─────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libpq-dev openssl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
    -subj "/C=RU/ST=Moscow/L=Moscow/O=NGFW Manager/CN=localhost"

ENV PYTHONPATH=/app

COPY . .


# Copy built SPA from stage 1
COPY --from=frontend-builder /app/static/dist ./app/static/dist

CMD ["python", "app/main.py"]
