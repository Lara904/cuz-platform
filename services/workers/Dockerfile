# services/workers/Dockerfile
# Image unique des jobs CUz (réconciliation, freshness-decay, stale-detection).
# Build : docker build -t cuz-worker:0.1.0 -f services/workers/Dockerfile .  (depuis la racine)
FROM python:3.12-slim

WORKDIR /app

COPY services/workers/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code des packages uniquement (pas de services/api)
COPY packages ./packages
COPY config ./config

ENV PYTHONDONTWRITEBYTECODE=1
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin cuz
USER 10001

ENTRYPOINT ["python", "-m"]
CMD ["packages.ingestion.reconcile", "--help"]
