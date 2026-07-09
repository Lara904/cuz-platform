# services/api/Dockerfile
# Image de production pour l'API CUz (FastAPI)
# Build : docker build -t cuz-api:latest -f services/api/Dockerfile .
# (à lancer depuis la RACINE du repo, pas depuis services/api/)

FROM python:3.12-slim

# Dépendances système minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copier uniquement les requirements pour exploiter le cache Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source complet
COPY . .

# Port exposé
EXPOSE 8000

# Health check Docker
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD curl -f http://localhost:8000/health || exit 1

# Démarrage
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]