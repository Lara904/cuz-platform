# services/api/requirements.txt
# Dépendances Python pour l'API CUz (P0.8)

# Web framework
fastapi==0.115.0
uvicorn[standard]==0.30.6

# Auth JWT
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.12  # requis pour OAuth2PasswordRequestForm

# PostgreSQL async
asyncpg==0.29.0

# Redis async (rate limiting)
redis[asyncio]==5.0.8

# Validation
pydantic==2.9.2
pydantic-core==2.23.4
pydantic-settings==2.5.2

# HTTP client (pour tests d'intégration)
httpx==0.27.2