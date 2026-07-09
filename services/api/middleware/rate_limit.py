"""
services/api/middleware/rate_limit.py
Rate limiting par IP via Redis (sliding window).
Limite par défaut : 100 requêtes / minute par IP.
Les health checks sont exemptés.
"""
import os
import time
import logging
from typing import Callable

import redis.asyncio as aioredis
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("cuz.rate_limit")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

# Paths exemptés du rate limiting
EXEMPT_PATHS = {"/health", "/", "/docs", "/redoc", "/openapi.json"}

_redis_client: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
    return _redis_client


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Exempter certains paths
        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = int(time.time())
        window_start = now - RATE_LIMIT_WINDOW_SECONDS
        key = f"rate_limit:{client_ip}"

        try:
            redis = await get_redis()
            # Sliding window : supprimer les entrées hors fenêtre, ajouter la courante
            pipe = redis.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, RATE_LIMIT_WINDOW_SECONDS * 2)
            results = await pipe.execute()
            request_count = results[2]

            if request_count > RATE_LIMIT_REQUESTS:
                logger.warning("Rate limit dépassé pour IP %s (%d req)", client_ip, request_count)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Trop de requêtes. Réessayez dans 60 secondes."},
                    headers={
                        "X-RateLimit-Limit": str(RATE_LIMIT_REQUESTS),
                        "X-RateLimit-Remaining": "0",
                        "Retry-After": str(RATE_LIMIT_WINDOW_SECONDS),
                    },
                )

            response = await call_next(request)
            remaining = max(0, RATE_LIMIT_REQUESTS - request_count)
            response.headers["X-RateLimit-Limit"] = str(RATE_LIMIT_REQUESTS)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            return response

        except Exception as e:
            # Si Redis est indisponible, on laisse passer (fail-open)
            logger.error("Rate limiter Redis indisponible : %s", e)
            return await call_next(request)