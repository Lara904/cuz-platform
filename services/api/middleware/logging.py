"""
services/api/middleware/logging.py
Middleware de logging structuré pour toutes les requêtes HTTP.
Chaque requête produit une ligne JSON avec : méthode, path, status, durée, IP.
"""
import time
import uuid
import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("cuz.api")
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]
        start = time.perf_counter()

        # Injecter le request_id dans le state pour les handlers
        request.state.request_id = request_id

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        client_ip = request.client.host if request.client else "unknown"

        logger.info(
            '"request_id":"%s","method":"%s","path":"%s","status":%d,"duration_ms":%s,"ip":"%s"',
            request_id,
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            client_ip,
        )

        response.headers["X-Request-ID"] = request_id
        return response