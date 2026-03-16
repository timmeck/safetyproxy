"""Authentication middleware for SafetyProxy."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.config import SAFETYPROXY_API_KEY


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        if not SAFETYPROXY_API_KEY:
            return await call_next(request)

        # Allow public endpoints
        if request.method == "GET" and request.url.path in ("/", "/api/status", "/api/events/stream"):
            return await call_next(request)

        key = request.headers.get("X-API-Key") or request.query_params.get("key")
        if key != SAFETYPROXY_API_KEY:
            if request.method in ("POST", "PUT", "DELETE"):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)

        return await call_next(request)
