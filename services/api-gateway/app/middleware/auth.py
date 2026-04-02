"""
JWT Authentication Middleware
"""

import logging
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from uuid import UUID

from ..services.token_service import TokenService

logger = logging.getLogger(__name__)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware that validates JWT tokens and attaches user context to request.
    Bypasses certain paths (login, register, health).
    """

    BYPASS_PATHS = {"/auth/login", "/auth/register", "/health", "/docs", "/openapi.json"}

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public endpoints
        if request.url.path in self.BYPASS_PATHS or request.url.path.startswith("/auth/"):
            return await call_next(request)

        # Extract authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.warning("Missing or invalid Authorization header for %s", request.url.path)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header"
            )

        token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            payload = TokenService.verify_token(token)
            request.state.user_id = UUID(payload.get("sub"))
            request.state.token_type = payload.get("token_type")
        except Exception as exc:
            logger.warning("Token verification failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )

        response = await call_next(request)
        return response
