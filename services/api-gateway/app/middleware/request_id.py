"""
Request ID Middleware for distributed tracing
"""

import logging
import uuid
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects X-Request-ID header into all requests for tracing across services.
    """

    async def dispatch(self, request: Request, call_next):
        # Use existing X-Request-ID or generate new one
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        # Add to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        # Log with request_id for distributed tracing
        logger.info(
            "[%s] %s %s",
            request_id,
            request.method,
            request.url.path
        )

        return response
