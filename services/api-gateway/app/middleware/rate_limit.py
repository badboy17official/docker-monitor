"""
Rate Limiting Middleware using Redis sliding window
"""

import logging
import time
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
import aioredis

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Implements sliding window rate limiting using Redis.
    Limits: 100 requests per minute per user (or per IP for anonymous).
    """

    REQUESTS_PER_MINUTE = 100
    WINDOW_SECONDS = 60

    def __init__(self, app, redis_url: str):
        super().__init__(app)
        self.redis_url = redis_url
        self.redis: aioredis.Redis = None

    async def init_redis(self):
        if self.redis is None:
            self.redis = await aioredis.from_url(self.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next):
        await self.init_redis()

        # Determine identifier: user_id if authenticated, otherwise IP
        identifier = str(getattr(request.state, "user_id", request.client.host))
        key = f"rate_limit:{identifier}"

        current_time = int(time.time())
        window_start = current_time - self.WINDOW_SECONDS

        try:
            # Remove old requests outside the window
            await self.redis.zremrangebyscore(key, 0, window_start)

            # Count requests in current window
            count = await self.redis.zcard(key)

            if count >= self.REQUESTS_PER_MINUTE:
                logger.warning("Rate limit exceeded for %s", identifier)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Max 100 requests per minute."
                )

            # Add current request
            await self.redis.zadd(key, {str(current_time): current_time})
            await self.redis.expire(key, self.WINDOW_SECONDS)

        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise
            logger.error("Rate limiting error: %s", exc)
            # Fail open if Redis is down (don't block requests)

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.REQUESTS_PER_MINUTE)
        response.headers["X-RateLimit-Used"] = str(count)
        return response
