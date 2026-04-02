"""
API Gateway main application
"""

import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .middleware.auth import JWTAuthMiddleware
from .middleware.rate_limit import RateLimitMiddleware
from .middleware.request_id import RequestIDMiddleware
from .routers import health

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management"""
    logger.info("🚀 API Gateway starting...")
    yield
    logger.info("🛑 API Gateway shutting down...")


# Create FastAPI app
app = FastAPI(
    title="DevSecOps API Gateway",
    description="Central request router with auth validation and rate limiting",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request ID middleware (logs all requests with tracing)
app.add_middleware(RequestIDMiddleware)

# Rate limiting middleware
redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
app.add_middleware(RateLimitMiddleware, redis_url=redis_url)

# JWT auth middleware (validates tokens)
app.add_middleware(JWTAuthMiddleware)

# Include routers
app.include_router(health.router)


@router.get("/", tags=["root"])
async def root():
    """
    DevSecOps API Gateway
    """
    return {
        "message": "DevSecOps API Gateway",
        "version": "1.0.0",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


from fastapi import APIRouter
router = APIRouter()
app.include_router(router)
