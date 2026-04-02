"""
Auth Service — Main FastAPI application
"""

import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .db import init_db, close_db
from .routes import auth, users

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management: startup and shutdown"""
    logger.info("🚀 Auth Service starting...")
    await init_db()
    logger.info("✅ Database initialized")
    yield
    logger.info("🛑 Auth Service shutting down...")
    await close_db()
    logger.info("✅ Database closed")


# Create FastAPI app
app = FastAPI(
    title="DevSecOps Auth Service",
    description="User authentication and JWT token management",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware for cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint.
    """
    return {
        "status": "ok",
        "service": "auth-service",
        "version": "1.0.0"
    }


@app.get("/", tags=["root"])
async def root():
    """
    Auth Service API documentation available at /docs
    """
    return {
        "message": "Auth Service",
        "docs": "/docs",
        "openapi": "/openapi.json"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
