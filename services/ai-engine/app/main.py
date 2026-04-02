"""
AI Engine — Main FastAPI application
"""

import logging
from fastapi import FastAPI
from contextlib import asynccontextmanager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management"""
    logger.info("🚀 AI Engine starting...")
    yield
    logger.info("🛑 AI Engine shutting down...")


app = FastAPI(
    title="DevSecOps AI Engine",
    description="Risk scoring and CVE enrichment",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "service": "ai-engine"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
