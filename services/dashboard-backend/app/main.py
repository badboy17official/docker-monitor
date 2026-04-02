"""
Dashboard Backend — Main application
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
    logger.info("🚀 Dashboard Backend starting...")
    yield
    logger.info("🛑 Dashboard Backend shutting down...")


app = FastAPI(
    title="DevSecOps Dashboard Backend",
    description="Analytics and aggregation",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "service": "dashboard-backend"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
