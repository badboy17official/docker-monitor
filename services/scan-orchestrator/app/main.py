"""
Scan Orchestrator — Main application
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
    logger.info("🚀 Scan Orchestrator starting...")
    yield
    logger.info("🛑 Scan Orchestrator shutting down...")


app = FastAPI(
    title="DevSecOps Scan Orchestrator",
    description="Scan workflow coordination",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/health", tags=["health"])
async def health():
    return {"status": "ok", "service": "scan-orchestrator"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
