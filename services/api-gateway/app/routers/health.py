"""
API Gateway — Reverse proxy to other services
Routes requests to auth, scan orchestrator, reports, etc.
"""

import logging
import os
from fastapi import APIRouter, Depends
from uuid import UUID
import httpx

from ..dependencies import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["gateway"])

# Service URLs (from environment)
AUTH_SERVICE_URL = os.environ.get("AUTH_SERVICE_URL", "http://auth-service:8001")
SCAN_ORCHESTRATOR_URL = os.environ.get("SCAN_ORCHESTRATOR_URL", "http://scan-orchestrator:8002")
AI_ENGINE_URL = os.environ.get("AI_ENGINE_URL", "http://ai-engine:8003")
REPORT_SERVICE_URL = os.environ.get("REPORT_SERVICE_URL", "http://report-service:8004")
DASHBOARD_BACKEND_URL = os.environ.get("DASHBOARD_BACKEND_URL", "http://dashboard-backend:8005")


@router.get("/health", tags=["health"])
async def gateway_health():
    """
    API Gateway health check.
    Returns status of all downstream services.
    """
    services = {}

    async with httpx.AsyncClient(timeout=5) as client:
        for name, url in [
            ("auth-service", AUTH_SERVICE_URL),
            ("scan-orchestrator", SCAN_ORCHESTRATOR_URL),
            ("ai-engine", AI_ENGINE_URL),
            ("report-service", REPORT_SERVICE_URL),
            ("dashboard-backend", DASHBOARD_BACKEND_URL),
        ]:
            try:
                resp = await client.get(f"{url}/health")
                services[name] = "ok" if resp.status_code == 200 else "error"
            except Exception as exc:
                logger.warning("Failed to check %s: %s", name, exc)
                services[name] = "error"

    return {
        "status": "ok" if all(v == "ok" for v in services.values()) else "degraded",
        "services": services
    }


# Placeholder for actual proxy implementation
# In production, you might use httpx.AsyncClient or a dedicated reverse proxy
