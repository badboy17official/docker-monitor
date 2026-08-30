"""Webhook-based alert manager."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from docker_monitor.config import Config

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None


class AlertManager:
    """Send alerts via webhook when scores exceed thresholds."""

    def __init__(self, config: Config):
        alert_cfg = config.alerting
        self.enabled = alert_cfg.get("enabled", False)
        self.threshold = alert_cfg.get("threshold", 75)
        self.webhook_url = alert_cfg.get("webhook_url", "")

    def trigger_alert(
        self,
        score: float,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        threshold_override: Optional[float] = None,
    ):
        if not self.enabled:
            return

        threshold = threshold_override if threshold_override is not None else self.threshold
        if score < threshold:
            return

        alert_text = f"HIGH RISK ALERT: {message}\nScore: {score}"

        ctx = context or {}
        if ctx.get("ai_explanation"):
            alert_text += f"\nAI: {ctx['ai_explanation']}"

        payload = {"text": alert_text, "context": ctx}

        if self.webhook_url:
            if requests is None:
                logger.warning("requests not installed, cannot send webhook alert")
                return
            try:
                requests.post(self.webhook_url, json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to send webhook alert: {e}")
                logger.warning(f"Fallback alert: {alert_text}")
        else:
            logger.warning(f"ALERT (no webhook): {alert_text}")
