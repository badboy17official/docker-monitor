import requests
import logging
from typing import Dict, Any

class AlertManager:
    def __init__(self, config: Dict[str, Any]):
        alert_config = config.get("alerting", {})
        self.enabled = alert_config.get("enabled", False)
        self.threshold = alert_config.get("threshold", 75)
        self.webhook_url = alert_config.get("webhook_url", "")
        
    def trigger_alert(self, score: float, message: str, context: Dict[str, Any] = None, threshold_override: float = None):
        if not self.enabled:
            return
            
        threshold_to_use = threshold_override if threshold_override is not None else self.threshold
        if score < threshold_to_use:
            return
            
        payload = {
            "text": f"🚨 HIGH RISK ALERT 🚨\n{message}\nScore: {score}",
            "context": context or {}
        }
        
        if self.webhook_url:
            try:
                requests.post(self.webhook_url, json=payload, timeout=5)
            except Exception as e:
                logging.error(f"Failed to send webhook alert: {e}")
                logging.warning(f"Fallback alert log: {payload['text']} | Context: {payload['context']}")
        else:
            logging.warning(f"ALERT (No webhook configured): {payload['text']} | Context: {payload['context']}")
