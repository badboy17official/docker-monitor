"""
Anomaly Detector — Z-score based sliding window detection
"""

import logging
from collections import defaultdict, deque
from statistics import mean, stdev
from typing import Optional

logger = logging.getLogger(__name__)

WINDOW_SIZE = 20        # Number of samples to track
Z_THRESHOLD = 3.0       # Standard deviations before flagging
MIN_SAMPLES = 5         # Don't alert until we have baseline


class AnomalyDetector:
    """
    Detects anomalies in container metrics using z-score method.
    Maintains rolling window per container/metric.
    """

    def __init__(self):
        # Structure: { container_id: { metric_name: deque[float] } }
        self._windows: dict[str, dict[str, deque]] = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
        )

    def ingest(self, metric: dict) -> list[dict]:
        """
        Ingest a metric snapshot.
        Returns list of anomaly alerts (may be empty).
        """
        container_id = metric.get("container_id")
        alerts = []

        for field in ("cpu_pct", "mem_pct"):
            value = metric.get(field, 0.0)
            window = self._windows[container_id][field]
            window.append(value)

            if len(window) < MIN_SAMPLES:
                continue

            alert = self._check_zscore(container_id, field, value, list(window))
            if alert:
                alerts.append(alert)

        return alerts

    @staticmethod
    def _check_zscore(
        container_id: str,
        metric_name: str,
        current: float,
        window: list[float]
    ) -> Optional[dict]:
        """
        Check if current value is a statistical outlier.
        Exclude current sample from baseline (only use history).
        """
        history = window[:-1]  # Exclude current sample

        if len(history) < MIN_SAMPLES:
            return None

        try:
            mu = mean(history)
            sigma = stdev(history)
        except Exception:
            return None

        if sigma == 0:
            return None

        z = (current - mu) / sigma

        if abs(z) < Z_THRESHOLD:
            return None

        # Anomaly detected
        severity = "CRITICAL" if abs(z) > 5 else "HIGH"

        return {
            "container_id": container_id,
            "alert_type": f"{metric_name}_spike",
            "severity": severity,
            "message": (
                f"{metric_name} spike detected: {current:.1f}% "
                f"(baseline={mu:.1f}%, z={z:.2f}σ)"
            ),
            "z_score": round(z, 3),
            "current_val": round(current, 2),
            "baseline_mean": round(mu, 2),
            "metric": metric_name,
        }
