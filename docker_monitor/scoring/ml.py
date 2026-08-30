"""Optional ML anomaly detector using IsolationForest.

Requires scikit-learn, joblib, numpy. If not installed, ML scoring is disabled.
Model is downloaded on first use with SHA256 verification.
"""

from __future__ import annotations

import hashlib
import logging
import math
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest

    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    joblib = None
    np = None
    IsolationForest = None


class MLAnomalyDetector:
    """IsolationForest-based anomaly detector with lazy model loading."""

    def __init__(self, model_path: Optional[str] = None, model_url: str = "", model_sha256: str = ""):
        self.model = None
        self._model_path = Path(model_path) if model_path else Path("ml_anomaly_model.joblib")
        self._model_url = model_url
        self._model_sha256 = model_sha256

        if _ML_AVAILABLE and self._model_path.exists():
            self._load_model()

    def _load_model(self):
        try:
            if self._model_sha256:
                file_hash = hashlib.sha256(self._model_path.read_bytes()).hexdigest()
                if file_hash != self._model_sha256:
                    logger.warning("ML model SHA256 mismatch, skipping load")
                    return
            self.model = joblib.load(self._model_path)
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")

    def _download_model(self) -> bool:
        if not self._model_url:
            return False
        try:
            import requests

            logger.info(f"Downloading ML model from {self._model_url}")
            resp = requests.get(self._model_url, timeout=60)
            resp.raise_for_status()
            self._model_path.write_bytes(resp.content)

            if self._model_sha256:
                file_hash = hashlib.sha256(resp.content).hexdigest()
                if file_hash != self._model_sha256:
                    logger.error("Downloaded model SHA256 mismatch, removing")
                    self._model_path.unlink()
                    return False

            self._load_model()
            return self.model is not None
        except Exception as e:
            logger.error(f"Failed to download ML model: {e}")
            return False

    @property
    def available(self) -> bool:
        return _ML_AVAILABLE and self.model is not None

    def score(self, features: Dict[str, float]) -> float:
        if not self.available:
            if self._model_url and not self._model_path.exists():
                self._download_model()
            if not self.available:
                return 0.0

        x = np.array([[
            float(features.get("cpu", 0.0)),
            float(features.get("memory", 0.0)),
            float(features.get("network_total", 0.0)),
            float(features.get("pids", 0.0)),
            float(features.get("restart_count", 0.0)),
            float(features.get("cpu_z", 0.0)),
            float(features.get("memory_z", 0.0)),
            float(features.get("network_z", 0.0)),
            float(features.get("pid_z", 0.0)),
        ]])

        score_val = self.model.decision_function(x)[0]
        anomaly_score = -score_val
        prob = 1 / (1 + math.exp(-(anomaly_score * 10)))
        return round(prob * 100, 2)

    @classmethod
    def train_and_save(cls, model_path: str = "ml_anomaly_model.joblib") -> bool:
        if not _ML_AVAILABLE:
            return False

        rng = np.random.RandomState(42)
        n_samples = 1000
        cpu = rng.uniform(0, 20, n_samples)
        mem = rng.uniform(0, 30, n_samples)
        net = rng.uniform(0, 50, n_samples)
        pids = rng.uniform(10, 50, n_samples)
        restart = np.zeros(n_samples)
        cpu_z = rng.normal(0, 0.5, n_samples)
        mem_z = rng.normal(0, 0.5, n_samples)
        net_z = rng.normal(0, 0.5, n_samples)
        pid_z = rng.normal(0, 0.5, n_samples)

        X = np.column_stack((cpu, mem, net, pids, restart, cpu_z, mem_z, net_z, pid_z))
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        joblib.dump(model, model_path)
        return True
