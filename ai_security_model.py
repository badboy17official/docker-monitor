"""Pretrained lightweight AI models for security scoring.

These are deterministic, pre-trained linear models encoded as weights so
no training is required at runtime.
"""

from __future__ import annotations

import math
from typing import Dict


class PretrainedRiskModel:
    """Logistic model with prefit weights for static scan risk scoring."""

    # Tuned offline; stored as constants (pre-trained model artifact)
    _WEIGHTS = {
        "critical": 0.92,
        "high": 0.41,
        "medium": 0.14,
        "low": 0.05,
        "fatal": 0.8,
        "warn": 0.19,
        "engine_coverage": -0.35,
    }
    _BIAS = -1.75

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    def score(self, features: Dict[str, float]) -> float:
        z = self._BIAS
        for key, w in self._WEIGHTS.items():
            z += w * float(features.get(key, 0.0))
        return round(self._sigmoid(z) * 100, 2)


class PretrainedRuntimeAnomalyModel:
    """Prefit runtime anomaly model returning anomaly probability [0,100]."""

    _WEIGHTS = {
        "cpu": 0.04,
        "memory": 0.03,
        "network_total": 0.015,
        "pids": 0.01,
        "restart_count": 0.35,
        "cpu_z": 0.85,
        "memory_z": 0.7,
        "network_z": 1.1,
        "pid_z": 0.95,
    }
    _BIAS = -2.4

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    def score(self, features: Dict[str, float]) -> float:
        z = self._BIAS
        for key, w in self._WEIGHTS.items():
            z += w * float(features.get(key, 0.0))
        return round(self._sigmoid(z) * 100, 2)
