"""Rule-based scoring models for security and anomaly detection.

These are deterministic weighted rule scorers. Not a trained ML model.
Weights are empirically tuned heuristics.
"""

from __future__ import annotations

import math
from typing import Dict


class RuleBasedRiskScorer:
    """Deterministic weighted rule scorer for static scan risk scoring. Not a trained ML model. Weights are empirically tuned heuristics."""

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


class RuleBasedAnomalyScorer:
    """Deterministic weighted rule scorer for runtime anomaly detection returning anomaly probability [0,100]. Not a trained ML model. Weights are empirically tuned heuristics."""

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
