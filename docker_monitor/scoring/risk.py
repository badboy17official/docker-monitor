"""Rule-based risk scorer for static scan results."""

from __future__ import annotations

import math
from typing import Dict


class RuleBasedRiskScorer:
    """Deterministic weighted rule scorer for static scan risk scoring.

    Uses sigmoid normalization to produce a score in [0, 100].
    Weights are empirically tuned heuristics, not trained ML.
    """

    _WEIGHTS = {
        "critical": 0.08,
        "high": 0.03,
        "medium": 0.01,
        "low": 0.002,
        "fatal": 0.08,
        "warn": 0.02,
        "engine_coverage": -0.5,
    }
    _BIAS = -2.0

    @staticmethod
    def _sigmoid(x: float) -> float:
        return 1 / (1 + math.exp(-x))

    def score(self, features: Dict[str, float]) -> float:
        z = self._BIAS
        for key, w in self._WEIGHTS.items():
            z += w * float(features.get(key, 0.0))
        return round(self._sigmoid(z) * 100, 2)
