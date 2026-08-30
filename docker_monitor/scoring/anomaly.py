"""Runtime anomaly detection: rule-based, z-score, EWMA, and ensemble."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List


class RuleBasedAnomalyScorer:
    """Deterministic weighted rule scorer for runtime anomaly detection.

    Returns anomaly probability in [0, 100].
    """

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


class ZScoreDetector:
    """Statistical z-score anomaly detector."""

    def __init__(self, window_size: int = 12):
        self.window_size = window_size
        self.history: Dict[str, Dict[str, Deque[float]]] = defaultdict(
            lambda: {
                "cpu": deque(maxlen=window_size),
                "memory": deque(maxlen=window_size),
                "network": deque(maxlen=window_size),
                "pids": deque(maxlen=window_size),
            }
        )

    @staticmethod
    def _zscore(value: float, samples: Deque[float]) -> float:
        if len(samples) < 6:
            return 0.0
        mean = statistics.mean(samples)
        std = statistics.pstdev(samples)
        if std == 0:
            return 0.0
        return (value - mean) / std

    def detect(self, container_id: str, cpu: float, mem: float, net: float, pids: float) -> Dict[str, float]:
        h = self.history[container_id]
        cpu_z = self._zscore(cpu, h["cpu"])
        mem_z = self._zscore(mem, h["memory"])
        net_z = self._zscore(net, h["network"])
        pid_z = self._zscore(pids, h["pids"])

        for key, value in (("cpu", cpu), ("memory", mem), ("network", net), ("pids", pids)):
            h[key].append(value)

        return {"cpu_z": cpu_z, "memory_z": mem_z, "network_z": net_z, "pid_z": pid_z}


class EWMADetector:
    """Exponentially Weighted Moving Average spike detector."""

    def __init__(self, alpha: float = 0.3):
        self.alpha = alpha
        self.ewma: Dict[str, Dict[str, float]] = defaultdict(dict)

    def detect(self, container_id: str, cpu: float, mem: float, net: float) -> Dict[str, float]:
        spikes = {}
        for key, value in (("cpu", cpu), ("memory", mem), ("network", net)):
            prev = self.ewma[container_id].get(key, value)
            smooth = self.alpha * value + (1 - self.alpha) * prev
            self.ewma[container_id][key] = smooth
            spikes[f"{key}_ewma_spike"] = 0.0 if smooth == 0 else (value - smooth) / max(smooth, 1e-6)
        return spikes


class EnsembleAnomalyDetector:
    """Combines rule-based, z-score, and EWMA detectors."""

    def __init__(self, window_size: int = 12):
        self.rule_model = RuleBasedAnomalyScorer()
        self.zscore = ZScoreDetector(window_size=window_size)
        self.ewma = EWMADetector()

    @staticmethod
    def _risk_bucket(score: int) -> str:
        if score >= 78:
            return "critical"
        if score >= 55:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    def score(
        self,
        container_id: str,
        cpu: float,
        mem: float,
        net: float,
        pids: float,
        restart_count: float,
        cve_critical: int,
        cve_high: int,
        ml_score: float = 0.0,
    ) -> Dict[str, Any]:
        reasons: List[str] = []
        detectors: List[str] = []
        score = 0

        zscores = self.zscore.detect(container_id, cpu, mem, net, pids)
        cpu_z = zscores["cpu_z"]
        mem_z = zscores["memory_z"]
        net_z = zscores["network_z"]
        pid_z = zscores["pid_z"]

        ewma_spikes = self.ewma.detect(container_id, cpu, mem, net)

        if cpu > 90:
            score += 20
            reasons.append("CPU > 90%")
            detectors.append("rule")
        if mem > 85:
            score += 18
            reasons.append("Memory > 85%")
            detectors.append("rule")
        if pids > 250:
            score += 15
            reasons.append("PIDs > 250")
            detectors.append("rule")
        if net > 300:
            score += 15
            reasons.append("Network throughput spike (>300MB)")
            detectors.append("rule")

        if cpu_z > 2.5:
            score += 12
            reasons.append(f"CPU z-score anomaly ({cpu_z:.2f})")
            detectors.append("zscore")
        if mem_z > 2.5:
            score += 10
            reasons.append(f"Memory z-score anomaly ({mem_z:.2f})")
            detectors.append("zscore")
        if net_z > 3.0:
            score += 12
            reasons.append(f"Network z-score anomaly ({net_z:.2f})")
            detectors.append("zscore")
        if pid_z > 3.0:
            score += 12
            reasons.append(f"PID z-score anomaly ({pid_z:.2f})")
            detectors.append("zscore")

        cpu_spike = ewma_spikes.get("cpu_ewma_spike", 0)
        mem_spike = ewma_spikes.get("memory_ewma_spike", 0)
        net_spike = ewma_spikes.get("network_ewma_spike", 0)
        if cpu_spike > 0.8 or mem_spike > 0.8 or net_spike > 1.2:
            score += 10
            reasons.append("EWMA sudden-behavior shift detected")
            detectors.append("ewma")

        features = {
            "cpu": cpu, "memory": mem, "network_total": net, "pids": pids,
            "restart_count": restart_count,
            "cpu_z": cpu_z, "memory_z": mem_z, "network_z": net_z, "pid_z": pid_z,
        }
        rule_score = self.rule_model.score(features)
        ai_score = (rule_score + ml_score) / 2 if ml_score > 0 else rule_score

        if ai_score > 75:
            score += 22
            reasons.append(f"AI model high anomaly probability ({ai_score:.1f})")
            detectors.append("ai_model")
        elif ai_score > 55:
            score += 10
            reasons.append(f"AI model moderate anomaly probability ({ai_score:.1f})")
            detectors.append("ai_model")

        if cve_critical > 0:
            score += min(25, cve_critical * 5)
            reasons.append(f"Critical CVEs present: {cve_critical}")
            detectors.append("vuln_cve")
        if cve_high > 0:
            score += min(15, cve_high * 2)
            reasons.append(f"High CVEs present: {cve_high}")
            detectors.append("vuln_cve")
        if restart_count >= 3:
            score += 8
            reasons.append("Restart churn (>=3)")
            detectors.append("rule")

        score = min(int(round(score)), 100)
        if not reasons:
            reasons = ["No significant anomalies detected"]

        ai_explanation = ""
        if score >= 75:
            exp_parts = []
            if cpu_z > 2.0:
                exp_parts.append(f"abnormal CPU usage {cpu_z:.1f} standard deviations above baseline")
            elif cpu > 80:
                exp_parts.append(f"high CPU usage of {cpu:.1f}%")
            if net_z > 2.0:
                exp_parts.append(f"elevated network activity {net_z:.1f} standard deviations above baseline")
            elif net > 100:
                exp_parts.append(f"elevated network activity ({net:.1f} MB)")
            if mem_z > 2.0:
                exp_parts.append(f"abnormal memory usage {mem_z:.1f} standard deviations above baseline")
            if pid_z > 2.0:
                exp_parts.append(f"abnormal process count {pid_z:.1f} standard deviations above baseline")
            if cve_critical > 0:
                exp_parts.append(f"the presence of {cve_critical} critical CVEs")

            if exp_parts:
                ai_explanation = "The combination of " + " and ".join(exp_parts[:2])
                if len(exp_parts) > 2:
                    ai_explanation += " along with other anomalies"
                ai_explanation += " suggests potential resource abuse, exploitation, or anomalous behavior."
            else:
                ai_explanation = "Multiple heuristics triggered indicating anomalous behavior."

        return {
            "score": score,
            "risk_level": self._risk_bucket(score),
            "reasons": reasons,
            "detectors_triggered": sorted(set(detectors)),
            "ai_anomaly_score": ai_score,
            "ai_explanation": ai_explanation,
        }
