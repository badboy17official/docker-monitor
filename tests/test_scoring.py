"""Tests for scoring models."""

import math
from docker_monitor.scoring.risk import RuleBasedRiskScorer
from docker_monitor.scoring.anomaly import RuleBasedAnomalyScorer, ZScoreDetector, EWMADetector, EnsembleAnomalyDetector


class TestRuleBasedRiskScorer:
    def test_high_risk(self):
        scorer = RuleBasedRiskScorer()
        score = scorer.score({"critical": 20, "high": 50, "medium": 100, "low": 200, "fatal": 10, "warn": 20, "engine_coverage": 4})
        assert score > 70

    def test_clean_image(self):
        scorer = RuleBasedRiskScorer()
        score = scorer.score({"critical": 0, "high": 0, "medium": 0, "low": 0, "fatal": 0, "warn": 0, "engine_coverage": 4})
        assert score < 10

    def test_score_range(self):
        scorer = RuleBasedRiskScorer()
        score = scorer.score({"critical": 100, "high": 200, "medium": 500, "low": 1000, "fatal": 50, "warn": 100, "engine_coverage": 0})
        assert 0 <= score <= 100

    def test_differentiation(self):
        scorer = RuleBasedRiskScorer()
        low = scorer.score({"critical": 0, "high": 0, "medium": 0, "low": 0, "fatal": 0, "warn": 0, "engine_coverage": 4})
        high = scorer.score({"critical": 10, "high": 20, "medium": 50, "low": 100, "fatal": 5, "warn": 10, "engine_coverage": 1})
        assert high > low


class TestRuleBasedAnomalyScorer:
    def test_normal_metrics(self):
        scorer = RuleBasedAnomalyScorer()
        score = scorer.score({"cpu": 10, "memory": 20, "network_total": 5, "pids": 30, "restart_count": 0, "cpu_z": 0, "memory_z": 0, "network_z": 0, "pid_z": 0})
        assert score < 30

    def test_high_metrics(self):
        scorer = RuleBasedAnomalyScorer()
        score = scorer.score({"cpu": 95, "memory": 90, "network_total": 500, "pids": 300, "restart_count": 5, "cpu_z": 3, "memory_z": 3, "network_z": 4, "pid_z": 4})
        assert score > 70


class TestZScoreDetector:
    def test_insufficient_data(self):
        z = ZScoreDetector(window_size=12)
        result = z.detect("c1", 50, 50, 50, 50)
        assert result["cpu_z"] == 0.0

    def test_anomaly_detection(self):
        z = ZScoreDetector(window_size=12)
        import random
        rng = random.Random(42)
        for _ in range(10):
            z.detect("c1", rng.uniform(8, 12), 10, 10, 10)
        result = z.detect("c1", 90, 90, 90, 90)
        assert result["cpu_z"] > 2.0


class TestEWMADetector:
    def test_spike_detection(self):
        ewma = EWMADetector(alpha=0.3)
        for _ in range(5):
            ewma.detect("c1", 10, 10, 10)
        result = ewma.detect("c1", 90, 90, 90)
        assert result["cpu_ewma_spike"] > 0.5


class TestEnsembleAnomalyDetector:
    def test_normal(self):
        det = EnsembleAnomalyDetector(window_size=6)
        result = det.score("c1", cpu=10, mem=10, net=5, pids=20, restart_count=0, cve_critical=0, cve_high=0)
        assert result["score"] < 30
        assert result["risk_level"] == "low"

    def test_high_threat(self):
        det = EnsembleAnomalyDetector(window_size=6)
        result = det.score("c2", cpu=95, mem=90, net=400, pids=300, restart_count=5, cve_critical=3, cve_high=5)
        assert result["score"] > 50
        assert result["risk_level"] in ("high", "critical")
