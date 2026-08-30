"""Tests for report generator."""

import json
import pytest
from docker_monitor.reports import ReportGenerator


@pytest.fixture
def sample_data():
    return {
        "timestamp": "2025-01-01T00:00:00",
        "vulnerable": {"critical": 10, "high": 20, "medium": 50, "low": 100, "fatal": 3, "warn": 5, "packages": 200, "engines_active": 4, "ai_risk_score": 85.5},
        "hardened": {"critical": 0, "high": 2, "medium": 10, "low": 30, "fatal": 0, "warn": 1, "packages": 150, "engines_active": 4, "ai_risk_score": 15.2},
        "comparison": {"ai_risk_drop": 70.3, "critical_drop": 10, "high_drop": 18, "engines_active": {"vulnerable": 4, "hardened": 4}},
    }


class TestReportGenerator:
    def test_json_report(self, tmp_path, sample_data):
        gen = ReportGenerator(str(tmp_path))
        path = gen.generate_json_report(sample_data)
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["vulnerable"]["critical"] == 10

    def test_html_report(self, tmp_path, sample_data):
        gen = ReportGenerator(str(tmp_path))
        path = gen.generate_html_report(sample_data)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Security Audit Report" in content
        assert "CRITICAL" in content

    def test_history_tracking(self, tmp_path, sample_data):
        gen = ReportGenerator(str(tmp_path))
        gen.update_history(sample_data)
        history_file = tmp_path / "audit_history.json"
        assert history_file.exists()
        with open(history_file, "r", encoding="utf-8") as f:
            history = json.load(f)
        assert len(history) == 1
