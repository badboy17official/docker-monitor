"""Tests for config loader."""

import pytest
from docker_monitor.config import Config


class TestConfig:
    def test_defaults(self, tmp_path):
        config_path = tmp_path / "empty.yaml"
        config_path.write_text("project:\n  name: test\n", encoding="utf-8")
        config = Config(str(config_path))
        assert config.scanning.get("parallel") is True
        assert config.runtime.get("poll_interval_seconds") == 20
        assert config.alerting.get("enabled") is False

    def test_override(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("""
alerting:
  enabled: true
  threshold: 50
runtime:
  poll_interval_seconds: 10
""", encoding="utf-8")
        config = Config(str(config_path))
        assert config.alerting.get("enabled") is True
        assert config.alerting.get("threshold") == 50
        assert config.runtime.get("poll_interval_seconds") == 10

    def test_missing_file(self):
        config = Config("/nonexistent/path/config.yaml")
        assert config.scanning.get("parallel") is True

    def test_section_access(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        config_path.write_text("images:\n  vulnerable:\n    name: test-img\n", encoding="utf-8")
        config = Config(str(config_path))
        assert config.images["vulnerable"]["name"] == "test-img"
