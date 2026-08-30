"""Test fixtures."""

import os
import pytest


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    """Set environment variables for testing."""
    monkeypatch.setenv("DASHBOARD_AUTH_USER", "testuser")
    monkeypatch.setenv("DASHBOARD_AUTH_PASSWORD", "testpass123")
    monkeypatch.setenv("DASHBOARD_ALLOW_INSECURE", "false")


@pytest.fixture
def tmp_config(tmp_path):
    """Create a minimal config file for testing."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("""
project:
  name: test
  version: "2.8.0"
images:
  vulnerable:
    name: test-vuln
    dockerfile: Dockerfile.vuln
    context: .
  hardened:
    name: test-hard
    dockerfile: Dockerfile.hardened
    context: .
scanning:
  parallel: false
  max_workers: 2
  trivy:
    enabled: true
    timeout: 30
  dockle:
    enabled: true
    timeout: 30
  syft:
    enabled: true
  grype:
    enabled: true
alerting:
  enabled: false
  threshold: 75
runtime:
  enabled: false
  poll_interval_seconds: 5
  ai_window_size: 6
  hosts: []
cloud:
  enabled: false
ml:
  enabled: false
reporting:
  output_dir: reports
  max_history: 10
vulnerability:
  enabled: false
dashboard:
  host: "127.0.0.1"
  port: 8080
""", encoding="utf-8")
    return config_path
