"""Configuration loader with validation and defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_DEFAULTS: Dict[str, Any] = {
    "project": {
        "name": "docker-monitor",
        "version": "2.8.0",
    },
    "images": {
        "vulnerable": {"name": "flask-app-vulnerable", "dockerfile": "Dockerfile.vuln", "context": "."},
        "hardened": {"name": "flask-app-hardened", "dockerfile": "Dockerfile.hardened", "context": "."},
    },
    "scanning": {
        "parallel": True,
        "max_workers": 4,
        "trivy": {
            "enabled": True,
            "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "timeout": 300,
            "ignore_unfixed": False,
        },
        "dockle": {"enabled": True, "timeout": 120},
        "syft": {"enabled": True, "format": "json"},
        "grype": {"enabled": True, "format": "json"},
    },
    "thresholds": {
        "critical": 5,
        "high": 20,
        "medium": 50,
        "low": 100,
        "image_size_mb": 500,
        "fail_on_exceed": True,
    },
    "reporting": {
        "formats": ["json", "html"],
        "output_dir": "reports",
        "max_history": 30,
    },
    "alerting": {
        "enabled": False,
        "threshold": 75,
        "webhook_url": "",
    },
    "runtime": {
        "enabled": True,
        "poll_interval_seconds": 20,
        "ai_window_size": 12,
        "max_concurrent_scans": 3,
        "hosts": ["unix://var/run/docker.sock"],
    },
    "vulnerability": {
        "enabled": True,
        "scan_cache_ttl_seconds": 900,
    },
    "cloud": {
        "enabled": True,
        "source": "osv",
        "sync_interval_hours": 6,
        "max_concurrent_fetches": 5,
    },
    "ml": {
        "enabled": False,
        "model_url": "",
        "model_sha256": "",
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 8080,
        "rate_limit": "200 per day",
    },
}


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Merge override into base, recursively."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    """Central configuration with validation and env var overrides."""

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path) if path else Path("config.yaml")
        self._data: Dict[str, Any] = _DEFAULTS.copy()
        self._load()
        self._apply_env_overrides()

    def _load(self):
        if self._path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                user_cfg = yaml.safe_load(f) or {}
            self._data = _deep_merge(self._data, user_cfg)

    def _apply_env_overrides(self):
        """Apply DM_* environment variables as config overrides."""
        prefix = "DM_"
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
            parts = key[len(prefix):].lower().split("__")
            if len(parts) == 2:
                section, field = parts
                if section in self._data and isinstance(self._data[section], dict):
                    coerced = self._coerce(value)
                    self._data[section][field] = coerced

    @staticmethod
    def _coerce(value: str) -> Any:
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def section(self, key: str) -> Dict[str, Any]:
        return self._data.get(key, {})

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    @property
    def images(self) -> Dict[str, Any]:
        return self._data.get("images", {})

    @property
    def scanning(self) -> Dict[str, Any]:
        return self._data.get("scanning", {})

    @property
    def thresholds(self) -> Dict[str, Any]:
        return self._data.get("thresholds", {})

    @property
    def reporting(self) -> Dict[str, Any]:
        return self._data.get("reporting", {})

    @property
    def alerting(self) -> Dict[str, Any]:
        return self._data.get("alerting", {})

    @property
    def runtime(self) -> Dict[str, Any]:
        return self._data.get("runtime", {})

    @property
    def vulnerability(self) -> Dict[str, Any]:
        return self._data.get("vulnerability", {})

    @property
    def cloud(self) -> Dict[str, Any]:
        return self._data.get("cloud", {})

    @property
    def ml(self) -> Dict[str, Any]:
        return self._data.get("ml", {})

    @property
    def dashboard(self) -> Dict[str, Any]:
        return self._data.get("dashboard", {})
