"""Tests for database operations."""

import json
import pytest
from docker_monitor import db


@pytest.fixture(autouse=True)
def setup_db(tmp_path, monkeypatch):
    """Use a temporary database for each test."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(db, "_DB_PATH", db_path)
    monkeypatch.setattr(db, "_initialized", False)
    # Clear thread-local connections
    if hasattr(db._local, "conn"):
        del db._local.conn
    yield
    if hasattr(db._local, "conn"):
        try:
            db._local.conn.close()
        except Exception:
            pass
        del db._local.conn


class TestDB:
    def test_init_db(self):
        db.init_db()
        assert db._initialized

    def test_protect_unprotect(self):
        db.protect_container("abc123", "test-container")
        assert db.is_container_protected("abc123")
        assert "abc123" in db.get_protected_containers()
        db.unprotect_container("abc123")
        assert not db.is_container_protected("abc123")

    def test_save_and_get_audit(self):
        data = {"timestamp": "2025-01-01T00:00:00", "vulnerable": {"critical": 5}, "hardened": {"critical": 0}}
        db.save_audit(data)
        history = db.get_audit_history()
        assert len(history) == 1
        assert history[0]["vulnerable"]["critical"] == 5

    def test_save_and_get_runtime_event(self):
        event = {"timestamp": "2025-01-01T00:00:00", "container": "web", "risk_level": "high", "runtime_score": 80, "ai_anomaly_score": 75.5, "cve_critical": 2}
        db.save_runtime_event(event)
        events = db.get_runtime_events()
        assert len(events) == 1
        assert events[0]["container_name"] == "web"

    def test_runtime_events_filter(self):
        db.save_runtime_event({"container": "web", "risk_level": "high", "runtime_score": 80, "ai_anomaly_score": 75, "cve_critical": 2})
        db.save_runtime_event({"container": "db", "risk_level": "low", "runtime_score": 10, "ai_anomaly_score": 5, "cve_critical": 0})
        events = db.get_runtime_events(container_name="web")
        assert len(events) == 1
        events = db.get_runtime_events(min_score=50)
        assert len(events) == 1
