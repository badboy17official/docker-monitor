"""SQLite persistence layer with connection pooling and lazy init."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_DB_PATH: Optional[Path] = None
_local = threading.local()
_initialized = False
_init_lock = threading.Lock()


def configure(db_path: str | Path):
    """Set the database path. Must be called before any DB operations."""
    global _DB_PATH
    _DB_PATH = Path(db_path).resolve()


def _get_path() -> Path:
    if _DB_PATH is None:
        return Path.home() / ".docker-monitor" / "monitor.db"
    return _DB_PATH


@contextmanager
def _get_conn():
    """Get a thread-local database connection with automatic cleanup."""
    path = _get_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(str(path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        _local.conn = conn

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    """Initialize database schema. Idempotent."""
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        with _get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS runtime_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    container_name TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    ai_score REAL NOT NULL,
                    cve_critical INTEGER NOT NULL,
                    data TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS protected_containers (
                    container_id TEXT PRIMARY KEY,
                    container_name TEXT NOT NULL,
                    protected_since TEXT NOT NULL
                )
            """)
        _initialized = True


def is_container_protected(container_id: str) -> bool:
    init_db()
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM protected_containers WHERE container_id = ?", (container_id,)
        ).fetchone()
        return row is not None


def get_protected_containers() -> List[str]:
    init_db()
    with _get_conn() as conn:
        rows = conn.execute("SELECT container_id FROM protected_containers").fetchall()
        return [r["container_id"] for r in rows]


def protect_container(container_id: str, container_name: str):
    init_db()
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO protected_containers "
            "(container_id, container_name, protected_since) "
            "VALUES (?, ?, ?)",
            (container_id, container_name, datetime.now().isoformat()),
        )


def unprotect_container(container_id: str):
    init_db()
    with _get_conn() as conn:
        conn.execute("DELETE FROM protected_containers WHERE container_id = ?", (container_id,))


def save_audit(data: Dict[str, Any]):
    init_db()
    timestamp = data.get("timestamp", datetime.now().isoformat())
    with _get_conn() as conn:
        conn.execute("INSERT INTO audits (timestamp, data) VALUES (?, ?)", (timestamp, json.dumps(data)))


def save_runtime_event(event: Dict[str, Any]):
    init_db()
    timestamp = event.get("timestamp", datetime.now().isoformat())
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO runtime_events "
            "(timestamp, container_name, risk_level, score, "
            "ai_score, cve_critical, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                timestamp,
                event.get("container", ""),
                event.get("risk_level", "low"),
                event.get("runtime_score", 0),
                event.get("ai_anomaly_score", 0.0),
                event.get("cve_critical", 0),
                json.dumps(event),
            ),
        )


def get_audit_history() -> List[Dict[str, Any]]:
    init_db()
    with _get_conn() as conn:
        rows = conn.execute("SELECT data FROM audits ORDER BY timestamp ASC").fetchall()
        return [json.loads(r["data"]) for r in rows]


def get_runtime_history() -> List[Dict[str, Any]]:
    init_db()
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT data FROM runtime_events ORDER BY timestamp DESC LIMIT 1000"
        ).fetchall()
        return [json.loads(r["data"]) for r in rows]


def get_runtime_events(
    container_name: Optional[str] = None,
    min_score: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    init_db()
    query = "SELECT * FROM runtime_events WHERE 1=1"
    params: list = []

    if container_name:
        query += " AND container_name LIKE ?"
        params.append(f"%{container_name}%")
    if min_score is not None:
        query += " AND score >= ?"
        params.append(min_score)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with _get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
