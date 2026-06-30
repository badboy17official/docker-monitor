import sqlite3
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

DB_PATH = Path("docker_monitor.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            data JSON NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS runtime_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            container_name TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score INTEGER NOT NULL,
            ai_score REAL NOT NULL,
            cve_critical INTEGER NOT NULL,
            data JSON NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_audit(data: Dict[str, Any]):
    timestamp = data.get("timestamp", datetime.now().isoformat())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO audits (timestamp, data) VALUES (?, ?)", (timestamp, json.dumps(data)))
    conn.commit()
    conn.close()

def save_runtime_event(event: Dict[str, Any]):
    timestamp = event.get("timestamp", datetime.now().isoformat())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO runtime_events (timestamp, container_name, risk_level, score, ai_score, cve_critical, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, event.get("container", ""), event.get("risk_level", "low"), event.get("runtime_score", 0), event.get("ai_anomaly_score", 0.0), event.get("cve_critical", 0), json.dumps(event))
    )
    conn.commit()
    conn.close()

def get_audit_history() -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM audits ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]

def get_runtime_history() -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT data FROM runtime_events ORDER BY timestamp DESC LIMIT 1000")
    rows = cursor.fetchall()
    conn.close()
    return [json.loads(row[0]) for row in rows]

# Initialize DB on import
init_db()
