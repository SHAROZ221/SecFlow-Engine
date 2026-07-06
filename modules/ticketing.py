"""
ticketing.py
Simple local ticket queue backed by SQLite. Stands in for a real
ticketing system (Jira/GLPI/ServiceNow) -- swap execute() calls here
for an API request if you wire this into a real one later.
"""

import sqlite3
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "evidence", "tickets.db")


def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            indicator TEXT,
            severity TEXT,
            status TEXT,
            created_at TEXT,
            summary TEXT
        )
        """
    )
    conn.commit()
    return conn


def open_ticket(alert_id: str, indicator: str, severity: str, summary: str) -> dict:
    conn = _init_db()
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO tickets (alert_id, indicator, severity, status, created_at, summary) "
        "VALUES (?, ?, ?, 'open', ?, ?)",
        (alert_id, indicator, severity, created_at, summary),
    )
    conn.commit()
    ticket_id = cur.lastrowid
    conn.close()
    return {
        "ticket_id": ticket_id,
        "status": "open",
        "created_at": created_at,
    }
