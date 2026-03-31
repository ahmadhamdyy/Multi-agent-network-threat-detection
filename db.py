from __future__ import annotations

import os
import sqlite3
from typing import Iterable

from state import Event


db_path = os.path.join(os.path.dirname(__file__), "data", "logs.db")
os.makedirs(os.path.dirname(db_path), exist_ok=True)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    ip TEXT,
    username TEXT,
    result TEXT,
    auth_method TEXT,
    device TEXT,
    country TEXT,
    mfa_required INTEGER
);
"""


def _ensure_schema() -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.executescript(_SCHEMA)
    conn.commit()
    conn.close()


def reset_logs_db() -> None:
    """Clear stored login events (useful for deterministic 10-row testing)."""
    _ensure_schema()
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM logins")
    conn.commit()
    conn.close()


def insert_event(evt: Event) -> None:
    """
    Insert a single event into `data/logs.db` in the `logins` table schema.
    """
    _ensure_schema()

    # sqlite expects ISO timestamps for lexicographical comparisons.
    timestamp = (evt.get("timestamp") or "").strip()
    ip = (evt.get("src_ip") or "").strip()
    username = (evt.get("username") or "").strip()

    login_success = bool(evt.get("login_success"))
    result = "success" if login_success else "failure"

    auth_method = (evt.get("auth_method") or "unknown").strip()
    device = (evt.get("device") or "unknown").strip()
    country = (evt.get("country") or "unknown").strip()
    mfa_required = int(evt.get("mfa_required") or 0)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO logins(timestamp, ip, username, result, auth_method, device, country, mfa_required)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, ip, username, result, auth_method, device, country, mfa_required),
    )
    conn.commit()
    conn.close()


def insert_events(events: Iterable[Event], *, reset: bool = False) -> None:
    if reset:
        reset_logs_db()
    for evt in events:
        # Best-effort: skip blank timestamps (shouldn't happen with our mapper).
        if not (evt.get("timestamp") or "").strip():
            continue
        insert_event(evt)

