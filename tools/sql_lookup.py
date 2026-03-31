import os
import sqlite3
from typing import Dict
from datetime import datetime, timedelta, timezone
from typing_extensions import Optional


db_path = os.path.join(os.path.dirname(__file__), "../data/logs.db")

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)

def _dataset_as_of() -> datetime:
    """
    Use `MAX(timestamp)` from `data/logs.db` as the lookback reference time.
    This keeps the 24h window meaningful for datasets whose timestamps are not "now".
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT MAX(timestamp) FROM logins")
    max_ts = cur.fetchone()[0]
    conn.close()

    if not max_ts:
        return _utc_now()

    # Normalize "...Z" to "...+00:00" for `fromisoformat`.
    ts = str(max_ts).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return _utc_now()

def sql_lookup(ip: Optional[str] = None, username: Optional[str] = None, lookback_h: int = 24) -> Dict[str, object]:
    """Return login stats for the last *lookback_h* hours filtered by ip/username."""
    as_of = _dataset_as_of()
    since_iso = (as_of - timedelta(hours=lookback_h)).isoformat().replace("+00:00", "Z")

    base_clauses, params = ["timestamp >= ?"], [since_iso]
    if ip:
        base_clauses.append("ip = ?"); params.append(ip)
    if username:
        base_clauses.append("username = ?"); params.append(username)
    where = " AND ".join(base_clauses)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    stats = {
        "ip_fail": 0,
        "ip_success": 0,
        "user_fail": 0,
        "user_success": 0,
        "ip_distinct_devices": 0,
        "user_distinct_countries": 0,
        "ip_mfa_bypass_fail": 0,
        "last_failure": None,
    }

    # --- success / failure counts ---
    cur.execute(
        f"SELECT ip, username, result, COUNT(*) AS cnt FROM logins WHERE {where} GROUP BY ip, username, result",
        params,
    )
    for row in cur.fetchall():
        if ip and row["ip"] == ip:
            if row["result"] == "failure":
                stats["ip_fail"] = row["cnt"]
            elif row["result"] == "success":
                stats["ip_success"] = row["cnt"]
        if username and row["username"] == username:
            if row["result"] == "failure":
                stats["user_fail"] = row["cnt"]
            elif row["result"] == "success":
                stats["user_success"] = row["cnt"]

    # --- distinct devices for IP ---
    if ip:
        cur.execute(
            f"SELECT COUNT(DISTINCT device) FROM logins WHERE {where}",
            params,
        )
        stats["ip_distinct_devices"] = cur.fetchone()[0]

        cur.execute(
            f"SELECT COUNT(*) FROM logins WHERE {where} AND result='failure' AND mfa_required=1",
            params,
        )
        stats["ip_mfa_bypass_fail"] = cur.fetchone()[0]

    # --- distinct countries for user ---
    if username:
        cur.execute(
            f"SELECT COUNT(DISTINCT country) FROM logins WHERE {where}",
            params,
        )
        stats["user_distinct_countries"] = cur.fetchone()[0]

    # --- last failure snapshot ---
    cur.execute(
        f"SELECT timestamp, auth_method, device, country FROM logins WHERE {where} AND result='failure' ORDER BY timestamp DESC LIMIT 1",
        params,
    )
    row = cur.fetchone()
    if row:
        stats["last_failure"] = {k: row[k] for k in row.keys()}

    conn.close()
    return stats