from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import Dict, Iterator, Optional

from state import Event


def _parse_rfc3339_z(dt_str: str) -> str:
    """
    Parse dataset timestamps like `2020-02-03 12:43:30.772` and return ISO8601 with `Z`.
    """
    dt_str = (dt_str or "").strip()
    if not dt_str:
        return ""

    # The dataset uses a "YYYY-MM-DD HH:MM:SS.mmm" format, but we accept no-millis as well.
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(dt_str, fmt)
            parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z")
        except ValueError:
            continue

    # Fallback: return as-is (best-effort); downstream code should still be robust enough.
    return dt_str


def _parse_bool(v: str) -> bool:
    v = (v or "").strip().lower()
    return v in {"true", "1", "yes", "y", "t"}


def _parse_int(v: str, default: int = 0) -> int:
    v = (v or "").strip()
    if not v:
        return default
    try:
        # RTT can be stored like "1123.0" in the CSV.
        return int(float(v))
    except ValueError:
        return default


def _iter_rba_csv_rows(limit: Optional[int] = None) -> Iterator[Dict[str, str]]:
    env_path = os.getenv("RBA_CSV_PATH", "").strip()
    candidates = []
    if env_path:
        candidates.append(env_path)
    else:
        # Support both repo layouts:
        #  - `./rba-dataset/rba-dataset.csv`
        #  - `./rba-dataset.csv`
        base = os.path.dirname(__file__)
        candidates.extend(
            [
                os.path.join(base, "rba-dataset.csv"),
                os.path.join(base, "rba-dataset", "rba-dataset.csv"),
            ]
        )

    csv_path = next((p for p in candidates if os.path.exists(p)), "")
    if not csv_path:
        raise FileNotFoundError(
            "RBA CSV not found. Looked for:\n- "
            + "\n- ".join(candidates)
            + "\nSet `RBA_CSV_PATH` to override."
        )

    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            if limit is not None and idx >= limit:
                break
            yield row


def _map_row_to_event(row: Dict[str, str]) -> Event:
    """
    Map RBA CSV columns to the repo's `Event` schema.
    See `rba-dataset/README.md` for the feature definitions.
    """
    timestamp = _parse_rfc3339_z(row.get("Login Timestamp", ""))
    src_ip = (row.get("IP Address") or "").strip()

    user_id = (row.get("User ID") or "").strip()
    username = f"uid:{user_id}" if user_id else "unknown"

    login_success = _parse_bool(row.get("Login Successful", "False"))
    is_attack_ip = _parse_bool(row.get("Is Attack IP", "False"))
    is_account_takeover = _parse_bool(row.get("Is Account Takeover", "False"))

    device_type = (row.get("Device Type") or "").strip() or "unknown"
    user_agent = (row.get("User Agent String") or "").strip()

    country = (row.get("Country") or "").strip() or "unknown"
    rtt_ms = _parse_int(row.get("Round-Trip Time [ms]"), default=0)

    # For compatibility with the previous HTTP-oriented schema, we provide a few optional defaults.
    # They will be ignored once `tools/event_analysis.py` is updated for login-event heuristics.
    event: Dict[str, object] = {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "username": username,
        "rtt_ms": rtt_ms,
        "country": country,
        "device": device_type,
        "user_agent": user_agent,
        "login_success": login_success,
        "is_attack_ip": is_attack_ip,
        "is_account_takeover": is_account_takeover,
        "auth_method": "unknown",
        "mfa_required": 0,
        # Defaults for legacy rules (safe no-ops once updated).
        "protocol": "HTTP",
        "http_status": 200 if login_success else 401,
        "method": "GET",
        "url": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "threat_signature": "Brute_force_login" if is_attack_ip else "",
        "bytes_sent": 0,
        "bytes_received": 0,
    }

    return event  # type: ignore[return-value]


def event_stream(limit: int | None = None):
    """Yield up to *limit* RBA login events (or all rows if None)."""
    for row in _iter_rba_csv_rows(limit=limit):
        yield _map_row_to_event(row)