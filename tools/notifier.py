import os
import textwrap
import datetime as dt
from typing import Dict, List, Optional


def _utc_now_iso_z() -> str:
    return dt.datetime.utcnow().isoformat().replace("+00:00", "Z")


def _ensure_banner(log_path: str) -> None:
    """
    Write a header similar to `example.log` once per file.
    """
    if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
        return

    dir_path = os.path.dirname(log_path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    session_dataset = os.getenv("SESSION_DATASET_LABEL", "RBA Dataset Prototype")
    model_label = os.getenv("CURRENT_MODEL_LABEL", "Unknown Model")

    banner = (
        "=" * 80
        + "\n"
        + f"LLM MULTI-AGENT CYBER THREAT DETECTION — {os.path.basename(log_path)}\n"
        + f"{session_dataset}  |  Log-File Output (replaces Slack notifications)\n"
        + f"Generated : {_utc_now_iso_z()}\n"
        + f"Model      : {model_label}\n"
        + "=" * 80
        + "\n\n"
    )
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(banner)


def notify(
    timestamp: str,
    src_ip: str,
    username: str,
    country: str,
    device: str,
    login_success: bool,
    is_attack_ip: bool,
    is_account_takeover: bool,
    risk: int,
    summary: str,
    links: Optional[List[str]] = None,
) -> Dict[str, str]:
    """
    Append an event entry to a log file.

    `main.py` sets `ALERT_LOG_FILE` (per-model) and `CURRENT_MODEL_LABEL`.
    """
    log_path = os.getenv("ALERT_LOG_FILE", "alerts.log")
    _ensure_banner(log_path)

    # Keep the event section close to the style of `example.log`.
    header = textwrap.dedent(
        f"""
        --------------------------------------------------------------------------------
        [{timestamp}] EVENT
          ip                : {src_ip}
          user              : {username}
          country          : {country}
          ua_device        : {device}
          login_success    : {str(login_success).lower()}
          is_attack_ip     : {str(is_attack_ip).lower()}
          is_account_takeover : {str(is_account_takeover).lower()}
        """
    ).rstrip()

    links_text = ""
    if links:
        links_text = "\nReferences:\n" + "\n".join(f"  • {x}" for x in links[:3])

    body = textwrap.dedent(
        f"""
        [notify] Risk={risk}/100
        {summary}
        {links_text}
        """
    ).rstrip()

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(header + "\n\n" + body + "\n")

    return {"status": "logged", "risk": str(risk)}