from typing import Dict, List, Tuple, Callable
from state import Event

Rule = Tuple[Callable[[Event], bool], int, str]

SUSPICIOUS_UA = {"curl", "python", "nmap", "sqlmap", "wget", "scrapy", "nikto"}
SUSPICIOUS_DEVICE = {"bot", "unknown", ""}

RULES: List[Rule] = [
    # Account takeover is the strongest signal in this dataset.
    (lambda e: bool(e.get("is_account_takeover")), 60, "Account takeover flag"),

    # Known attacker IPs (per RBA dataset).
    (lambda e: bool(e.get("is_attack_ip")), 30, "Attack IP flag"),

    # Failed logins are suspicious; successes are not automatically safe because RBA also marks attack IPs.
    (lambda e: not bool(e.get("login_success")), 25, "Login unsuccessful"),

    # Device / UA hints of automation.
    (lambda e: str(e.get("device", "")).strip().lower() in SUSPICIOUS_DEVICE, 12, "Suspicious device type"),

    (
        lambda e: any(
            kw in str(e.get("user_agent", "")).lower()
            for kw in SUSPICIOUS_UA
        ),
        15,
        "Suspicious user-agent substring",
    ),

    # High RTT values can indicate unusual paths / riskier access patterns.
    (lambda e: int(e.get("rtt_ms", 0) or 0) >= 2_000_000, 12, "Very high RTT"),
    (lambda e: int(e.get("rtt_ms", 0) or 0) >= 1_000_000, 8, "High RTT"),
    (lambda e: int(e.get("rtt_ms", 0) or 0) == 0, 4, "Missing/zero RTT"),

    # Country can be empty/unknown depending on parsing; keep a small weight.
    (lambda e: str(e.get("country", "")).strip().lower() in {"", "-", "unknown"}, 5, "Unknown country"),

    # Backward-compatible HTTP-oriented signals (in case events are still synthetic).
    (lambda e: int(e.get("http_status", 0) or 0) in {401, 403, 500, 502, 503}, 20, "HTTP error status (legacy)"),
    (
        lambda e: bool(e.get("threat_signature", "")),
        25,
        "IDS/IPS threat signature (legacy)",
    ),
    (
        lambda e: str(e.get("protocol", "")).upper() not in {"HTTP", "HTTPS", "SSH", "DNS", ""},
        5,
        "Unusual protocol (legacy)",
    ),
]

MAX_SCORE = 100

def event_analysis(event: Event) -> Dict[str, object]:  # noqa: D401 – simple
    """Compute a heuristic **risk_score** plus rule breakdown."""
    score = 0
    hits: List[str] = []
    for cond, weight, desc in RULES:
        if cond(event):
            score += weight
            hits.append(desc)
    score = min(score, MAX_SCORE)
    return {"risk_score": score, "reasons": hits}