from typing_extensions import NotRequired, TypedDict


class Event(TypedDict):
    """
    Repo-wide event schema.

    The project started with an HTTP-ish shape; we now also support
    RBA login events (timestamp/ip/username/login_success/etc.).
    """

    # --- RBA login-event fields ---
    timestamp: str
    src_ip: str
    username: str
    rtt_ms: int
    country: str
    device: str
    user_agent: str
    login_success: bool
    is_attack_ip: bool
    is_account_takeover: bool
    auth_method: str
    mfa_required: int

    # --- Legacy HTTP-ish fields (optional; retained for backward compatibility) ---
    dst_ip: NotRequired[str]
    src_port: NotRequired[int]
    dst_port: NotRequired[int]
    protocol: NotRequired[str]  # e.g. "HTTP", "HTTPS", "SSH"
    http_status: NotRequired[int]
    url: NotRequired[str]
    method: NotRequired[str]  # GET, POST
    threat_signature: NotRequired[str]  # IDS/IPS signature ("" if none)
    bytes_sent: NotRequired[int]
    bytes_received: NotRequired[int]