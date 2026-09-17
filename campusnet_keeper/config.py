from __future__ import annotations

import os
from dataclasses import dataclass


DEFAULT_CHECK_URLS = (
    "http://www.baidu.com/",
)


def _positive_float(name: str, default: float) -> float:
    raw = os.getenv(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def _boolean(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


@dataclass(frozen=True, slots=True)
class Settings:
    account: str
    password: str
    account_type: str
    portal_url: str
    check_urls: tuple[str, ...]
    check_interval: float
    retry_interval: float
    terminal_retry_interval: float
    request_timeout: float
    network_interface: str
    allow_session_replace: bool
    state_file: str
    log_level: str
    user_agent: str
    aes_key: str

    @classmethod
    def from_env(cls) -> "Settings":
        account = os.getenv("GWIFI_ACCOUNT", "").strip()
        password = os.getenv("GWIFI_PASSWORD", "")
        if not account:
            raise ValueError("GWIFI_ACCOUNT is required")
        if not password:
            raise ValueError("GWIFI_PASSWORD is required")

        urls = tuple(
            item.strip()
            for item in os.getenv("CHECK_URLS", ",".join(DEFAULT_CHECK_URLS)).split(",")
            if item.strip()
        )
        if not urls:
            raise ValueError("CHECK_URLS must contain at least one URL")

        aes_key = os.getenv("GWIFI_AES_KEY", "1234567887654321")
        if len(aes_key.encode("utf-8")) not in {16, 24, 32}:
            raise ValueError("GWIFI_AES_KEY must be 16, 24, or 32 bytes")

        return cls(
            account=account,
            password=password,
            account_type=os.getenv("GWIFI_ACCOUNT_TYPE", "").strip(),
            portal_url=os.getenv(
                "PORTAL_URL", "http://10.4.0.5/gportal/web/login"
            ).strip(),
            check_urls=urls,
            check_interval=_positive_float("CHECK_INTERVAL", 86400),
            retry_interval=_positive_float("RETRY_INTERVAL", 60),
            terminal_retry_interval=_positive_float(
                "TERMINAL_RETRY_INTERVAL", 21600
            ),
            request_timeout=_positive_float("REQUEST_TIMEOUT", 10),
            network_interface=os.getenv("NETWORK_INTERFACE", "").strip(),
            allow_session_replace=_boolean("ALLOW_SESSION_REPLACE"),
            state_file=os.getenv("STATE_FILE", "/data/cookies.txt").strip(),
            log_level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
            user_agent=os.getenv(
                "USER_AGENT",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/140.0.0.0 Safari/537.36",
            ),
            aes_key=aes_key,
        )
