from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading

from .config import Settings
from .portal import PortalClient, PortalError


LOGGER = logging.getLogger(__name__)


def run_check(client: PortalClient) -> bool:
    if client.is_online():
        LOGGER.info("Internet connection is available")
        return True

    LOGGER.warning("Internet connection is unavailable; trying campus login")
    try:
        result = client.login()
    except PortalError as exc:
        LOGGER.error("Campus login failed: %s", exc)
        return False

    if not result.success:
        suffix = f" [code {result.code}]" if result.code else ""
        LOGGER.error("Campus login was rejected%s: %s", suffix, result.message)
        return False

    LOGGER.info("Campus portal accepted the login: %s", result.message)
    if client.is_online():
        LOGGER.info("Internet access has been restored")
        return True
    LOGGER.warning("Login was accepted, but Internet access is not available yet")
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Keep a GiWiFi campus network online")
    parser.add_argument(
        "--once", action="store_true", help="check once and exit instead of monitoring"
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        settings = Settings.from_env()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    client = PortalClient(settings)

    if args.once:
        return 0 if run_check(client) else 1

    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    LOGGER.info(
        "CampusNetKeeper started (normal interval %.0fs, retry interval %.0fs)",
        settings.check_interval,
        settings.retry_interval,
    )
    while not stop_event.is_set():
        online = run_check(client)
        delay = settings.check_interval if online else settings.retry_interval
        stop_event.wait(delay)
    LOGGER.info("CampusNetKeeper stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
