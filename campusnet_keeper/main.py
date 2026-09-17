from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from dataclasses import dataclass

from .config import Settings
from .portal import PortalClient, PortalError


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    online: bool
    retryable: bool = True


def run_check(client: PortalClient) -> CheckOutcome:
    if client.is_online():
        LOGGER.info("Internet connection is available")
        return CheckOutcome(True)

    LOGGER.warning("Internet connection is unavailable; trying campus login")
    try:
        result = client.login()
    except PortalError as exc:
        LOGGER.error("Campus login failed: %s", exc)
        if client.is_online():
            LOGGER.info("Internet access is available after the inconclusive login")
            return CheckOutcome(True)
        return CheckOutcome(False)

    if not result.success:
        suffix = f" [code {result.code}]" if result.code else ""
        LOGGER.error("Campus login was rejected%s: %s", suffix, result.message)
        return CheckOutcome(False, retryable=result.retryable)

    LOGGER.info("Campus portal accepted the login: %s", result.message)
    if client.is_online():
        LOGGER.info("Internet access has been restored")
        return CheckOutcome(True)
    LOGGER.warning("Login was accepted, but Internet access is not available yet")
    return CheckOutcome(False)


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
        return 0 if run_check(client).online else 1

    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    LOGGER.info(
        "CampusNetKeeper started (normal %.0fs, retry %.0fs, terminal %.0fs)",
        settings.check_interval,
        settings.retry_interval,
        settings.terminal_retry_interval,
    )
    while not stop_event.is_set():
        outcome = run_check(client)
        if outcome.online:
            delay = settings.check_interval
        elif outcome.retryable:
            delay = settings.retry_interval
        else:
            delay = settings.terminal_retry_interval
            LOGGER.error("Non-retryable portal response; next check in %.0fs", delay)
        stop_event.wait(delay)
    LOGGER.info("CampusNetKeeper stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
