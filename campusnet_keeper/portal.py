from __future__ import annotations

import base64
import json
import logging
import os
import socket
import struct
from dataclasses import dataclass
from http.cookiejar import MozillaCookieJar
from html.parser import HTMLParser
from typing import Any
from urllib.parse import quote, urlencode, urljoin, urlparse

import requests
from Crypto.Cipher import AES
from requests.adapters import HTTPAdapter

from .config import Settings


LOGGER = logging.getLogger(__name__)


class PortalError(RuntimeError):
    """Base error for portal operations."""


class PortalProtocolError(PortalError):
    """Raised when the gateway page does not match the expected protocol."""


@dataclass(frozen=True, slots=True)
class LoginForm:
    action: str
    fields: list[tuple[str, str]]

    def value(self, name: str) -> str:
        for field_name, value in self.fields:
            if field_name == name:
                return value
        return ""


@dataclass(frozen=True, slots=True)
class LoginResult:
    success: bool
    message: str
    code: str = ""
    retryable: bool = True


class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_address: str, *args: Any, **kwargs: Any) -> None:
        self.source_address = source_address
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        pool_kwargs["source_address"] = (self.source_address, 0)
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


def interface_ipv4_address(interface: str) -> str:
    if os.name != "posix":
        raise PortalProtocolError(
            "NETWORK_INTERFACE is supported only by the Linux container"
        )
    import fcntl

    if not interface or len(interface.encode("utf-8")) > 15:
        raise PortalProtocolError("NETWORK_INTERFACE is invalid")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as network_socket:
        request = struct.pack("256s", interface.encode("utf-8"))
        try:
            response = fcntl.ioctl(network_socket.fileno(), 0x8915, request)
        except OSError as exc:
            raise PortalProtocolError(
                f"could not resolve IPv4 address for interface {interface}: {exc}"
            ) from exc
    return socket.inet_ntoa(response[20:24])


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_login_form = False
        self.action = ""
        self.fields: list[tuple[str, str]] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag == "form" and attributes.get("id") == "loginForm":
            self.in_login_form = True
            self.action = attributes.get("action") or ""
            return
        if self.in_login_form and tag == "input":
            name = attributes.get("name")
            if name:
                self.fields.append((name, attributes.get("value") or ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self.in_login_form:
            self.in_login_form = False


def parse_login_form(html: str, page_url: str) -> LoginForm:
    parser = _LoginFormParser()
    parser.feed(html)
    names = {name for name, _ in parser.fields}
    if not {"user_account", "user_password", "iv"}.issubset(names):
        raise PortalProtocolError("loginForm is missing required fields")
    action = urljoin(page_url, parser.action or "/gportal/Web/loginAction")
    return LoginForm(action=action, fields=parser.fields)


def encrypt_form(encoded_form: str, key: str, iv: str) -> str:
    key_bytes = key.encode("utf-8")
    iv_bytes = iv.encode("utf-8")
    if len(iv_bytes) != AES.block_size:
        raise PortalProtocolError(
            f"portal returned an invalid AES IV ({len(iv_bytes)} bytes)"
        )
    payload = encoded_form.encode("utf-8")
    remainder = len(payload) % AES.block_size
    if remainder:
        payload += b"\0" * (AES.block_size - remainder)
    encrypted = AES.new(key_bytes, AES.MODE_CBC, iv_bytes).encrypt(payload)
    return base64.b64encode(encrypted).decode("ascii")


def decode_json_response(response: requests.Response) -> dict[str, Any]:
    try:
        text = response.content.decode("utf-8")
    except UnicodeDecodeError:
        text = response.content.decode("gb18030")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("portal returned a non-object JSON response")
    return payload


class PortalClient:
    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.settings = settings
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": settings.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            }
        )
        if settings.network_interface:
            source_address = interface_ipv4_address(settings.network_interface)
            adapter = SourceAddressAdapter(source_address)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            LOGGER.info(
                "Network requests are bound to %s (%s)",
                settings.network_interface,
                source_address,
            )
        self._configure_cookie_jar()

    def _configure_cookie_jar(self) -> None:
        if not self.settings.state_file or not isinstance(
            self.session.cookies, requests.cookies.RequestsCookieJar
        ):
            return
        cookie_jar = MozillaCookieJar(self.settings.state_file)
        if os.path.exists(self.settings.state_file):
            try:
                cookie_jar.load(ignore_discard=True, ignore_expires=True)
            except (OSError, ValueError):
                LOGGER.warning("Could not load the saved portal cookies")
        self.session.cookies = cookie_jar

    def _save_cookies(self) -> None:
        cookie_jar = self.session.cookies
        if not isinstance(cookie_jar, MozillaCookieJar):
            return
        directory = os.path.dirname(self.settings.state_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        try:
            cookie_jar.save(ignore_discard=True, ignore_expires=True)
        except OSError as exc:
            LOGGER.warning("Could not save portal cookies: %s", exc)

    def is_online(self) -> bool:
        for url in self.settings.check_urls:
            try:
                response = self.session.get(
                    url,
                    allow_redirects=False,
                    timeout=self.settings.request_timeout,
                )
            except requests.RequestException as exc:
                LOGGER.debug("Connectivity probe failed for %s: %s", url, exc)
                continue
            if self._is_expected_connectivity_response(url, response):
                return True
            LOGGER.debug(
                "Connectivity probe was intercepted: url=%s status=%s location=%s",
                url,
                response.status_code,
                response.headers.get("Location", ""),
            )
        return False

    @staticmethod
    def _is_expected_connectivity_response(
        probe_url: str, response: requests.Response
    ) -> bool:
        if response.is_redirect:
            return False
        host = (urlparse(probe_url).hostname or "").lower()
        if "gstatic.com" in host:
            return response.status_code == 204 and not response.content
        if "msftconnecttest.com" in host:
            return (
                response.status_code == 200
                and response.text.strip() == "Microsoft Connect Test"
            )
        return response.status_code in {200, 204}

    def _load_login_page(self) -> requests.Response:
        # A captive-portal redirect usually carries the per-device IV and NAS fields.
        for probe_url in self.settings.check_urls:
            try:
                response = self.session.get(
                    probe_url,
                    allow_redirects=True,
                    timeout=self.settings.request_timeout,
                )
            except requests.RequestException:
                continue
            if "loginForm" in response.text and "user_account" in response.text:
                return response

        try:
            response = self.session.get(
                self.settings.portal_url,
                allow_redirects=True,
                timeout=self.settings.request_timeout,
            )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            raise PortalError(f"could not open the portal: {exc}") from exc

    def login(self, _replacement_attempted: bool = False) -> LoginResult:
        page = self._load_login_page()
        form = parse_login_form(page.text, page.url)
        fields = list(form.fields)
        replacements = {
            "user_account": self.settings.account,
            "user_password": self.settings.password,
        }
        if self.settings.account_type:
            replacements["account_type"] = self.settings.account_type
        fields = [(name, replacements.get(name, value)) for name, value in fields]

        iv = next((value for name, value in fields if name == "iv"), "")
        if not iv:
            raise PortalProtocolError(
                "the portal did not provide an IV; connect this host to the campus "
                "network and make sure its captive redirect reaches the container"
            )

        # jQuery.serialize uses encodeURIComponent, which represents spaces as %20.
        encrypted = encrypt_form(
            urlencode(fields, quote_via=quote), self.settings.aes_key, iv
        )
        login_url = urljoin(page.url, "/gportal/Web/loginAction")
        try:
            response = self.session.post(
                login_url,
                data={"data": encrypted, "iv": iv},
                headers={
                    "X-Requested-With": "XMLHttpRequest",
                    "Referer": page.url,
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                },
                timeout=self.settings.request_timeout,
            )
            response.raise_for_status()
            payload = decode_json_response(response)
        except (requests.RequestException, ValueError) as exc:
            raise PortalError(f"portal login request failed: {exc}") from exc

        self._save_cookies()
        if str(payload.get("status")) == "1":
            return LoginResult(True, str(payload.get("info") or "login accepted"))

        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        code = str(data.get("resultCode") or "")
        message = str(payload.get("info") or "portal rejected the login")

        if (
            code == "124"
            and self.settings.allow_session_replace
            and not _replacement_attempted
        ):
            replace_url = str(data.get("resultData") or "")
            self._replace_session(replace_url, page.url)
            return LoginResult(True, "device binding request accepted")

        if code == "124":
            message += " (set ALLOW_SESSION_REPLACE=true to disconnect the old session)"
        elif code == "122":
            missing = [
                name
                for name in ("sta_port", "sta_vlan", "nas_ip")
                if not form.value(name)
            ]
            detail = ", ".join(missing) if missing else "none"
            message += (
                " (the gateway does not support binding this station; "
                f"missing portal fields: {detail}; ask the network operator to "
                "enable wired-terminal authentication)"
            )
        elif code in {"40", "114", "152"}:
            message += " (the portal requires interactive account verification or password setup)"
        return LoginResult(False, message, code, retryable=code not in {"40", "114", "122", "152"})

    def _replace_session(self, replace_url: str, portal_page_url: str) -> None:
        resolved_url = urljoin(portal_page_url, replace_url)
        parsed_target = urlparse(resolved_url)
        parsed_portal = urlparse(portal_page_url)
        if (
            parsed_target.scheme not in {"http", "https"}
            or parsed_target.hostname != parsed_portal.hostname
        ):
            raise PortalProtocolError("refused an unsafe session-replacement URL")
        try:
            response = self.session.post(
                resolved_url, timeout=self.settings.request_timeout
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise PortalError(f"could not replace the old session: {exc}") from exc
