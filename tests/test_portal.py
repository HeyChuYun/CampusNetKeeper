from __future__ import annotations

import base64
from unittest.mock import Mock

from Crypto.Cipher import AES

from campusnet_keeper.config import Settings
from campusnet_keeper.portal import PortalClient, encrypt_form, parse_login_form


def test_parse_login_form_keeps_field_order_and_values() -> None:
    html = """
    <form id="loginForm">
      <input type="hidden" name="sign" value="signed">
      <input type="hidden" name="iv" value="1234567890abcdef">
      <input type="text" name="user_account">
      <input type="password" name="user_password">
    </form>
    """

    form = parse_login_form(html, "http://10.4.0.5/gportal/web/login")

    assert form.fields == [
        ("sign", "signed"),
        ("iv", "1234567890abcdef"),
        ("user_account", ""),
        ("user_password", ""),
    ]


def test_encrypt_form_matches_cryptojs_zero_padding() -> None:
    plaintext = "iv=1234567890abcdef&user_account=alice&user_password=secret"
    key = "1234567887654321"
    iv = "1234567890abcdef"

    encrypted = encrypt_form(plaintext, key, iv)
    decrypted = AES.new(
        key.encode(), AES.MODE_CBC, iv.encode()
    ).decrypt(base64.b64decode(encrypted))

    assert decrypted.rstrip(b"\0").decode() == plaintext


def test_session_replacement_resolves_relative_portal_url() -> None:
    settings = Settings(
        account="alice",
        password="secret",
        account_type="",
        portal_url="http://10.4.0.5/gportal/web/login",
        check_urls=("http://example.test/probe",),
        check_interval=86400,
        retry_interval=60,
        request_timeout=10,
        allow_session_replace=True,
        state_file="",
        log_level="INFO",
        user_agent="test",
        aes_key="1234567887654321",
    )
    session = Mock()
    session.headers = {}
    session.cookies = object()
    session.post.return_value.raise_for_status.return_value = None
    client = PortalClient(settings, session=session)

    client._replace_session("/gportal/Web/replace", settings.portal_url)

    session.post.assert_called_once_with(
        "http://10.4.0.5/gportal/Web/replace", timeout=10
    )
