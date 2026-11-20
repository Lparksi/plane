# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import smtplib
from socketserver import StreamRequestHandler, TCPServer
from threading import Thread
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from plane.license.utils import smtp


@pytest.mark.unit
@pytest.mark.parametrize(
    "host, port, starttls, implicit_tls, sender",
    [
        ("", "587", "1", "0", "plane@example.test"),
        ("https://smtp.example.test", "587", "1", "0", "plane@example.test"),
        ("smtp.example.test", "0", "1", "0", "plane@example.test"),
        ("smtp.example.test", "65536", "1", "0", "plane@example.test"),
        ("smtp.example.test", "not-a-port", "1", "0", "plane@example.test"),
        ("smtp.example.test", "587", "1", "1", "plane@example.test"),
        ("smtp.example.test", "587", "1", "0", "not-an-address"),
    ],
)
def test_reject_invalid_smtp_config(host, port, starttls, implicit_tls, sender):
    with pytest.raises(smtp.SMTPConfigurationError):
        smtp.validate_smtp_settings(host, port, starttls, implicit_tls, sender)


@pytest.mark.unit
def test_smtp_failure_does_not_disclose_server_response(monkeypatch):
    monkeypatch.setattr(smtp, "get_configuration_value", lambda keys: ("1",))
    monkeypatch.setattr(
        smtp,
        "get_email_configuration",
        lambda: ("smtp.example.test", "account", "private-value", "587", "1", "0", "Plane <plane@example.test>"),
    )
    connect = Mock(side_effect=smtplib.SMTPAuthenticationError(535, b"private-value"))
    monkeypatch.setattr(smtp, "get_connection", connect)

    with pytest.raises(smtp.SMTPDeliveryError, match="SMTP authentication failed") as error:
        smtp.send_smtp_test_email("owner@example.test", subject="SMTP test", body="Example")

    assert "private-value" not in str(error.value)
    assert connect.call_args.kwargs["timeout"] == smtp.SMTP_TIMEOUT
    assert connect.call_args.kwargs["use_tls"] is True
    assert connect.call_args.kwargs["use_ssl"] is False


@pytest.mark.unit
@pytest.mark.parametrize("recipient", [None, ["owner@example.test"], "abc", "a@example.test\nb@example.test"])
def test_invalid_recipient_never_opens_connection(monkeypatch, recipient):
    connect = Mock()
    monkeypatch.setattr(smtp, "get_connection", connect)

    with pytest.raises(smtp.SMTPConfigurationError, match="valid recipient"):
        smtp.send_smtp_test_email(recipient, subject="SMTP test", body="Example")

    connect.assert_not_called()


class SMTPTestHandler(StreamRequestHandler):
    """Tiny loopback SMTP sink; never relays a message outside the test process."""

    def handle(self):
        self.wfile.write(b"220 loopback.test SMTP\r\n")
        in_data = False
        data = []
        while line := self.rfile.readline():
            if in_data:
                if line == b".\r\n":
                    self.server.messages.append(b"".join(data))
                    in_data = False
                    self.wfile.write(b"250 accepted\r\n")
                else:
                    data.append(line)
                continue
            verb = line.split(maxsplit=1)[0].upper()
            if verb in (b"EHLO", b"HELO", b"MAIL", b"RCPT"):
                self.wfile.write(b"250 OK\r\n")
            elif verb == b"DATA":
                in_data = True
                self.wfile.write(b"354 send message\r\n")
            elif verb == b"QUIT":
                self.wfile.write(b"221 closing connection\r\n")
                break
            else:
                self.wfile.write(b"500 unsupported\r\n")


class SMTPTestServer(TCPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), SMTPTestHandler)
        self.messages = []


@pytest.mark.unit
def test_sends_through_fake_smtp_even_with_memory_django_backend(monkeypatch, settings):
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
    monkeypatch.setattr(smtp, "get_configuration_value", lambda keys: ("1",))
    with SMTPTestServer() as server:
        monkeypatch.setattr(
            smtp,
            "get_email_configuration",
            lambda: ("127.0.0.1", "", "", str(server.server_address[1]), "0", "0", "Plane <plane@example.test>"),
        )
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            smtp.send_smtp_test_email("owner@example.test", subject="SMTP test", body="Example only")
        finally:
            server.shutdown()
            thread.join(timeout=2)

        [message] = server.messages
        assert b"Subject: SMTP test" in message
        assert b"To: owner@example.test" in message
        assert b"Example only" in message


@pytest.mark.unit
def test_disabled_smtp_does_not_open_connection(monkeypatch):
    monkeypatch.setattr(smtp, "get_configuration_value", lambda keys: ("0",))
    connect = Mock()
    monkeypatch.setattr(smtp, "get_connection", connect)
    with pytest.raises(smtp.SMTPConfigurationError, match="SMTP is disabled"):
        smtp.send_smtp_test_email("owner@example.test", subject="SMTP test", body="Example")
    connect.assert_not_called()


@pytest.mark.unit
@pytest.mark.parametrize("password", ["", None])
def test_blank_password_keeps_existing_encrypted_value(monkeypatch, settings, password):
    from plane.license.api.views import configuration

    settings.SKIP_ENV_VAR = True
    secret = SimpleNamespace(key="EMAIL_HOST_PASSWORD", value="encrypted-existing-secret", is_encrypted=True)
    manager = Mock()
    manager.filter.return_value = [secret]
    monkeypatch.setattr(configuration.InstanceConfiguration, "objects", manager)
    monkeypatch.setattr(
        configuration,
        "get_email_configuration",
        lambda: ("smtp.example.test", "user", "secret", "587", "1", "0", "plane@example.test"),
    )
    monkeypatch.setattr(
        configuration, "InstanceConfigurationSerializer", lambda *args, **kwargs: SimpleNamespace(data=[])
    )
    monkeypatch.setattr(configuration, "invalidate_cache_directly", Mock())
    request = SimpleNamespace(data={"EMAIL_HOST_PASSWORD": password})
    # The cache decorator is orthogonal to preservation of the encrypted value.
    response = configuration.InstanceConfigurationEndpoint.patch.__wrapped__(
        configuration.InstanceConfigurationEndpoint(), request
    )
    assert response.status_code == 200
    assert secret.value == "encrypted-existing-secret"
    assert manager.bulk_update.call_args.args[0] == []
