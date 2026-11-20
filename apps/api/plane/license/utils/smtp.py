# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from email.utils import parseaddr
from smtplib import (
    SMTPAuthenticationError,
    SMTPException,
    SMTPNotSupportedError,
    SMTPRecipientsRefused,
    SMTPSenderRefused,
)
from ssl import SSLError

from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives, get_connection
from django.core.validators import validate_email

from plane.license.utils.instance_value import get_configuration_value, get_email_configuration

SMTP_SETTING_KEYS = (
    "EMAIL_HOST",
    "EMAIL_HOST_USER",
    "EMAIL_HOST_PASSWORD",
    "EMAIL_PORT",
    "EMAIL_USE_TLS",
    "EMAIL_USE_SSL",
    "EMAIL_FROM",
)
SMTP_TIMEOUT = 10
SMTP_BACKEND = "django.core.mail.backends.smtp.EmailBackend"


class SMTPConfigurationError(ValueError):
    """A configuration error safe to show to an instance administrator."""


class SMTPDeliveryError(RuntimeError):
    """A delivery error without server-supplied strings or credentials."""


def validate_smtp_settings(host, port, use_tls, use_ssl, sender):
    if not isinstance(host, str) or not host or any(character.isspace() or character in "/@?#" for character in host):
        raise SMTPConfigurationError("Enter an SMTP hostname without a URL or scheme.")
    try:
        port = int(port)
    except (ValueError, TypeError):
        raise SMTPConfigurationError("Enter an SMTP port between 1 and 65535.") from None
    if not 1 <= port <= 65535:
        raise SMTPConfigurationError("Enter an SMTP port between 1 and 65535.")
    if use_tls not in ("0", "1") or use_ssl not in ("0", "1") or (use_tls == use_ssl == "1"):
        raise SMTPConfigurationError("Choose either STARTTLS, implicit TLS, or no encryption.")
    try:
        if not isinstance(sender, str) or not sender or "\r" in sender or "\n" in sender:
            raise ValidationError("Invalid sender")
        validate_email(parseaddr(sender)[1])
    except ValidationError:
        raise SMTPConfigurationError("Enter a valid sender email address.") from None
    return port


def send_smtp_test_email(receiver, *, subject, body, html=None):
    try:
        if not isinstance(receiver, str) or "\r" in receiver or "\n" in receiver:
            raise ValidationError("Invalid recipient")
        receiver = receiver.strip()
        validate_email(receiver)
    except ValidationError:
        raise SMTPConfigurationError("Enter a valid recipient email address.") from None

    (enabled,) = get_configuration_value([{"key": "ENABLE_SMTP", "default": "0"}])
    if enabled != "1":
        raise SMTPConfigurationError("SMTP is disabled. Enable it before sending a test email.")

    host, username, password, port, use_tls, use_ssl, sender = get_email_configuration()
    port = validate_smtp_settings(host, port, use_tls, use_ssl, sender)

    try:
        # Local/test Django settings may otherwise use the console or in-memory backend.
        connection = get_connection(
            backend=SMTP_BACKEND,
            host=host,
            port=port,
            username=username or "",
            password=password or "",
            use_tls=use_tls == "1",
            use_ssl=use_ssl == "1",
            timeout=SMTP_TIMEOUT,
        )
        message = EmailMultiAlternatives(subject, body, sender, [receiver], connection=connection)
        if html:
            message.attach_alternative(html, "text/html")
        if message.send(fail_silently=False) != 1:
            raise SMTPDeliveryError("The SMTP server did not accept the test email.")
    except SMTPAuthenticationError:
        raise SMTPDeliveryError("SMTP authentication failed. Check the username and password.") from None
    except SMTPSenderRefused:
        raise SMTPDeliveryError("The SMTP server refused the sender address.") from None
    except SMTPRecipientsRefused:
        raise SMTPDeliveryError("The SMTP server refused the recipient address.") from None
    except (SSLError, SMTPNotSupportedError):
        raise SMTPDeliveryError("SMTP negotiation failed. Check the selected encryption mode and port.") from None
    except TimeoutError:
        raise SMTPDeliveryError("Timed out connecting to the SMTP server.") from None
    except (OSError, SMTPException):
        raise SMTPDeliveryError("Unable to send mail through the SMTP server. Check its configuration.") from None
    except Exception:
        # Backends and remote servers may include credentials in exception text.
        raise SMTPDeliveryError("Unable to send mail through the SMTP server. Check its configuration.") from None
