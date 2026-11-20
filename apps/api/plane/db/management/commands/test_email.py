# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.core.management import BaseCommand, CommandError
from django.template.loader import render_to_string

from plane.license.utils.smtp import SMTPConfigurationError, SMTPDeliveryError, send_smtp_test_email
from plane.utils.email import generate_plain_text_from_html


class Command(BaseCommand):
    help = "Send a test email through the configured SMTP server"

    def add_arguments(self, parser):
        parser.add_argument("to_email", type=str, help="recipient's email")

    def handle(self, *args, **options):
        html = render_to_string("emails/test_email.html")
        try:
            send_smtp_test_email(
                options["to_email"],
                subject="Test email from Plane",
                body=generate_plain_text_from_html(html),
                html=html,
            )
        except (SMTPConfigurationError, SMTPDeliveryError) as error:
            raise CommandError(str(error)) from None

        self.stdout.write(self.style.SUCCESS("The SMTP server accepted the test email."))
