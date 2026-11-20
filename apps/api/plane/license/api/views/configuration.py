# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

# Django imports
from django.conf import settings
from django.db.models import Q, Case, When, Value

# Third party imports
from rest_framework import status
from rest_framework.response import Response

# Module imports
from .base import BaseAPIView
from plane.license.api.permissions import InstanceAdminPermission
from plane.license.models import InstanceConfiguration
from plane.license.api.serializers import InstanceConfigurationSerializer
from plane.license.utils.encryption import encrypt_data
from plane.license.utils.instance_language import DEFAULT_LANGUAGE_KEY, SUPPORTED_LANGUAGES
from plane.utils.cache import invalidate_cache, invalidate_cache_directly
from plane.license.utils.instance_value import get_email_configuration
from plane.license.utils.smtp import (
    SMTPConfigurationError,
    SMTPDeliveryError,
    SMTP_SETTING_KEYS,
    send_smtp_test_email,
    validate_smtp_settings,
)


class InstanceConfigurationEndpoint(BaseAPIView):
    permission_classes = [InstanceAdminPermission]

    def get(self, request):
        instance_configurations = InstanceConfiguration.objects.all()
        serializer = InstanceConfigurationSerializer(instance_configurations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK, headers={"Cache-Control": "no-store"})

    @invalidate_cache(path="/api/instances/", user=False)
    def patch(self, request):
        if DEFAULT_LANGUAGE_KEY in request.data:
            language = request.data[DEFAULT_LANGUAGE_KEY]
            if not isinstance(language, str) or language not in SUPPORTED_LANGUAGES:
                return Response(
                    {"error": "Unsupported default language."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        smtp_keys = {*SMTP_SETTING_KEYS, "ENABLE_SMTP"}
        requested_smtp_keys = smtp_keys.intersection(request.data)
        if requested_smtp_keys:
            if not settings.SKIP_ENV_VAR:
                return Response(
                    {"error": "SMTP is managed by environment variables on this instance."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            enabled = str(request.data.get("ENABLE_SMTP", "1")).strip()
            if enabled not in ("0", "1"):
                return Response({"error": "Invalid SMTP enabled flag."}, status=status.HTTP_400_BAD_REQUEST)
            if enabled == "1":
                effective = dict(zip(SMTP_SETTING_KEYS, get_email_configuration(), strict=True))
                for key in requested_smtp_keys:
                    if key != "ENABLE_SMTP":
                        effective[key] = self.clean_configuration_value(key, request.data[key])
                try:
                    validate_smtp_settings(
                        effective["EMAIL_HOST"],
                        effective["EMAIL_PORT"],
                        effective["EMAIL_USE_TLS"],
                        effective["EMAIL_USE_SSL"],
                        effective["EMAIL_FROM"],
                    )
                except SMTPConfigurationError as error:
                    return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)

        if DEFAULT_LANGUAGE_KEY in request.data:
            InstanceConfiguration.objects.get_or_create(
                key=DEFAULT_LANGUAGE_KEY,
                defaults={"value": "en", "category": "GENERAL", "is_encrypted": False},
            )

        configurations = InstanceConfiguration.objects.filter(key__in=request.data.keys())

        bulk_configurations = []
        for configuration in configurations:
            raw_value = request.data.get(configuration.key, configuration.value)
            # Passwords are write-only: a blank field means retain the stored secret.
            if configuration.key == "EMAIL_HOST_PASSWORD" and raw_value in (None, ""):
                continue
            value = self.clean_configuration_value(configuration.key, raw_value)
            if configuration.is_encrypted:
                configuration.value = encrypt_data(value)
            else:
                configuration.value = value
            bulk_configurations.append(configuration)

        InstanceConfiguration.objects.bulk_update(bulk_configurations, ["value"], batch_size=100)
        # Invalidate after the write as well, so a concurrent read cannot leave a
        # stale value cached between the decorator's invalidation and the update.
        invalidate_cache_directly(path="/api/instances/", user=False, request=request)

        serializer = InstanceConfigurationSerializer(configurations, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK, headers={"Cache-Control": "no-store"})

    @staticmethod
    def clean_configuration_value(key, raw_value):
        if raw_value is None:
            return ""
        value = str(raw_value)
        return value if key == "EMAIL_HOST_PASSWORD" else value.strip()


class DisableEmailFeatureEndpoint(BaseAPIView):
    permission_classes = [InstanceAdminPermission]

    @invalidate_cache(path="/api/instances/", user=False)
    def delete(self, request):
        if not settings.SKIP_ENV_VAR:
            return Response(
                {"error": "SMTP is managed by environment variables on this instance."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            InstanceConfiguration.objects.filter(
                Q(
                    key__in=[
                        "EMAIL_HOST",
                        "EMAIL_HOST_USER",
                        "EMAIL_HOST_PASSWORD",
                        "ENABLE_SMTP",
                        "EMAIL_PORT",
                        "EMAIL_FROM",
                    ]
                )
            ).update(value=Case(When(key="ENABLE_SMTP", then=Value("0")), default=Value("")))
            invalidate_cache_directly(path="/api/instances/", user=False, request=request)
            return Response(status=status.HTTP_200_OK)
        except Exception:
            return Response(
                {"error": "Failed to disable email configuration"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class EmailCredentialCheckEndpoint(BaseAPIView):
    permission_classes = [InstanceAdminPermission]

    def post(self, request):
        try:
            send_smtp_test_email(
                request.data.get("receiver_email"),
                subject="Test email from Plane",
                body="This is a test email sent using the SMTP settings for this Plane instance.",
            )
        except (SMTPConfigurationError, SMTPDeliveryError) as error:
            return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "The SMTP server accepted the test email."}, status=status.HTTP_200_OK)
