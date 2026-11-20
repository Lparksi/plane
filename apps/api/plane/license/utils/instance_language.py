# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Instance-level language defaults for the frontend and new profiles."""

from plane.license.models import InstanceConfiguration

DEFAULT_LANGUAGE_KEY = "DEFAULT_LANGUAGE"
FALLBACK_LANGUAGE = "en"
# Keep in sync with packages/i18n/src/constants/language.ts.
SUPPORTED_LANGUAGES = frozenset(
    (
        "en",
        "fr",
        "es",
        "ja",
        "zh-CN",
        "zh-TW",
        "ru",
        "it",
        "cs",
        "sk",
        "de",
        "ua",
        "pl",
        "ko",
        "pt-BR",
        "id",
        "ro",
        "vi-VN",
        "tr-TR",
        "ka-ge",
        "nl",
        "bg",
    )
)


def get_instance_default_language():
    value = (
        InstanceConfiguration.objects.filter(key=DEFAULT_LANGUAGE_KEY, is_encrypted=False)
        .values_list("value", flat=True)
        .first()
    )
    return value if value in SUPPORTED_LANGUAGES else FALLBACK_LANGUAGE
