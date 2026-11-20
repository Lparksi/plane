# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from unicodedata import category

from .base import BaseSerializer
from plane.db.models import APIToken, APIActivityLog
from rest_framework import serializers
from django.utils import timezone


class APITokenSerializer(BaseSerializer):
    class Meta:
        model = APIToken
        fields = "__all__"
        read_only_fields = [
            "token",
            "expired_at",
            "created_at",
            "updated_at",
            "workspace",
            "user",
            "is_active",
            "last_used",
            "user_type",
            "agent_name",
        ]


class APITokenCreateSerializer(BaseSerializer):
    class Meta:
        model = APIToken
        fields = ("label", "description", "expired_at", "agent_name")
        extra_kwargs = {"label": {"required": False}}

    def validate_agent_name(self, name):
        # Disallow invisible control/format characters that can obscure attribution.
        if any(category(character).startswith("C") for character in name):
            raise serializers.ValidationError("Agent name cannot contain control characters.")
        return name


class APITokenReadSerializer(BaseSerializer):
    is_active = serializers.SerializerMethodField()

    class Meta:
        model = APIToken
        exclude = ("token",)

    def get_is_active(self, obj: APIToken) -> bool:
        if obj.expired_at is None:
            return True
        return timezone.now() < obj.expired_at


class APIActivityLogSerializer(BaseSerializer):
    class Meta:
        model = APIActivityLog
        fields = "__all__"
