# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from rest_framework import serializers

from plane.db.models import DraftIssue
from plane.utils.content_validator import validate_html_content


class DraftWorkItemSerializer(serializers.ModelSerializer):
    project_id = serializers.UUIDField(read_only=True, allow_null=True)
    state_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = DraftIssue
        fields = (
            "id",
            "project_id",
            "state_id",
            "name",
            "description_html",
            "priority",
            "start_date",
            "target_date",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class DraftWorkItemInput(serializers.Serializer):
    name = serializers.CharField(max_length=255, required=False, allow_blank=True, allow_null=True)
    description_html = serializers.CharField(
        max_length=100_000, required=False, allow_blank=True, trim_whitespace=False
    )
    priority = serializers.ChoiceField(choices=DraftIssue.PRIORITY_CHOICES, required=False)
    start_date = serializers.DateField(required=False, allow_null=True)
    target_date = serializers.DateField(required=False, allow_null=True)

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError({"non_field_errors": ["Request body must be a JSON object."]})
        if data.keys() - self.fields.keys():
            raise serializers.ValidationError({"non_field_errors": ["Request contains unsupported draft fields."]})
        if self.instance is not None and not data:
            raise serializers.ValidationError({"non_field_errors": ["Provide at least one draft field to update."]})
        return super().to_internal_value(data)

    def validate_description_html(self, content):
        valid, _, cleaned = validate_html_content(content)
        if not valid:
            raise serializers.ValidationError("Invalid HTML content.")
        return content if cleaned is None else cleaned

    def validate(self, attrs):
        start = attrs.get("start_date", getattr(self.instance, "start_date", None))
        target = attrs.get("target_date", getattr(self.instance, "target_date", None))
        if start is not None and target is not None and start > target:
            raise serializers.ValidationError({"target_date": "Target date cannot precede start date."})
        return attrs

    def create(self, validated_data):
        draft = DraftIssue(**validated_data)
        draft.save(disable_auto_set_user=True)
        return draft

    def update(self, instance, validated_data):
        # The external API edits the canonical HTML used by the draft editor.
        # Do not keep older rich-text representations after replacing that HTML.
        if "description_html" in validated_data:
            validated_data.update(description_json={}, description_binary=None)
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save(disable_auto_set_user=True)
        return instance


class DraftWorkItemCreateInput(DraftWorkItemInput):
    project_id = serializers.UUIDField(required=False, allow_null=True)
