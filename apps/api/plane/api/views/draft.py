# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, OpenApiTypes, extend_schema
from rest_framework import serializers, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from plane.api.serializers.draft import DraftWorkItemCreateInput, DraftWorkItemInput, DraftWorkItemSerializer
from plane.api.views.base import BaseAPIView
from plane.app.permissions import WorkspaceUserPermission
from plane.db.models import DraftIssue, ProjectMember, Workspace
from plane.utils.draft_permissions import can_write_project
from plane.utils.openapi import create_paginated_response


class DraftWorkItemEndpoint(BaseAPIView):
    permission_classes = [WorkspaceUserPermission]
    serializer_class = DraftWorkItemSerializer

    def dispatch(self, request, *args, **kwargs):
        # Keep the existing PAT audit trail without recording personal draft
        # contents a second time in the API log storage.
        request.api_log_metadata_only = True
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        member_projects = ProjectMember.objects.filter(
            workspace__slug=self.workspace_slug,
            project__workspace__slug=self.workspace_slug,
            project__deleted_at__isnull=True,
            member=self.request.user,
            is_active=True,
        ).values("project_id")
        return DraftIssue.objects.filter(workspace__slug=self.workspace_slug, created_by=self.request.user).filter(
            Q(project_id__isnull=True) | Q(project_id__in=member_projects)
        )

    def check_project_write(self, project_id):
        if project_id is not None and not can_write_project(self.request.user, self.workspace_slug, project_id):
            raise PermissionDenied("You don't have the required project permissions.")


class DraftWorkItemListCreateEndpoint(DraftWorkItemEndpoint):
    @extend_schema(
        description="List only the authenticated user's private work item drafts in the workspace.",
        parameters=[OpenApiParameter("project_id", OpenApiTypes.UUID, description="Limit to this project.")],
        responses={200: create_paginated_response(DraftWorkItemSerializer, "DraftWorkItem", "Private drafts")},
    )
    def get(self, request, slug):
        drafts = self.get_queryset().order_by("-created_at", "-id")
        project_id = request.query_params.get("project_id")
        if project_id is not None:
            drafts = drafts.filter(project_id=serializers.UUIDField().run_validation(project_id))
        return self.paginate(
            request=request,
            queryset=drafts,
            on_results=lambda rows: self.get_serializer(rows, many=True).data,
            default_per_page=20,
            max_per_page=100,
        )

    @extend_schema(request=DraftWorkItemCreateInput, responses={201: DraftWorkItemSerializer})
    def post(self, request, slug):
        workspace = get_object_or_404(Workspace, slug=slug)
        serializer = DraftWorkItemCreateInput(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_project_write(serializer.validated_data.get("project_id"))
        draft = serializer.save(workspace=workspace, created_by=request.user)
        return Response(self.get_serializer(draft).data, status=status.HTTP_201_CREATED)


class DraftWorkItemDetailEndpoint(DraftWorkItemEndpoint):
    @extend_schema(responses={200: DraftWorkItemSerializer})
    def get(self, request, slug, pk):
        return Response(self.get_serializer(get_object_or_404(self.get_queryset(), pk=pk)).data)

    @extend_schema(request=DraftWorkItemInput, responses={200: DraftWorkItemSerializer})
    @transaction.atomic
    def patch(self, request, slug, pk):
        draft = get_object_or_404(self.get_queryset().select_for_update(), pk=pk)
        self.check_project_write(draft.project_id)
        serializer = DraftWorkItemInput(draft, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        draft = serializer.save(updated_by=request.user)
        return Response(self.get_serializer(draft).data)
