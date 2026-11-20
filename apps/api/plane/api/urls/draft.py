# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.urls import path

from plane.api.views.draft import DraftWorkItemDetailEndpoint, DraftWorkItemListCreateEndpoint


urlpatterns = [
    path(
        "workspaces/<str:slug>/draft-work-items/",
        DraftWorkItemListCreateEndpoint.as_view(http_method_names=["get", "post"]),
        name="draft-work-item-list-create",
    ),
    path(
        "workspaces/<str:slug>/draft-work-items/<uuid:pk>/",
        DraftWorkItemDetailEndpoint.as_view(http_method_names=["get", "patch"]),
        name="draft-work-item-detail",
    ),
]
