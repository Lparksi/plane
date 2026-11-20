# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from plane.app.permissions import ROLE
from plane.db.models import ProjectMember, WorkspaceMember


def can_write_project(user, slug, project_id):
    # Same rule IssueViewSet.create enforces (allow_permission): an active
    # ADMIN/MEMBER of the project, which must belong to the URL workspace, or a
    # workspace ADMIN who is an active member of the project at any role.
    role = (
        ProjectMember.objects.filter(
            member=user,
            workspace__slug=slug,
            project__workspace__slug=slug,
            project__deleted_at__isnull=True,
            project_id=project_id,
            is_active=True,
        )
        .values_list("role", flat=True)
        .first()
    )
    if role is None:
        return False
    return (
        role in (ROLE.ADMIN.value, ROLE.MEMBER.value)
        or WorkspaceMember.objects.filter(
            member=user, workspace__slug=slug, role=ROLE.ADMIN.value, is_active=True
        ).exists()
    )
