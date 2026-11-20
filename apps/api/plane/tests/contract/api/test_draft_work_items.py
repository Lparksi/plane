# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from uuid import uuid4

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from plane.db.models import DraftIssue, Issue, Project, ProjectMember, User, Workspace


pytestmark = [pytest.mark.contract, pytest.mark.django_db]


def _url(workspace, draft_id=None):
    base = f"/api/v1/workspaces/{workspace.slug}/draft-work-items/"
    return f"{base}{draft_id}/" if draft_id else base


def _draft(workspace, user, **kwargs):
    draft = DraftIssue(workspace=workspace, created_by=user, **kwargs)
    draft.save(disable_auto_set_user=True)
    return draft


@pytest.fixture
def project(workspace, create_user):
    project = Project.objects.create(workspace=workspace, name="Draft project", identifier="DRAFT")
    ProjectMember.objects.create(project=project, member=create_user, role=15)
    return project


def test_authenticated_draft_round_trip(api_key_client, workspace, create_user, project):
    issue_count = Issue.objects.count()
    created = api_key_client.post(
        _url(workspace),
        {
            "project_id": str(project.id),
            "name": "Private draft",
            "description_html": "<p>My draft</p><script>alert(1)</script>",
            "priority": "low",
            "start_date": "2026-11-20",
        },
        format="json",
    )
    assert created.status_code == status.HTTP_201_CREATED, created.data
    draft_id = created.data["id"]
    assert created.data["project_id"] == str(project.id)
    assert created.data["description_html"] == "<p>My draft</p>"
    assert DraftIssue.objects.get(pk=draft_id).created_by == create_user

    list_response = api_key_client.get(f"{_url(workspace)}?project_id={project.id}&per_page=1")
    assert list_response.status_code == status.HTTP_200_OK, list_response.data
    assert list_response.data["total_count"] == 1
    assert list_response.data["results"][0]["id"] == draft_id

    updated = api_key_client.patch(
        _url(workspace, draft_id), {"name": "Updated", "priority": "high"}, format="json"
    )
    assert updated.status_code == status.HTTP_200_OK, updated.data
    assert updated.data["name"] == "Updated"
    assert updated.data["priority"] == "high"
    assert updated.data["description_html"] == "<p>My draft</p>"
    assert DraftIssue.objects.get(pk=draft_id).updated_by == create_user
    assert Issue.objects.count() == issue_count
    assert api_key_client.get(_url(workspace, draft_id)).data == updated.data
    assert api_key_client.delete(_url(workspace, draft_id)).status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_only_the_token_owners_drafts_are_visible(api_key_client, workspace, create_user, project):
    other_id = uuid4().hex
    other = User.objects.create(email=f"{other_id}@plane.so", username=other_id)
    another_workspaces_draft = _draft(
        Workspace.objects.create(name="Other Workspace", owner=create_user, slug="other-workspace"), create_user
    )
    own = _draft(workspace, create_user, name="Visible")
    foreign = _draft(workspace, other, name="Private to someone else", project=project)
    removed = _draft(workspace, create_user, name="Removed")
    DraftIssue.objects.filter(pk=removed.pk).delete()

    listed = api_key_client.get(_url(workspace))
    assert listed.status_code == status.HTTP_200_OK, listed.data
    assert [row["id"] for row in listed.data["results"]] == [str(own.pk)]
    for draft in (foreign, removed, another_workspaces_draft):
        assert api_key_client.get(_url(workspace, draft.pk)).status_code == status.HTTP_404_NOT_FOUND
        assert (
            api_key_client.patch(_url(workspace, draft.pk), {"name": "blocked"}, format="json").status_code
            == status.HTTP_404_NOT_FOUND
        )


def test_member_role_and_scope_are_enforced(api_key_client, workspace, create_user, project):
    unjoined = Project.objects.create(workspace=workspace, name="Private Project", identifier="UNJOINED", network=0)
    foreign_workspace = Workspace.objects.create(name="Another workspace", owner=create_user, slug="outside-workspace")
    foreign_project = Project.objects.create(workspace=foreign_workspace, name="Foreign Project", identifier="FOREIGN")
    ProjectMember.objects.create(project=foreign_project, member=create_user, role=15)
    for rejected in (unjoined, foreign_project):
        response = api_key_client.post(_url(workspace), {"project_id": str(rejected.id)}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    draft = _draft(workspace, create_user, project=project)
    project_member = ProjectMember.objects.filter(project=project, member=create_user)
    # Inactive membership hides even a formerly-owned project draft.
    project_member.update(is_active=False)
    assert api_key_client.get(_url(workspace, draft.pk)).status_code == status.HTTP_404_NOT_FOUND
    assert api_key_client.get(_url(workspace)).data["results"] == []

    # Active project guest under a workspace member may read but cannot modify a project draft.
    workspace.workspace_member.filter(member=create_user).update(role=15)
    project_member.update(is_active=True, role=5)
    assert api_key_client.get(_url(workspace, draft.pk)).status_code == status.HTTP_200_OK
    assert (
        api_key_client.patch(_url(workspace, draft.pk), {"name": "blocked"}, format="json").status_code
        == status.HTTP_403_FORBIDDEN
    )

    # A stale project membership is not enough after removal from the workspace.
    workspace.workspace_member.filter(member=create_user).update(is_active=False)
    assert api_key_client.get(_url(workspace)).status_code == status.HTTP_403_FORBIDDEN


def test_validates_payload_dates_and_is_immutable_across_projects(api_key_client, workspace, create_user, project):
    draft = _draft(workspace, create_user, project=project, start_date="2026-11-20")
    url = _url(workspace, draft.pk)
    unauthorized_payloads = (
        [],
        {},
        {"target_date": "2026-11-18"},
        {"priority": "unsupported"},
        {"project_id": None},
        {"created_by": str(uuid4())},
    )
    for payload in unauthorized_payloads:
        response = api_key_client.patch(url, payload, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert api_key_client.post(_url(workspace), {"project_id": "bad-id"}, format="json").status_code == 400
    assert api_key_client.get(f"{_url(workspace)}?project_id=nope").status_code == 400
    assert DraftIssue.objects.get(pk=draft.pk).project_id == project.pk


def test_authentication_and_private_body_redaction(api_key_client, workspace, create_user, mocker):
    assert APIClient().get(_url(workspace)).status_code == status.HTTP_401_UNAUTHORIZED
    draft = _draft(workspace, create_user, name="Only for me")
    audit = mocker.patch("plane.middleware.logger.process_logs.delay")
    response = api_key_client.patch(_url(workspace, draft.pk), {"name": "Still confidential"}, format="json")
    assert response.status_code == status.HTTP_200_OK, response.data
    audit.assert_called_once()
    logged = audit.call_args.kwargs["log_data"]
    assert logged["method"] == "PATCH"
    assert logged["response_code"] == 200
    assert logged["body"] is None
    assert logged["response_body"] is None


def test_replacing_description_clears_stale_editor_content(api_key_client, workspace, create_user):
    draft = _draft(workspace, create_user, description_json={"old": "content"}, description_binary=b"old")
    response = api_key_client.patch(
        _url(workspace, draft.pk), {"description_html": "<p>Updated</p>"}, format="json"
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    draft.refresh_from_db()
    assert draft.description_html == "<p>Updated</p>"
    assert draft.description_json == {}
    assert draft.description_binary is None
