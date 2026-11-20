# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import pytest

from plane.db.models import APIToken, User


@pytest.mark.django_db
@pytest.mark.contract
def test_agent_tokens_are_owned_and_independently_revocable(session_client, create_user):
    url = "/api/users/api-tokens/"
    first = session_client.post(url, {"label": "first", "agent_name": "dot"}, format="json")
    second = session_client.post(url, {"label": "second", "agent_name": "other"}, format="json")
    assert first.status_code == second.status_code == 201
    other = User.objects.create(email="other-agent-owner@example.test", username="other-agent-owner")
    session_client.force_authenticate(user=other)
    denied = session_client.delete(f"{url}{first.data['id']}/")
    assert denied.status_code == 404
    assert APIToken.objects.filter(pk=first.data["id"], user=create_user).exists()
    session_client.force_authenticate(user=create_user)
    assert session_client.delete(f"{url}{first.data['id']}/").status_code == 204
    assert APIToken.objects.filter(pk=second.data["id"], user=create_user).exists()


@pytest.mark.django_db
@pytest.mark.contract
def test_agent_names_reject_control_characters(session_client):
    response = session_client.post(
        "/api/users/api-tokens/", {"label": "agent", "agent_name": "do\u202et"}, format="json"
    )
    assert response.status_code == 400
