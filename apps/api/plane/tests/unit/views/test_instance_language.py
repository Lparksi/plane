# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from unittest.mock import Mock

import pytest

from plane.license.utils import instance_language


@pytest.mark.unit
@pytest.mark.parametrize("stored, expected", [("zh-CN", "zh-CN"), ("en", "en"), (None, "en"), ("invalid", "en")])
def test_instance_language_uses_supported_value_or_english(monkeypatch, stored, expected):
    query = Mock()
    query.values_list.return_value.first.return_value = stored
    monkeypatch.setattr(instance_language.InstanceConfiguration.objects, "filter", Mock(return_value=query))
    assert instance_language.get_instance_default_language() == expected
    instance_language.InstanceConfiguration.objects.filter.assert_called_once_with(
        key="DEFAULT_LANGUAGE", is_encrypted=False
    )


@pytest.mark.unit
def test_existing_profile_is_not_overwritten_by_instance_default(monkeypatch):
    from plane.authentication.utils import redirection_path

    profile = Mock(is_onboarded=False, language="en")
    get_or_create = Mock(return_value=(profile, False))
    monkeypatch.setattr(redirection_path.Profile.objects, "get_or_create", get_or_create)
    user = Mock()
    redirection_path.get_redirection_path(user)
    assert get_or_create.call_args.kwargs["defaults"]["language"] is redirection_path.get_instance_default_language
    assert profile.language == "en"
