# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import unittest

from plane_mcp_bridge.catalog import DRAFT_TOOLS, TOOLS

ID = "12345678-1234-1234-1234-123456789abc"


class CatalogTests(unittest.TestCase):
    def test_catalog_has_only_scoped_non_destructive_operations(self):
        for tool in [*TOOLS.values(), *DRAFT_TOOLS.values()]:
            with self.subTest(tool=tool.name):
                self.assertIn(tool.method, {"GET", "POST", "PATCH"})
                self.assertTrue(tool.path_template.startswith("/api/v1/"))
                self.assertFalse(any(word in tool.path_template for word in ("smtp", "admin", "archive")))
                if tool.name != "plane_get_current_user":
                    self.assertIn("{workspace}", tool.path_template)

    def test_path_and_unknown_argument_rejected(self):
        tool = TOOLS["plane_get_work_item"]
        for arguments in (
            {"project_id": "../../admin", "issue_id": ID},
            {"project_id": ID, "issue_id": ID, "url": "http://localhost"},
        ):
            with self.assertRaises(ValueError):
                tool.request(arguments, "workspace")
        with self.assertRaises(ValueError):
            tool.request({"project_id": ID, "issue_id": ID}, "../other")

    def test_comment_text_is_escaped(self):
        request = TOOLS["plane_create_work_item_comment"].request(
            {"project_id": ID, "issue_id": ID, "comment_text": "<script>x</script>\nsecond"}, "team"
        )
        self.assertEqual(request.json, {"comment_html": "<p>&lt;script&gt;x&lt;/script&gt;<br>second</p>"})

    def test_empty_patch_and_inconsistent_cursor_rejected(self):
        with self.assertRaises(ValueError):
            TOOLS["plane_update_work_item"].request({"project_id": ID, "issue_id": ID}, "team")
        with self.assertRaises(ValueError):
            TOOLS["plane_list_projects"].request({"cursor": "30:1:0", "per_page": 20}, "team")
        with self.assertRaises(ValueError):
            TOOLS["plane_list_projects"].request({"cursor": "99:1:0"}, "team")

    def test_draft_create_does_not_publish(self):
        request = DRAFT_TOOLS["plane_create_draft_work_item"].request({"name": "draft"}, "team")
        self.assertEqual(request.path, "/api/v1/workspaces/team/draft-work-items/")
        self.assertEqual(request.json, {"name": "draft"})


if __name__ == "__main__":
    unittest.main()
