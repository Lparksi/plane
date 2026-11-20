# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Allowlisted, workspace-scoped bindings to Plane's public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from html import escape
import re
from string import Formatter
from typing import Any
from urllib.parse import quote, urlsplit

UUID_PATTERN = r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$"
SLUG_PATTERN = r"[a-zA-Z0-9_-]{1,128}"
CURSOR_PATTERN = r"^[1-9][0-9]{0,2}:[0-9]{1,5}:[01]$"
MAX_PAGE_SIZE = 50
DEFAULT_PAGE_SIZE = 20


def string(description: str, *, maximum: int = 255, minimum: int = 1, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "description": description, "minLength": minimum, "maxLength": maximum, **extra}


def integer(description: str, minimum: int, maximum: int) -> dict[str, Any]:
    return {"type": "integer", "description": description, "minimum": minimum, "maximum": maximum}


def boolean(description: str) -> dict[str, Any]:
    return {"type": "boolean", "description": description}


def choice(description: str, *options: str) -> dict[str, Any]:
    return {"type": "string", "description": description, "enum": list(options)}


def uid(description: str) -> dict[str, Any]:
    return string(description, maximum=36, minimum=36, pattern=UUID_PATTERN)


def ids(description: str, *, minimum: int = 0) -> dict[str, Any]:
    return {"type": "array", "description": description, "minItems": minimum, "maxItems": 25, "items": uid("UUID")}


def _valid(value: Any, schema: dict[str, Any]) -> bool:
    match schema["type"]:
        case "string":
            if not isinstance(value, str) or any(ord(c) == 0 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
                return False
            if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 64):
                return False
            if schema.get("minLength", 0) and not value.strip():
                return False
            if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
                return False
            if "enum" in schema and value not in schema["enum"]:
                return False
            try:
                if schema.get("format") == "date":
                    date.fromisoformat(value)
                elif schema.get("format") == "date-time":
                    if datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() is None:
                        return False
                elif schema.get("format") == "uri":
                    if any(c.isspace() or ord(c) < 32 or c == "\\" for c in value):
                        return False
                    parts = urlsplit(value)
                    return (
                        parts.scheme in {"https", "http"}
                        and bool(parts.hostname)
                        and parts.username is None
                        and parts.password is None
                    )
            except ValueError:
                return False
            return True
        case "integer":
            return type(value) is int and schema["minimum"] <= value <= schema["maximum"]
        case "boolean":
            return type(value) is bool
        case "array":
            return (
                isinstance(value, list)
                and schema["minItems"] <= len(value) <= schema["maxItems"]
                and all(_valid(item, schema["items"]) for item in value)
            )
        case _:
            raise AssertionError("Unsupported field schema")


def _text_html(text: str) -> str:
    # Use plain text at the MCP boundary; never accept model-generated HTML.
    return "<p>" + escape(text.replace("\r\n", "\n").replace("\r", "\n")).replace("\n", "<br>") + "</p>"


@dataclass(frozen=True)
class RequestSpec:
    method: str
    path: str
    query: dict[str, str | int] | None
    json: dict[str, Any] | None


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    method: str
    path_template: str
    path_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    body_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    query_fields: dict[str, dict[str, Any]] = field(default_factory=dict)
    required_fields: tuple[str, ...] = ()
    html_fields: dict[str, str] = field(default_factory=dict)
    paginated: bool = False

    @property
    def input_schema(self) -> dict[str, Any]:
        query_fields = self.query_fields
        if self.paginated:
            query_fields = {**query_fields, **PAGING}
        schema = {
            "type": "object",
            "properties": {**self.path_fields, **query_fields, **self.body_fields},
            "required": [*self.path_fields, *self.required_fields],
            "additionalProperties": False,
        }
        if self.method == "PATCH":
            schema["minProperties"] = len(self.path_fields) + 1
        return schema

    def request(self, args: dict[str, Any], workspace_slug: str) -> RequestSpec:
        if not re.fullmatch(SLUG_PATTERN, workspace_slug):
            raise ValueError("Invalid configured workspace slug")
        schema = self.input_schema
        props = schema["properties"]
        if not isinstance(args, dict) or any(key not in props for key in args):
            raise ValueError("Arguments contain unsupported fields")
        for key in schema["required"]:
            if key not in args:
                raise ValueError(f"Missing required field: {key}")
        for key, value in args.items():
            if not _valid(value, props[key]):
                raise ValueError(f"Invalid field: {key}")
        path = self.path_template.format(
            workspace=quote(workspace_slug, safe=""),
            **{key: quote(str(args[key]), safe="") for key in self.path_fields},
        )
        query = {key: args[key] for key in self.query_fields if key in args}
        if self.paginated:
            query["per_page"] = args.get("per_page", DEFAULT_PAGE_SIZE)
            if "cursor" in args:
                cursor = args["cursor"]
                # Server cursors encode their page size. Never accept inconsistent offsets.
                if "per_page" in args and int(cursor.split(":", 1)[0]) != query["per_page"]:
                    raise ValueError("Cursor page size does not match per_page")
                query["per_page"] = int(cursor.split(":", 1)[0])
                if query["per_page"] > MAX_PAGE_SIZE:
                    raise ValueError("Cursor exceeds page size limit")
                query["cursor"] = cursor
        if self.name == "plane_search_work_items":
            query["workspace_search"] = "false" if "project_id" in query else "true"
            query.setdefault("limit", DEFAULT_PAGE_SIZE)
        body = {
            self.html_fields.get(key, key): _text_html(args[key]) if key in self.html_fields else args[key]
            for key in self.body_fields
            if key in args
        }
        if self.method == "PATCH" and not body:
            raise ValueError("Provide at least one field to update")
        return RequestSpec(self.method, path, query or None, body if self.method != "GET" else None)


PAGING = {
    "per_page": integer("Page size (default 20, maximum 50)", 1, MAX_PAGE_SIZE),
    "cursor": string("The next_cursor supplied by Plane; omit on the first page", maximum=32, pattern=CURSOR_PATTERN),
}
TITLE = string("Name or title")
SHORT_TEXT = string("Plain-text description", maximum=10000, minimum=0)
LONG_TEXT = string("Plain-text description; converted to safe HTML", maximum=16000, minimum=0)
REQUIRED_TEXT = string("Nonempty plain text; converted to safe HTML", maximum=16000)
DATE = string(
    "Calendar date, YYYY-MM-DD", minimum=10, maximum=10, format="date", pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
)
DATETIME = string(
    "ISO 8601 date and time with a timezone, e.g. 2026-11-01T09:00:00Z", maximum=40, format="date-time",
    pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T.+(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
COLOR = string("Hex color such as #3D75FF", minimum=7, maximum=7, pattern=r"^#[a-fA-F0-9]{6}$")
IDENTIFIER = string(
    "Project identifier, for example ENG", maximum=12, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,11}$"
)
WORKSPACE = "/api/v1/workspaces/{workspace}"
PROJECT = WORKSPACE + "/projects/{project_id}"
ITEM = PROJECT + "/work-items/{issue_id}"
_PATH_FIELDS = {
    name: uid(description) for name, description in {
        "project_id": "Project UUID returned by plane_list_projects",
        "issue_id": "Work item UUID returned by a work item list or search",
        "comment_id": "Comment UUID",
        "link_id": "Link UUID",
        "state_id": "Workflow state UUID",
        "label_id": "Label UUID",
        "cycle_id": "Cycle UUID",
        "module_id": "Module UUID",
        "sticky_id": "Sticky note UUID",
        "draft_id": "Draft work item UUID",
    }.items()
}
_PATH_FIELDS.update({
    "project_identifier": IDENTIFIER,
    "issue_identifier": integer("Work item sequence number, e.g. 42 for ENG-42", 1, 2147483647),
})


def _tool(
    name: str,
    description: str,
    method: str,
    path: str,
    *,
    body: dict[str, dict[str, Any]] | None = None,
    query: dict[str, dict[str, Any]] | None = None,
    required: tuple[str, ...] = (),
    html: dict[str, str] | None = None,
    paginated: bool = False,
) -> ToolSpec:
    path_fields = {name: _PATH_FIELDS[name] for _, name, _, _ in Formatter().parse(path) if name and name != "workspace"}
    if path_fields.keys() & (body or {}).keys() or path_fields.keys() & (query or {}).keys():
        raise AssertionError("Arguments must belong to one of path, body or query")
    return ToolSpec(f"plane_{name}", description, method, path, path_fields, body or {}, query or {}, required,
                    html or {}, paginated)


def _collection(
    plural: str,
    singular: str,
    label: str,
    path: str,
    identifier: str,
    fields: dict[str, dict[str, Any]],
    required: tuple[str, ...],
    *,
    scope: str,
    html: dict[str, str] | None = None,
    list_query: dict[str, dict[str, Any]] | None = None,
) -> list[ToolSpec]:
    detail = path + "/{" + identifier + "}/"
    return [
        _tool(f"list_{plural}", f"List {label} records in the {scope}.", "GET", path + "/", query=list_query,
              paginated=True),
        _tool(f"get_{singular}", f"Get a {label} by UUID.", "GET", detail),
        _tool(f"create_{singular}", f"Create a {label} in the {scope}.", "POST", path + "/", body=fields,
              required=required, html=html),
        _tool(f"update_{singular}", f"Update only the specified {label} fields.", "PATCH", detail, body=fields,
              html=html),
    ]


_PROJECT_FIELDS = {
    "name": TITLE, "identifier": IDENTIFIER, "description": SHORT_TEXT,
    "module_view": boolean("Enable modules for this project"),
    "cycle_view": boolean("Enable cycles for this project"),
    "issue_views_view": boolean("Enable saved work item views for this project"),
    "page_view": boolean("Enable pages for this project"),
    "intake_view": boolean("Enable intake for this project"),
}
_ITEM_FIELDS = {
    "name": TITLE, "description_text": LONG_TEXT,
    "priority": choice("Priority", "urgent", "high", "medium", "low", "none"),
    "state": uid("Project workflow state UUID"),
    "parent": uid("Parent work item UUID in this project"),
    "assignees": ids("Replace assignees with these workspace user UUIDs; empty clears all"),
    "labels": ids("Replace labels with these label UUIDs; empty clears all"),
    "start_date": DATE, "target_date": DATE,
}
_CYCLE_FIELDS = {"name": TITLE, "description": SHORT_TEXT, "start_date": DATETIME, "end_date": DATETIME}
_MODULE_FIELDS = {
    "name": TITLE, "description": SHORT_TEXT, "start_date": DATE, "target_date": DATE,
    "status": choice("Module status", "backlog", "planned", "in-progress", "paused", "completed", "cancelled"),
}

_TOOL_LIST = [
    _tool("get_current_user", "Get the authenticated Plane account profile.", "GET", "/api/v1/users/me/"),
    _tool("list_workspace_members", "List basic workspace member identities for task assignment.", "GET",
          WORKSPACE + "/members-lite/", paginated=True),
    _tool("list_project_members", "List basic project member identities.", "GET",
          PROJECT + "/project-members-lite/", paginated=True),
    *_collection("projects", "project", "project", WORKSPACE + "/projects", "project_id", _PROJECT_FIELDS,
                 ("name", "identifier"), scope="workspace"),
    _tool("get_project_summary", "Get the project's aggregate work item and membership summary.", "GET",
          PROJECT + "/summary/"),
    *_collection("work_items", "work_item", "work item", PROJECT + "/work-items", "issue_id", _ITEM_FIELDS,
                 ("name",), scope="project", html={"description_text": "description_html"}),
    _tool("search_work_items", "Search names or identifiers in this workspace, optionally limited to one project.",
          "GET", WORKSPACE + "/work-items/search/", query={
              "search": string("Work item name or identifier to search for"),
              "project_id": uid("Optional project UUID to restrict the search"),
              "limit": integer("Maximum search results (default 20)", 1, MAX_PAGE_SIZE),
          }, required=("search",)),
    _tool("get_work_item_by_identifier", "Get a work item using its human-readable project and sequence identifiers.",
          "GET", WORKSPACE + "/work-items/{project_identifier}-{issue_identifier}/"),
    *_collection("work_item_comments", "work_item_comment", "work item comment", ITEM + "/comments", "comment_id",
                 {"comment_text": REQUIRED_TEXT}, ("comment_text",), scope="work item",
                 html={"comment_text": "comment_html"}),
    *_collection("work_item_links", "work_item_link", "work item link", ITEM + "/links", "link_id",
                 {"title": TITLE, "url": string("HTTP or HTTPS link", maximum=200, format="uri")}, ("url",),
                 scope="work item"),
    _tool("list_work_item_relations", "List blockers and other relations for a work item.", "GET", ITEM + "/relations/"),
    _tool("add_work_item_relations", "Add typed relations to other work item UUIDs.", "POST", ITEM + "/relations/",
          body={
              "relation_type": choice("Relation kind", "blocking", "blocked_by", "duplicate", "relates_to", "start_before",
                                      "start_after", "finish_before", "finish_after"),
              "issues": ids("Work item UUIDs to relate", minimum=1),
          }, required=("relation_type", "issues")),
    _tool("list_work_item_activities", "List change history for a work item.", "GET", ITEM + "/activities/",
          paginated=True),
    *_collection("states", "state", "workflow state", PROJECT + "/states", "state_id", {
        "name": TITLE, "color": COLOR, "description": SHORT_TEXT,
        "group": choice("State group", "backlog", "unstarted", "started", "completed", "cancelled"),
    }, ("name", "color"), scope="project"),
    *_collection("labels", "label", "label", PROJECT + "/labels", "label_id",
                 {"name": TITLE, "color": COLOR, "description": SHORT_TEXT}, ("name",), scope="project"),
    *_collection("cycles", "cycle", "cycle", PROJECT + "/cycles", "cycle_id", _CYCLE_FIELDS, ("name",), scope="project"),
    *_collection("modules", "module", "module", PROJECT + "/modules", "module_id", _MODULE_FIELDS, ("name",),
                 scope="project"),
    _tool("list_cycle_work_items", "List work items assigned to a cycle.", "GET",
          PROJECT + "/cycles/{cycle_id}/cycle-issues/", paginated=True),
    _tool("add_work_items_to_cycle", "Assign work items to this cycle; this may move them out of their current cycle.",
          "POST", PROJECT + "/cycles/{cycle_id}/cycle-issues/", body={"issues": ids("Work item UUIDs", minimum=1)},
          required=("issues",)),
    _tool("list_module_work_items", "List work items assigned to a module.", "GET",
          PROJECT + "/modules/{module_id}/module-issues/", paginated=True),
    _tool("add_work_items_to_module", "Add work items to a module.", "POST",
          PROJECT + "/modules/{module_id}/module-issues/", body={"issues": ids("Work item UUIDs", minimum=1)},
          required=("issues",)),
    *_collection("stickies", "sticky", "private note owned by the connected Plane account", WORKSPACE + "/stickies",
                 "sticky_id", {"name": TITLE, "description_text": LONG_TEXT}, ("name",), scope="workspace",
                 html={"description_text": "description_html"}, list_query={"query": string("Search note text")}),
]
TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in _TOOL_LIST}

assert len(TOOLS) == len(_TOOL_LIST), "Tool names must be unique"


# These routes are fork-specific. The bridge must not advertise them until an
# administrator explicitly enables drafts against a compatible backend.
_DRAFT_ROOT = WORKSPACE + "/draft-work-items"
_DRAFT_FIELDS = {
    "name": string("Draft title; may remain blank", maximum=255, minimum=0),
    "description_text": LONG_TEXT,
    "priority": _ITEM_FIELDS["priority"],
    "start_date": DATE,
    "target_date": DATE,
}
_DRAFT_DETAIL = _DRAFT_ROOT + "/{draft_id}/"
_DRAFT_LIST = [
    _tool("list_draft_work_items", "List the connected account's personal draft work items.", "GET",
          _DRAFT_ROOT + "/", paginated=True, query={"project_id": uid("Optional project UUID to filter drafts")}),
    _tool("get_draft_work_item", "Get a personal draft by UUID.", "GET", _DRAFT_DETAIL),
    _tool("create_draft_work_item", "Save a private personal draft without publishing a work item.", "POST",
          _DRAFT_ROOT + "/", body={**_DRAFT_FIELDS, "project_id": uid("Optional project UUID for this draft")},
          html={"description_text": "description_html"}),
    _tool("update_draft_work_item", "Update the specified fields on a personal draft.", "PATCH",
          _DRAFT_DETAIL, body=_DRAFT_FIELDS, html={"description_text": "description_html"}),
]
DRAFT_TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in _DRAFT_LIST}
