// Copyright (c) 2023-present Plane Software, Inc. and contributors
// SPDX-License-Identifier: AGPL-3.0-only
// See the LICENSE file for details.
import assert from "node:assert/strict";
import test from "node:test";
import { internalApiOrigin } from "../app/utils/api-origin.server.ts";

test("accepts only an explicitly configured HTTP(S) origin", () => {
  assert.equal(internalApiOrigin("http://api:8000"), "http://api:8000");
  assert.equal(internalApiOrigin("https://example.test/"), "https://example.test");
  for (const value of [
    "",
    "/api",
    "file:///tmp/a",
    "http://user:pass@api",
    "http://api/path",
    "http://api/?q=1",
    "http://api/#x",
  ]) {
    assert.equal(internalApiOrigin(value), null);
  }
});
