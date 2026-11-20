// Copyright (c) 2023-present Plane Software, Inc. and contributors
// SPDX-License-Identifier: AGPL-3.0-only
// See the LICENSE file for details.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sourceCodeUrl } from "../src/endpoints.ts";

test("source offer accepts only a full lowercase commit in the fixed repository", () => {
  const sha = "a".repeat(40);
  assert.equal(sourceCodeUrl(sha), `https://github.com/Lparksi/plane/tree/${sha}`);
  for (const value of [
    undefined,
    "",
    "A".repeat(40),
    "a".repeat(39),
    "a".repeat(41),
    `${sha}\n`,
    "https://example.com",
  ]) {
    assert.equal(sourceCodeUrl(value), undefined);
  }
});

test("sign-in screens provide a configured link or a neutral unavailable state", async () => {
  for (const path of [
    "../../../apps/web/components/account/auth-forms/auth-root.tsx",
    "../../../apps/admin/app/(all)/(home)/sign-in-form.tsx",
    "../../../apps/space/components/account/auth-forms/auth-root.tsx",
  ]) {
    const source = await readFile(new URL(path, import.meta.url), "utf8");
    assert.match(source, /SOURCE_CODE_URL\s*\?/);
    assert.match(source, /href=\{SOURCE_CODE_URL\}/);
    assert.match(source, /Source unavailable/);
    assert.doesNotMatch(source, /href="\/source\/"/);
  }
});
