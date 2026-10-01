// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import { canonicalWorkflowAction, workflowActionDigest } from "../dist/workflow-decisions.js";
const vector = JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/workflow-action-01.json", import.meta.url)));
globalThis.crypto ??= webcrypto;

test("workflow binding matches the normative vector and changes for every field", async () => {
  assert.equal(await workflowActionDigest(vector.action), vector.binding_digest);
  for (const [field, value] of Object.entries(vector.field_edits)) {
    assert.notEqual(await workflowActionDigest({ ...vector.action, [field]: value }), vector.binding_digest);
  }
});
test("workflow binding rejects missing, unknown, unsafe and malformed fields", () => {
  const missing = { ...vector.action }; delete missing.window_id;
  for (const action of [missing, { ...vector.action, approved: true },
    { ...vector.action, revision: true }, { ...vector.action, revision: 1.5 },
    { ...vector.action, revision: Number.MAX_SAFE_INTEGER + 1 },
    { ...vector.action, recipient_id: "\u00e9" },
    { ...vector.action, content_digest: "AB".repeat(32) },
    { ...vector.action, expires_at: vector.action.not_before }]) {
    assert.throws(() => canonicalWorkflowAction(action));
  }
});
test("workflow binding snapshots mutable input before hashing and escapes DEL", async () => {
  const action = { ...vector.action };
  const pending = workflowActionDigest(action);
  action.recipient_id = "changed-after-hash";
  assert.equal(await pending, vector.binding_digest);
  const bytes = canonicalWorkflowAction({ ...vector.action, window_id: "window\x7f" });
  assert.match(new TextDecoder().decode(bytes), /window\\u007f/u);
});
