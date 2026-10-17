// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const { validateSetup } = require("./owner-workspace.js");
const account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", session = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const owner = { account_id: account, session_id: session };
const empty = () => ({ schema_version: 1, account_id: account, session_id: session, observed_at_ms: 1000,
  sms_line_activation_available: true, pairings: [], devices: [], line_activations: [], truncated: false });
test("setup progress is bound to current account and session, with explicit incomplete inventory", () => {
  assert.equal(validateSetup(empty(), owner).pairings.length, 0);
  assert.equal(validateSetup({ ...empty(), truncated: true }, owner).truncated, true);
  for (const value of [{ ...empty(), account_id: session }, { ...empty(), session_id: account },
    { ...empty(), sms_line_activation_available: undefined }, { ...empty(), pairings: null }]) assert.throws(() => validateSetup(value, owner));
});
test("ambiguous public locators and unsafe activation generations cannot restore progress", () => {
  const phone = { device_id: account, setup_line_id: account, setup_opening_id: session,
    revoked: false, key_fingerprint: "A".repeat(64), line_activation_version: 2 };
  assert.equal(validateSetup({ ...empty(), devices: [phone] }, owner).devices.length, 1);
  assert.throws(() => validateSetup({ ...empty(), devices: [phone, phone] }, owner));
  assert.throws(() => validateSetup({ ...empty(), devices: [{ ...phone, line_activation_version: 3 }] }, owner));
  const activation = { line_id: account, challenge_id: account, device_id: account, opening_id: session,
    generation: "9223372036854775807", expires_at_ms: 2000, same_session: true, status: "awaiting_owner" };
  assert.equal(validateSetup({ ...empty(), line_activations: [activation] }, owner).line_activations.length, 1);
  assert.throws(() => validateSetup({ ...empty(), line_activations: [{ ...activation, generation: "9223372036854775808" }] }, owner));
});
