// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const test = require("node:test");
const testPassword = randomBytes(20).toString("hex");

function response(status, body = {}) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  const bytes = new TextEncoder().encode(raw);
  return {
    status, ok: status >= 200 && status < 300,
    headers: { get: (name) => name === "content-type" ? "application/json; charset=utf-8" : null },
    body: { getReader: () => {
      let read = false;
      return { read: async () => read ? { done: true } : (read = true, { done: false, value: bytes }), cancel: async () => {} };
    } },
    json: async () => {
      if (status === 202 || status === 204) throw new Error("empty response has no JSON body");
      return body;
    },
  };
}

const ownerSession = { account_id: "11111111-1111-4111-8111-111111111111", user_id: "22222222-2222-4222-8222-222222222222", session_id: "33333333-3333-4333-8333-333333333333", role: "owner" };

async function accountPage({ signedIn = false, cookie = "__Host-zrotext_csrf=ztc_synthetic", session = ownerSession, handler } = {}) {
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, value: "", children: [], listeners: {},
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    removeAttribute(name) { delete this[name]; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  const calls = [];
  const replies = new Map();
  const windowListeners = {};
  let mfaEnabled = false;
  const fetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (replies.has(path)) return replies.get(path);
    if (handler) {
      const handled = await handler(path, options);
      if (handled !== undefined) return handled;
    }
    if (path === "/v1/auth/session") return response(signedIn ? 200 : 401, session);
    if (path === "/v1/auth/mfa") return response(200, { enabled: mfaEnabled, pending: false });
    if (path === "/v1/auth/register") return response(202);
    if (path === "/v1/auth/verify-email") return response(204);
    if (path === "/v1/auth/resend-verification") return response(202);
    if (path === "/v1/auth/mfa/enroll") return response(200, {
      secret_base32: "ABCDEFGHIJKLMNOP234567", provisioning_uri: "otpauth://totp/ZROtext?secret=ABCDEFGHIJKLMNOP234567",
    });
    if (path === "/v1/auth/mfa/confirm") {
      mfaEnabled = true;
      return response(200, { recovery_codes: ["first-recovery", "second-recovery"] });
    }
    if (path === "/v1/auth/mfa/disable") {
      mfaEnabled = false;
      return response(204);
    }
    throw new Error(`Unexpected request: ${path}`);
  };
  globalThis.document = { cookie, getElementById: element, createElement: makeElement };
  globalThis.window = { addEventListener(name, listener) { windowListeners[name] = listener; } };
  globalThis.fetch = fetch;
  const blobs = [];
  const revoked = [];
  URL.createObjectURL = (blob) => { blobs.push(blob); return `blob:synthetic-${blobs.length}`; };
  URL.revokeObjectURL = (url) => revoked.push(url);
  delete require.cache[require.resolve("./account.js")];
  require("./account.js");
  await new Promise(setImmediate);
  return { element, calls, replies, windowListeners, blobs, revoked };
}

async function submit(element) {
  let prevented = false;
  await element.listeners.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
}

test("invited registration sends credentials in JSON and invite only in a header", async () => {
  const { element, calls } = await accountPage();
  element("register-email").value = "invited@example.test";
  element("register-password").value = testPassword;
  element("register-token").value = " address-bound-token ";
  await submit(element("register-form"));
  const call = calls.at(-1);
  assert.equal(call.path, "/v1/auth/register");
  assert.deepEqual(JSON.parse(call.options.body), {
    email: "invited@example.test", password: testPassword,
  });
  assert.equal(call.options.headers["x-zrotext-registration-token"], "address-bound-token");
  assert.equal(call.options.headers["x-zrotext-csrf"], undefined);
  assert.equal(call.options.redirect, "error");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(element("register-password").value, "");
  assert.equal(element("register-token").value, "");
  assert.match(element("register-status").textContent, /If registration is open/);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("verification and resend never put a code or password in a URL", async () => {
  const { element, calls, replies } = await accountPage();
  element("verification-code").value = " code from email ";
  element("verify-password").value = testPassword;
  await submit(element("verify-form"));
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), {
    token: "code from email", password: testPassword,
  });
  assert.equal(element("verification-code").value, "");
  assert.equal(element("verify-password").value, "");
  element("resend-email").value = "owner@example.test";
  element("resend-password").value = testPassword;
  await submit(element("resend-form"));
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), {
    email: "owner@example.test", password: testPassword,
  });
  assert.equal(element("resend-password").value, "");
  replies.set("/v1/auth/verify-email", response(400));
  element("verification-code").value = "wrong-code";
  element("verify-password").value = testPassword;
  await submit(element("verify-form"));
  assert.match(element("verify-status").textContent, /Check the entered values/);
  assert.equal(element("verify-password").value, "");
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("MFA setup requires CSRF and clears one-time secrets", async () => {
  const { element, calls, windowListeners } = await accountPage({ signedIn: true });
  assert.equal(element("mfa-section").hidden, false);
  element("mfa-enroll-password").value = testPassword;
  await submit(element("mfa-enroll-form"));
  assert.equal(calls.at(-1).path, "/v1/auth/mfa/enroll");
  assert.equal(calls.at(-1).options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.equal(element("mfa-enroll-password").value, "");
  assert.equal(element("mfa-secret-panel").hidden, false);
  assert.equal(element("mfa-confirm-form").hidden, false);
  element("mfa-confirm-code").value = "123456";
  await submit(element("mfa-confirm-form"));
  assert.deepEqual(JSON.parse(calls.at(-2).options.body), { code: "123456" });
  assert.equal(element("mfa-secret").textContent, "");
  assert.equal(element("recovery-panel").hidden, false);
  assert.deepEqual(element("recovery-codes").children.map((item) => item.textContent),
    ["first-recovery", "second-recovery"]);
  windowListeners.pagehide();
  assert.deepEqual(element("recovery-codes").children, []);
  assert.equal(element("recovery-panel").hidden, true);
  assert.equal(element("mfa-provisioning-uri").textContent, "");
});

test("MFA disable uses password and code in JSON and handles missing CSRF", async () => {
  const page = await accountPage({ signedIn: true });
  page.element("mfa-enroll-password").value = testPassword;
  await submit(page.element("mfa-enroll-form"));
  page.element("mfa-confirm-code").value = "123456";
  await submit(page.element("mfa-confirm-form"));
  page.element("mfa-disable-password").value = testPassword;
  page.element("mfa-disable-code").value = "unused-recovery";
  await submit(page.element("mfa-disable-form"));
  const call = page.calls.at(-2);
  assert.equal(call.path, "/v1/auth/mfa/disable");
  assert.deepEqual(JSON.parse(call.options.body), {
    password: testPassword, code: "unused-recovery",
  });
  assert.equal(page.element("mfa-disable-password").value, "");
  assert.equal(page.element("mfa-disable-code").value, "");
  assert.equal(page.element("mfa-disable-form").hidden, true);

  const noCsrf = await accountPage({ signedIn: true, cookie: "" });
  const count = noCsrf.calls.length;
  noCsrf.element("mfa-enroll-password").value = testPassword;
  await submit(noCsrf.element("mfa-enroll-form"));
  assert.equal(noCsrf.calls.length, count);
  assert.match(noCsrf.element("mfa-status").textContent, /Sign in before managing MFA/);
});

test("a late enrollment response cannot restore a secret after leaving", async () => {
  const { element, replies, windowListeners } = await accountPage({ signedIn: true });
  let release;
  replies.set("/v1/auth/mfa/enroll", new Promise((resolve) => { release = resolve; }));
  element("mfa-enroll-password").value = testPassword;
  const pending = submit(element("mfa-enroll-form"));
  windowListeners.pagehide();
  release(response(200, {
    secret_base32: "ABCDEFGHIJKLMNOP234567",
    provisioning_uri: "otpauth://totp/ZROtext?secret=ABCDEFGHIJKLMNOP234567",
  }));
  await pending;
  assert.equal(element("mfa-secret").textContent, "");
  assert.equal(element("mfa-secret-panel").hidden, true);
  assert.equal(element("mfa-confirm-form").hidden, true);
});

function exportPage() {
  const page = () => ({ items: [], next_cursor: null });
  const pages = (...keys) => Object.fromEntries(keys.map((key) => [key, page()]));
  return {
    original_replies: page(), provider_receipts: page(),
    opening_capacity: pages("openings", "offers", "allocations", "requests"),
    provider_configurations: pages("heads", "versions", "mutations"),
    contact_reader_issuance: { state: null, pending: [], receipts: [], pending_next_cursor: null, receipt_next_cursor: null },
    sealed_line_setup: { installed: false, registrations: [], exchanges: [] },
    sealed_event_deliveries: page(),
    execution_inventory: { records: [], truncated: false, next_cursor: null },
    workflow_schedule: pages("policies", "series", "occurrences", "audit"),
    workflow_integrations: pages("grants", "envelopes", "access"),
    managed_reader_grants: pages("events", "selections", "versions", "grants", "policies", "readers"),
    invoice_billing: { entitlement: null, periods: [], usage: [], audit: [], periods_next: null, usage_next: null, audit_next: null },
    invoice_observations: { observations: [], next: null },
    encrypted_templates: pages("templates", "versions"),
    workflow_context: pages("contexts", "versions", "exceptions", "audit"),
    confirmation_inventory: { records: [], truncated: false, next_cursor: null },
    agent_grants: { grants: [], truncated: false, next_cursor: null },
    workflow_decisions: pages("actions", "versions", "mutations", "correlations", "message_links", "routines", "context_fences"),
    conversation_inventory: { consent: null, intervals: [], intervals_truncated: false, intervals_next_cursor: null, sealed_events: [], sealed_events_truncated: false, sealed_events_next_cursor: null },
    generated_at_ms: 1, account: { ...ownerSession }, devices: [], contacts: [], contacts_truncated: false, contacts_next_cursor: null,
    messages: [], messages_truncated: false, next_cursor: null,
  };
}

async function click(page, id) { await page.element(id).listeners.click(); }

async function reviewErasure(page) {
  await click(page, "erasure-review");
  page.element("erasure-confirm").checked = true;
  page.element("erasure-password").value = testPassword;
  page.element("erasure-code").value = " synthetic-factor ";
}

function erasureReceipt() {
  return { account_id: ownerSession.account_id, deleted: [{ table: "accounts", rows: 1 }, { table: "observer_users", rows: 0 }],
    retained: [{ table: "auth_abuse_counters", rows: null, reason: "Shared keyed request budgets retain their own lifecycle." },
      { table: "payload_profile_account_anchors", rows: 1, reason: "Pseudonymous account ID, deleted state and version counter prevent identity reuse." }],
    statement: "Account-local erasure committed. External copies and backups retain separate lifecycles." };
}

test("data controls are owner-only and require the captured CSRF cookie", async () => {
  for (const session of [{ ...ownerSession, role: "observer" }, {}, { ...ownerSession, account_id: "bad" }]) {
    const page = await accountPage({ signedIn: true, session });
    assert.equal(page.element("data-section").hidden, true);
    await click(page, "export-start");
    await click(page, "erasure-review");
    assert.ok(page.calls.every(({ path }) => !path.startsWith("/v1/owner/")));
  }
  const page = await accountPage({ signedIn: true, cookie: "" });
  await click(page, "export-start");
  await click(page, "erasure-review");
  assert.ok(page.calls.every(({ path }) => !path.startsWith("/v1/owner/")));
});

test("takeout exhausts six reply sections and independent late pages across bounded parts", async () => {
  const queries = [];
  const raws = [];
  const page = await accountPage({ signedIn: true, handler(path, options) {
    if (!path.startsWith("/v1/owner/export?")) return;
    const query = new URLSearchParams(path.split("?")[1]);
    queries.push(query);
    assert.equal(options.headers["x-zrotext-csrf"], "ztc_synthetic");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    const data = exportPage();
    if (queries.length < 10) data.workflow_decisions.context_fences.next_cursor = `synthetic:${queries.length}`;
    if (queries.length === 1) {
      data.messages_truncated = true;
      data.next_cursor = "44444444-4444-4444-8444-444444444444";
      data.contacts_truncated = true;
      data.contacts_next_cursor = "55555555-5555-4555-8555-555555555555";
    }
    // This number is deliberately outside JS's exact Number range; raw download
    // fidelity is checked byte-for-byte rather than parsing and rounding it.
    const raw = JSON.stringify(data).replace('"messages":[]', '"messages":[{"opaque_counter":9223372036854775807,"text":"escaped \\\" quote and \\u2603"}]');
    raws.push(raw);
    return response(200, raw);
  } });
  await click(page, "export-start");
  assert.equal(queries.length, 8);
  assert.equal(page.element("export-continue").hidden, false);
  const first = await page.blobs[0].text();
  assert.match(first, /"complete":false/);
  assert.ok(raws.slice(0, 8).every((raw) => first.includes(raw)));
  assert.equal(queries[1].get("before"), "44444444-4444-4444-8444-444444444444");
  assert.equal(queries[1].get("contacts_before"), "55555555-5555-4555-8555-555555555555");
  await click(page, "export-continue");
  assert.equal(queries.length, 10);
  assert.equal(page.element("export-continue").hidden, true);
  assert.match(page.element("export-status").textContent, /All exposed API pages retrieved/);
  assert.deepEqual([...new Set(queries.map((q) => q.get("original_reply_section")))],
    ["grants", "requests", "consumptions", "sources", "access", "manifests"]);
  assert.match(await page.blobs[1].text(), /"complete":true/);
  assert.equal(page.revoked.length, 1);
  await click(page, "export-clear");
  assert.equal(page.revoked.length, 2);
  assert.equal(page.element("export-download").hidden, true);
});

test("takeout routes every server cursor independently and preserves exact positive i64 audit cursors", async () => {
  const paths = {
    before: "next_cursor", contacts_before: "contacts_next_cursor", sealed_before: "conversation_inventory.sealed_events_next_cursor",
    interval_before: "conversation_inventory.intervals_next_cursor", confirmation_before: "confirmation_inventory.next_cursor",
    execution_before: "execution_inventory.next_cursor", agent_before: "agent_grants.next_cursor", original_reply_before: "original_replies.next_cursor",
    provider_receipts_after: "provider_receipts.next_cursor", contact_reader_pending_after: "contact_reader_issuance.pending_next_cursor",
    contact_reader_receipts_after: "contact_reader_issuance.receipt_next_cursor", sealed_deliveries_after: "sealed_event_deliveries.next_cursor",
    invoice_observations_after: "invoice_observations.next", invoice_periods_after: "invoice_billing.periods_next", invoice_usage_after: "invoice_billing.usage_next",
    invoice_audit_after: "invoice_billing.audit_next", openings_after: "opening_capacity.openings.next_cursor", opening_offers_after: "opening_capacity.offers.next_cursor",
    opening_allocations_after: "opening_capacity.allocations.next_cursor", opening_requests_after: "opening_capacity.requests.next_cursor",
    provider_configurations_after: "provider_configurations.heads.next_cursor", provider_configuration_versions_after: "provider_configurations.versions.next_cursor",
    provider_configuration_mutations_after: "provider_configurations.mutations.next_cursor", templates_after: "encrypted_templates.templates.next_cursor",
    template_versions_after: "encrypted_templates.versions.next_cursor", workflow_grants_before: "workflow_integrations.grants.next_cursor",
    workflow_envelopes_before: "workflow_integrations.envelopes.next_cursor", workflow_access_before: "workflow_integrations.access.next_cursor",
    workflow_contexts_before: "workflow_context.contexts.next_cursor", workflow_versions_before: "workflow_context.versions.next_cursor",
    workflow_exceptions_before: "workflow_context.exceptions.next_cursor", workflow_audit_before: "workflow_context.audit.next_cursor",
    workflow_actions_before: "workflow_decisions.actions.next_cursor", workflow_action_versions_before: "workflow_decisions.versions.next_cursor",
    workflow_action_mutations_before: "workflow_decisions.mutations.next_cursor", workflow_correlations_before: "workflow_decisions.correlations.next_cursor",
    workflow_message_links_before: "workflow_decisions.message_links.next_cursor", workflow_routines_before: "workflow_decisions.routines.next_cursor",
    workflow_context_fences_before: "workflow_decisions.context_fences.next_cursor", schedule_policies_before: "workflow_schedule.policies.next_cursor",
    schedule_series_before: "workflow_schedule.series.next_cursor", schedule_occurrences_before: "workflow_schedule.occurrences.next_cursor",
    schedule_audit_before: "workflow_schedule.audit.next_cursor", managed_events_after: "managed_reader_grants.events.next_cursor",
    managed_selections_after: "managed_reader_grants.selections.next_cursor", managed_versions_after: "managed_reader_grants.versions.next_cursor",
    managed_grants_after: "managed_reader_grants.grants.next_cursor", managed_policies_after: "managed_reader_grants.policies.next_cursor",
    managed_readers_after: "managed_reader_grants.readers.next_cursor",
  };
  assert.equal(Object.keys(paths).length, 49);
  for (const integer of ["9007199254740992", "9223372036854775807"]) {
    let number = 0;
    let second;
    const page = await accountPage({ signedIn: true, handler(path) {
      if (!path.startsWith("/v1/owner/export?")) return;
      number += 1;
      const value = exportPage();
      if (number === 1) {
        for (const route of Object.values(paths)) {
          const keys = route.split("."); const last = keys.pop();
          keys.reduce((v, key) => v[key], value)[last] = "44444444-4444-4444-8444-444444444444";
        }
        for (const object of [value, value.conversation_inventory, value.confirmation_inventory, value.execution_inventory, value.agent_grants]) {
          for (const key of Object.keys(object)) if (key.endsWith("truncated")) object[key] = true;
        }
        value.invoice_billing.audit_next = "integer-placeholder";
      } else if (number === 2) second = new URLSearchParams(path.split("?")[1]);
      return response(200, JSON.stringify(value).replace('"integer-placeholder"', integer));
    } });
    await click(page, "export-start");
    for (const name of Object.keys(paths)) assert.equal(second.get(name), name === "invoice_audit_after" ? integer : "44444444-4444-4444-8444-444444444444", name);
    assert.match(page.element("export-status").textContent, /All exposed API pages retrieved/);
  }
});

test("unknown paging, bad cursors and noncanonical JSON never produce an export completion", async () => {
  const cases = [
    (v) => { v.future_family = {}; },
    (v) => { v.workflow_context.future_page = { items: [], next_cursor: null }; },
    (v) => { delete v.managed_reader_grants; },
    (v) => { v.invoice_billing.audit_next = "9223372036854775807"; },
    (v) => { v.invoice_billing.audit_next = -1; },
    (v) => { v.next_cursor = "invalid"; v.messages_truncated = true; },
    (v) => { v.messages_truncated = true; },
    (v) => { v.account.account_id = "99999999-9999-4999-8999-999999999999"; },
  ];
  const raws = [
    (s) => s.replace('"audit_next":null', '"audit_next":9223372036854775808'),
    (s) => s.replace('"audit_next":null', '"audit_next":01'),
    (s) => s.replace('"audit_next":null', '"audit_next":1e999'),
    (s) => s.replace('"audit_next":null', '"audit_next":1e0'),
    (s) => s.replace('"audit_next":null', '"audit_next":1.00000000000000000001'),
    (s) => s + " trailing",
    (s) => s.replace('"next_cursor":null', '"next_cursor":null,"next_\\u0063ursor":null'),
    (s) => s.replace('"account_id":', '"account_id":"99999999-9999-4999-8999-999999999999","account_id":'),
  ];
  for (const [edit, isRaw] of cases.map((edit) => [edit, false]).concat(raws.map((edit) => [edit, true]))) {
    const page = await accountPage({ signedIn: true, handler(path) {
      if (!path.startsWith("/v1/owner/export?")) return;
      const value = exportPage();
      if (isRaw) return response(200, edit(JSON.stringify(value)));
      edit(value);
      return response(200, value);
    } });
    await click(page, "export-start");
    assert.doesNotMatch(page.element("export-status").textContent, /All exposed API pages retrieved/);
    assert.equal(page.blobs.length, 0);
  }
});

test("repeated cursors interrupt takeout while preserving the prior raw page and continuation", async () => {
  const page = await accountPage({ signedIn: true, handler(path) {
    if (!path.startsWith("/v1/owner/export?")) return;
    const value = exportPage(); value.original_replies.next_cursor = "44444444-4444-4444-8444-444444444444";
    return response(200, value);
  } });
  await click(page, "export-start");
  assert.match(page.element("export-status").textContent, /Repeated export cursor/);
  const part = JSON.parse(await page.blobs[0].text());
  assert.equal(part.pages.length, 1);
  assert.equal(part.complete, false);
  assert.equal(part.interrupted, true);
  assert.equal(part.next_query.original_reply_before, "44444444-4444-4444-8444-444444444444");
});

test("transport interruption retains accepted pages and continues without replaying their request", async () => {
  let requests = 0;
  const seen = [];
  const page = await accountPage({ signedIn: true, handler(path) {
    if (!path.startsWith("/v1/owner/export?")) return;
    requests += 1; seen.push(path);
    if (requests === 2) throw new Error("synthetic connection interruption");
    const value = exportPage();
    if (requests === 1) value.original_replies.next_cursor = "44444444-4444-4444-8444-444444444444";
    return response(200, value);
  } });
  await click(page, "export-start");
  assert.match(page.element("export-status").textContent, /incomplete/);
  assert.equal(JSON.parse(await page.blobs[0].text()).pages.length, 1);
  await click(page, "export-continue");
  assert.equal(seen[1], seen[2]);
  assert.match(page.element("export-status").textContent, /All exposed API pages retrieved/);
});

test("response streams are bounded without Content-Length, cancelled and strict UTF-8", async () => {
  for (const chunk of [new Uint8Array(8 * 1024 * 1024 + 1), new Uint8Array([0xc3, 0x28])]) {
    let cancelled = false;
    let signal;
    const page = await accountPage({ signedIn: true, handler(path, options) {
      if (!path.startsWith("/v1/owner/export?")) return;
      signal = options.signal;
      return { status: 200, headers: { get: () => "application/json" }, body: { getReader() {
        let once = false;
        return { read: async () => once ? { done: true } : (once = true, { value: chunk, done: false }), cancel: async () => { cancelled = true; } };
      } } };
    } });
    await click(page, "export-start");
    assert.equal(cancelled, true);
    assert.equal(signal.aborted, true);
    assert.equal(page.blobs.length, 0);
    assert.match(page.element("export-status").textContent, /incomplete/);
  }
});

test("a changed session stops export and erasure before private API requests", async () => {
  const page = await accountPage({ signedIn: true });
  page.replies.set("/v1/auth/session", response(200, { ...ownerSession, session_id: "44444444-4444-4444-8444-444444444444" }));
  await click(page, "export-start");
  await click(page, "erasure-review");
  assert.ok(page.calls.every(({ path }) => !path.startsWith("/v1/owner/")));
  assert.equal(page.element("data-section").hidden, true);
});

test("late export cannot recreate a download after page exit or cookie replacement", async () => {
  for (const change of [() => { document.cookie = "__Host-zrotext_csrf=ztc_changed"; }, (page) => page.windowListeners.pagehide()]) {
    let release;
    const page = await accountPage({ signedIn: true, handler(path) {
      if (path.startsWith("/v1/owner/export?")) return new Promise((resolve) => { release = resolve; });
    } });
    const pending = click(page, "export-start");
    while (!release) await new Promise(setImmediate);
    change(page); release(response(200, exportPage())); await pending;
    assert.equal(page.blobs.length, 0);
    assert.equal(page.element("export-download").hidden, true);
  }
});

test("erasure needs explicit review and confirmation and cancels without sending", async () => {
  const page = await accountPage({ signedIn: true });
  page.element("erasure-password").value = testPassword;
  await submit(page.element("erasure-form"));
  assert.ok(page.calls.every(({ path }) => path !== "/v1/owner/erasure"));
  await reviewErasure(page);
  await click(page, "erasure-cancel");
  assert.equal(page.element("erasure-password").value, "");
  assert.equal(page.element("erasure-code").value, "");
  assert.equal(page.element("erasure-confirm").checked, false);
  assert.equal(page.element("erasure-form").hidden, true);
  assert.ok(page.calls.every(({ path }) => path !== "/v1/owner/erasure"));
});

test("erasure posts once with JSON password/factor and displays exact scoped deletion and retention receipt", async () => {
  let release;
  const receipt = erasureReceipt();
  const page = await accountPage({ signedIn: true, handler(path) {
    if (path === "/v1/owner/erasure") return new Promise((resolve) => { release = resolve; });
  } });
  await reviewErasure(page);
  const pending = submit(page.element("erasure-form"));
  while (!release) await new Promise(setImmediate);
  await submit(page.element("erasure-form"));
  const calls = page.calls.filter(({ path }) => path === "/v1/owner/erasure");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.equal(calls[0].options.credentials, "same-origin");
  assert.equal(calls[0].options.redirect, "error");
  assert.deepEqual(JSON.parse(calls[0].options.body), { current_password: testPassword, code: "synthetic-factor" });
  assert.equal(page.element("erasure-password").value, "");
  release(response(200, receipt)); await pending;
  assert.match(page.element("erasure-status").textContent, /server confirmed erasure/);
  assert.equal(page.element("erasure-result").textContent, JSON.stringify(receipt));
  assert.equal(page.element("export-start").disabled, true);
  assert.equal(page.element("erasure-code").value, "");
  await click(page, "erasure-review"); await submit(page.element("erasure-form"));
  assert.equal(page.calls.filter(({ path }) => path === "/v1/owner/erasure").length, 1);
});

test("erasure blockers render server result as text and require a fresh deliberate review", async () => {
  const blocked = { code: "erasure_blocked", blocked: [{ table: "phone_lines", rows: 1 }], statement: "Nothing was deleted. <synthetic>" };
  const page = await accountPage({ signedIn: true, handler(path) { if (path === "/v1/owner/erasure") return response(409, blocked); } });
  await reviewErasure(page); await submit(page.element("erasure-form"));
  assert.match(page.element("erasure-status").textContent, /nothing was deleted/);
  assert.equal(page.element("erasure-result").textContent, JSON.stringify(blocked));
  assert.equal(page.element("erasure-form").hidden, true);
  await submit(page.element("erasure-form"));
  assert.equal(page.calls.filter(({ path }) => path === "/v1/owner/erasure").length, 1);
});

test("uncertain erasure outcomes stay UNKNOWN with no retry or success inference", async () => {
  const cases = [
    () => { throw new Error("synthetic lost response"); },
    () => response(204), () => response(503, { code: "unavailable" }), () => response(200, {}),
    () => response(200, { ...erasureReceipt(), account_id: "99999999-9999-4999-8999-999999999999" }),
    () => response(200, { ...erasureReceipt(), deleted: [{ table: "accounts", rows: 9007199254740992 }] }),
    () => response(200, { ...erasureReceipt(), retained: [{ table: "auth_abuse_counters", rows: 9007199254740992, reason: "synthetic" }] }),
    () => response(409, { code: "erasure_blocked", blocked: [], statement: "invalid blockers" }),
    () => response(200, JSON.stringify(erasureReceipt()).replace('"rows":1', '"rows":1.00000000000000000001')),
    () => response(200, JSON.stringify(erasureReceipt()).replace('"rows":1', '"rows":1e0')),
  ];
  for (const reply of cases) {
    const page = await accountPage({ signedIn: true, handler(path) { if (path === "/v1/owner/erasure") return reply(); } });
    await reviewErasure(page); await submit(page.element("erasure-form"));
    assert.match(page.element("erasure-status").textContent, /UNKNOWN.*Do not repeat/);
    assert.equal(page.element("erasure-password").value, "");
    assert.equal(page.element("erasure-code").value, "");
    await click(page, "erasure-review"); await submit(page.element("erasure-form"));
    assert.equal(page.calls.filter(({ path }) => path === "/v1/owner/erasure").length, 1);
  }
});

test("known erasure refusals never claim deletion or automatically repeat the mutation", async () => {
  for (const status of [400, 401, 403, 429, 501]) {
    const page = await accountPage({ signedIn: true, handler(path) { if (path === "/v1/owner/erasure") return response(status, { code: "refused" }); } });
    await reviewErasure(page); await submit(page.element("erasure-form"));
    assert.match(page.element("erasure-status").textContent, /refused.*no erasure confirmation/);
    assert.doesNotMatch(page.element("erasure-status").textContent, /confirmed erasure/);
    assert.equal(page.element("erasure-password").value, "");
    assert.equal(page.calls.filter(({ path }) => path === "/v1/owner/erasure").length, 1);
  }
});

test("serialized takeout parts include wrapper bytes within the advertised limit", async () => {
  let count = 0;
  const page = await accountPage({ signedIn: true, handler(path) {
    if (!path.startsWith("/v1/owner/export?")) return;
    count += 1;
    const value = exportPage();
    value.messages = [{ synthetic_padding: "x".repeat(7 * 1024 * 1024) }];
    return response(200, value);
  } });
  await click(page, "export-start");
  assert.equal(count, 4);
  assert.equal(page.blobs.length, 1);
  assert.ok(page.blobs[0].size < 32 * 1024 * 1024);
  assert.equal(page.element("export-continue").hidden, false);
  assert.match(page.element("export-status").textContent, /incomplete/);
});

test("large numeric tokens, invalid string escapes and unexpected collection shapes refuse completion", async () => {
  for (const edit of [
    (s) => s.replace('"audit_next":null', `"audit_next":${"9".repeat(129)}`),
    (s) => s.replace('"messages":[]', '"messages":["bad\\q"]'),
    (s) => s.replace('"messages":[]', '"messages":["unterminated]'),
    (s) => s.replace('"messages":[]', '"messages":{}'),
    (s) => s.replace('"original_replies":{"items":[]', '"original_replies":{"items":false'),
    (s) => "\ufeff" + s,
  ]) {
    const page = await accountPage({ signedIn: true, handler(path) {
      if (path.startsWith("/v1/owner/export?")) return response(200, edit(JSON.stringify(exportPage())));
    } });
    await click(page, "export-start");
    assert.equal(page.blobs.length, 0);
    assert.match(page.element("export-status").textContent, /incomplete/);
  }
});

test("erasure review is bound to its original session and CSRF proof", async () => {
  for (const change of [
    (page) => page.replies.set("/v1/auth/session", response(200, { ...ownerSession, account_id: "44444444-4444-4444-8444-444444444444" })),
    () => { document.cookie = "__Host-zrotext_csrf=ztc_changed"; },
  ]) {
    const page = await accountPage({ signedIn: true });
    await reviewErasure(page); change(page);
    await submit(page.element("erasure-form"));
    assert.ok(page.calls.every(({ path }) => path !== "/v1/owner/erasure"));
    assert.equal(page.element("erasure-password").value, "");
    assert.equal(page.element("erasure-code").value, "");
  }
});

test("page exit fences late erasure receipt and BFCache return retains the no-retry hold", async () => {
  let release;
  const page = await accountPage({ signedIn: true, handler(path) {
    if (path === "/v1/owner/erasure") return new Promise((resolve) => { release = resolve; });
  } });
  await reviewErasure(page);
  const pending = submit(page.element("erasure-form"));
  while (!release) await new Promise(setImmediate);
  page.windowListeners.pagehide();
  release(response(200, erasureReceipt())); await pending;
  assert.equal(page.element("erasure-result").textContent, "");
  assert.equal(page.element("erasure-result").hidden, true);
  page.windowListeners.pageshow({ persisted: true });
  await new Promise(setImmediate);
  assert.equal(page.element("data-section").hidden, false);
  assert.match(page.element("erasure-status").textContent, /UNKNOWN.*Do not repeat/);
  assert.equal(page.element("erasure-review").disabled, true);
  await reviewErasure(page); await submit(page.element("erasure-form"));
  assert.equal(page.calls.filter(({ path }) => path === "/v1/owner/erasure").length, 1);
});
