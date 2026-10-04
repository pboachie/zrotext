// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { create, billingView } = require("./hosted-onboarding.js");

const owner = Object.freeze({ role: "owner", account_id: "00000000-0000-4000-8000-000000000001",
  session_id: "00000000-0000-4000-8000-000000000002" });
const billing = (changes = {}) => ({ mode: "test", customerBound: false,
  pendingReconciliations: 0, reviewReconciliations: 0, reviewRiskEvents: 0,
  nonterminalSubscriptions: 0, projectedEntitlement: { reason: null, outboundLimit: null,
    deviceCap: null, paymentHold: false }, ...changes });
const active = () => billing({ customerBound: true, nonterminalSubscriptions: 1,
  projectedEntitlement: { reason: "active", outboundLimit: 19, deviceCap: 1, paymentHold: false } });
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
  json: async () => body });
const available = (changes = {}) => ({ schema_version: 1, deployment: "hosted", registration: "open",
  billing: "test", checkout_available: true, plan_catalog_available: true, ...changes });

function fixture(overrides = {}) {
  const calls = [];
  let snapshot = billing();
  const routes = {
    "/v1/service/availability": () => response(available()),
    "/v1/auth/register": () => response(null, 202),
    "/v1/auth/resend-verification": () => response(null, 202),
    "/v1/auth/verify-email": () => response(null, 204),
    "/v1/auth/login": () => response(null, 204),
    "/v1/auth/login/mfa": () => response(null, 204),
    "/v1/auth/session": () => response(owner),
    "/v1/billing/status": () => response(snapshot),
    "/v1/billing/checkout": () => response({ url: "https://checkout.stripe.com/c/pay/test_fixture" }),
    "/v1/billing/portal": () => response({ url: "https://billing.stripe.com/p/session/test_fixture" }),
    ...overrides,
  };
  const controller = create({ cookie: () => "__Host-zrotext_csrf=synthetic-csrf",
    randomUUID: () => "00000000-0000-4000-8000-000000000003",
    fetch: async (path, init) => {
      calls.push({ path, ...init });
      assert.equal(init.credentials, "same-origin");
      assert.equal(init.cache, "no-store");
      assert.equal(init.redirect, "error");
      assert.ok(init.signal);
      assert.ok(routes[path], `Unexpected endpoint: ${path}`);
      return routes[path](init);
    } });
  return { controller, calls, snapshot: (next) => { snapshot = next; } };
}

test("hosted signup, verification, sign-in and TEST checkout wait for local reconciliation", async () => {
  const f = fixture();
  assert.equal(f.controller.select("hosted").phase, "availability_unknown");
  await f.controller.register("owner@example.test", "synthetic-password", "synthetic-invite");
  assert.equal(f.controller.view().phase, "verification_requested");
  assert.match(f.controller.view().message, /If registration is open/);
  await f.controller.resend("owner@example.test", "synthetic-password");
  await f.controller.verify("synthetic-code", "synthetic-password");
  assert.equal(f.controller.view().phase, "sign_in");
  await f.controller.login("owner@example.test", "synthetic-password");
  assert.equal(f.controller.view().checkoutAvailable, true);
  assert.equal(await f.controller.handoff("checkout"), "https://checkout.stripe.com/c/pay/test_fixture");
  assert.equal(f.controller.view().phase, "billing_handoff");
  assert.equal(f.controller.view().productionReady, false);
  f.snapshot(billing({ customerBound: true, pendingReconciliations: 1 }));
  await f.controller.refresh();
  assert.equal(f.controller.view().phase, "billing_pending");
  assert.equal(f.controller.view().checkoutAvailable, false);
  f.snapshot(active());
  await f.controller.refresh();
  assert.equal(f.controller.view().phase, "test_subscription_observed");
  assert.equal(f.controller.view().checkoutAvailable, false);
  assert.equal(f.controller.view().portalAvailable, true);
  assert.equal(f.controller.view().productionReady, false);
  const signup = f.calls.find((call) => call.path.endsWith("/register"));
  assert.equal(signup.headers["x-zrotext-registration-token"], "synthetic-invite");
  assert.deepEqual(JSON.parse(signup.body), { email: "owner@example.test", password: "synthetic-password" });
  const checkout = f.calls.find((call) => call.path.endsWith("/checkout"));
  assert.equal(checkout.headers["x-zrotext-csrf"], "synthetic-csrf");
  assert.equal(checkout.headers["idempotency-key"], "00000000-0000-4000-8000-000000000003");
  assert.equal(checkout.body, undefined, "browser cannot select price, customer or return URL");
  assert.doesNotMatch(JSON.stringify(f.controller.view()), /password|invite|synthetic-code|stripe.com/);
});

test("self hosting never queries payment availability or creates a subscription", async () => {
  const f = fixture();
  f.controller.select("self_hosted");
  await assert.rejects(f.controller.refresh(), /Choose hosted/);
  await assert.rejects(f.controller.handoff("checkout"), /Choose hosted/);
  assert.equal(f.calls.length, 0);
  assert.equal(f.controller.view().phase, "self_hosted");
});

test("MFA challenge stays private until a second factor establishes the owner session", async () => {
  const f = fixture({ "/v1/auth/login": () => response({ challenge_token: "ztm_fixture" }, 202) });
  f.controller.select("hosted");
  await f.controller.login("owner@example.test", "synthetic-password");
  assert.equal(f.controller.view().phase, "second_factor");
  assert.equal(f.calls.length, 1);
  assert.doesNotMatch(JSON.stringify(f.controller.view()), /ztm_fixture/);
  await f.controller.secondFactor("synthetic-factor");
  const factor = f.calls.find((call) => call.path.endsWith("/mfa"));
  assert.deepEqual(JSON.parse(factor.body), { challenge_token: "ztm_fixture", code: "synthetic-factor" });
  assert.equal(f.controller.view().phase, "choose_test_subscription");
});

test("invalid accepted MFA responses cannot reuse a previous owner session", async () => {
  for (const body of [null, {}, { challenge_token: "invalid" }]) {
    const f = fixture({ "/v1/auth/login": () => response(body, 202) });
    f.controller.select("hosted");
    await assert.rejects(f.controller.login("owner@example.test", "synthetic-password"), /invalid/);
    assert.equal(f.calls.length, 1);
  }
});

test("observer sessions cannot request billing or checkout", async () => {
  const f = fixture({ "/v1/auth/session": () => response({ ...owner, role: "observer" }) });
  f.controller.select("hosted");
  await assert.rejects(f.controller.refresh(), /owner account/);
  assert.equal(f.calls.length, 1);
  assert.equal(f.controller.view().checkoutAvailable, undefined);
});

test("pending, risk, review, ambiguous and unpaid states never open another checkout", () => {
  for (const snapshot of [billing({ pendingReconciliations: 1 }),
    billing({ reviewReconciliations: 1 }), billing({ reviewRiskEvents: 1 }),
    billing({ projectedEntitlement: { reason: "active", outboundLimit: 19, deviceCap: 1, paymentHold: true } }),
    { ...active(), nonterminalSubscriptions: 2 },
    { ...active(), projectedEntitlement: { reason: "inactive", outboundLimit: 0, deviceCap: 0, paymentHold: false } },
  ]) assert.equal(billingView(snapshot).checkoutAvailable, false);
});

test("grace is labeled TEST and canceled subscriptions require a fresh authoritative read", async () => {
  const f = fixture();
  f.controller.select("hosted");
  f.snapshot({ ...active(), projectedEntitlement: { ...active().projectedEntitlement, reason: "grace" } });
  await f.controller.refresh();
  assert.equal(f.controller.view().entitlementReason, "grace");
  await f.controller.handoff("portal");
  assert.equal(f.controller.view().phase, "billing_handoff");
  assert.equal(f.controller.view().checkoutAvailable, undefined);
  f.snapshot(billing({ customerBound: true, projectedEntitlement:
    { reason: "inactive", outboundLimit: 0, deviceCap: 0, paymentHold: false } }));
  await f.controller.refresh();
  assert.equal(f.controller.view().checkoutAvailable, true);
});

test("malformed and live billing never fall back to TEST checkout", () => {
  for (const invalid of [null, {}, billing({ mode: "live" }), billing({ mode: "disabled" }),
    billing({ pendingReconciliations: -1 }), billing({ customerBound: "true" }),
    billing({ reviewRiskEvents: undefined }), billing({ projectedEntitlement: {} }),
    billing({ projectedEntitlement: { reason: "active", outboundLimit: "19", deviceCap: 1, paymentHold: false } }),
  ]) assert.throws(() => billingView(invalid), /invalid/);
});

test("billing failures erase earlier actionable views", async () => {
  let fail = false;
  const f = fixture({ "/v1/billing/status": () => fail ? response(null, 503) : response(billing()) });
  f.controller.select("hosted");
  await f.controller.refresh();
  fail = true;
  await assert.rejects(f.controller.refresh(), /unavailable/);
  assert.equal(f.controller.view().phase, "unavailable");
  assert.equal(f.controller.view().checkoutAvailable, undefined);
  await assert.rejects(f.controller.handoff("checkout"), /Refresh billing/);
  assert.equal(f.calls.filter((call) => call.path.endsWith("/checkout")).length, 0);
});

test("account changes during a read discard the billing snapshot", async () => {
  let reads = 0;
  const f = fixture({ "/v1/auth/session": () => response(++reads === 1 ? owner :
    { ...owner, account_id: "00000000-0000-4000-8000-000000000004" }) });
  f.controller.select("hosted");
  await assert.rejects(f.controller.refresh(), /session changed/);
  assert.equal(f.controller.view().checkoutAvailable, undefined);
});

test("account changes before a mutation prevent a provider handoff", async () => {
  let changed = false;
  const f = fixture({ "/v1/auth/session": () => response(changed ?
    { ...owner, session_id: "00000000-0000-4000-8000-000000000004" } : owner) });
  f.controller.select("hosted");
  await f.controller.refresh();
  changed = true;
  await assert.rejects(f.controller.handoff("checkout"), /session changed/);
  assert.equal(f.calls.filter((call) => call.path.endsWith("/checkout")).length, 0);
});

test("account changes during a handoff discard the returned URL", async () => {
  let changed = false;
  const f = fixture({ "/v1/auth/session": () => response(changed ?
    { ...owner, session_id: "00000000-0000-4000-8000-000000000004" } : owner),
  "/v1/billing/checkout": () => { changed = true; return response({ url: "https://checkout.stripe.com/test" }); } });
  f.controller.select("hosted");
  await f.controller.refresh();
  await assert.rejects(f.controller.handoff("checkout"), /session changed/);
  assert.equal(f.controller.view().phase, "unavailable");
});

test("provider URLs require the exact HTTPS host without credentials", async () => {
  for (const url of ["http://checkout.stripe.com/test", "https://checkout.stripe.com.evil.test/test",
    "https://synthetic@checkout.stripe.com/test", "https://checkout.stripe.com:444/test", "javascript:alert(1)"]) {
    const f = fixture({ "/v1/billing/checkout": () => response({ url }) });
    f.controller.select("hosted");
    await f.controller.refresh();
    await assert.rejects(f.controller.handoff("checkout"), /invalid/);
  }
});

test("missing CSRF refuses mutation before checkout", async () => {
  const calls = [];
  const controller = create({ fetch: async (path) => {
    calls.push(path);
    return response(path.endsWith("/session") ? owner : billing());
  },
    cookie: () => "", randomUUID: () => "00000000-0000-4000-8000-000000000003" });
  controller.select("hosted");
  await assert.rejects(controller.refresh(), /Sign in again/);
  await assert.rejects(controller.handoff("checkout"), /Refresh billing/);
  assert.equal(calls.filter((path) => path.endsWith("/checkout")).length, 0);
});

test("cookie replacement immediately before POST sends the original session's CSRF", async () => {
  let csrf = "csrf-owner-a";
  let sent;
  const controller = create({ cookie: () => `__Host-zrotext_csrf=${csrf}`,
    randomUUID: () => { csrf = "csrf-owner-b"; return "00000000-0000-4000-8000-000000000003"; },
    fetch: async (path, init) => {
      if (path === "/v1/billing/checkout") {
        sent = init.headers["x-zrotext-csrf"];
        // Existing server rejects a token from A paired with B's cookies.
        return response(null, sent === csrf ? 200 : 403);
      }
      if (path === "/v1/service/availability") return response(available());
      return response(path.endsWith("/session") ? owner : billing());
    } });
  controller.select("hosted");
  await controller.refresh();
  await assert.rejects(controller.handoff("checkout"), /refused/);
  assert.equal(sent, "csrf-owner-a");
  assert.equal(controller.view().phase, "sign_in");
});

test("CSRF rotation while reading a session discards its billing controls", async () => {
  let csrf = "csrf-owner-a";
  const controller = create({ cookie: () => `__Host-zrotext_csrf=${csrf}`,
    fetch: async () => { csrf = "csrf-owner-b"; return response(owner); } });
  controller.select("hosted");
  await assert.rejects(controller.refresh(), /session changed/);
  assert.equal(controller.view().checkoutAvailable, undefined);
});

test("duplicate signup submits cannot create parallel requests", async () => {
  let resolve;
  const f = fixture({ "/v1/auth/register": () => new Promise((done) => { resolve = done; }) });
  f.controller.select("hosted");
  const first = f.controller.register("owner@example.test", "synthetic-password");
  await assert.rejects(f.controller.register("owner@example.test", "synthetic-password"), /already running/);
  await new Promise(setImmediate);
  resolve(response(null, 202));
  await first;
  assert.equal(f.calls.filter((call) => call.path === "/v1/auth/register").length, 1);
});

test("changing to self hosting discards an in-flight hosted result", async () => {
  let resolve;
  const f = fixture({ "/v1/auth/register": () => new Promise((done) => { resolve = done; }) });
  f.controller.select("hosted");
  const pending = f.controller.register("owner@example.test", "synthetic-password");
  await new Promise(setImmediate);
  f.controller.select("self_hosted");
  resolve(response(null, 202));
  await assert.rejects(pending, /Onboarding changed/);
  assert.equal(f.controller.view().phase, "self_hosted");
});

test("registration failures never expose raw provider bodies", async () => {
  const f = fixture({ "/v1/auth/register": () => response({ private: "synthetic-provider-detail" }, 429) });
  f.controller.select("hosted");
  await assert.rejects(f.controller.register("owner@example.test", "synthetic-password"), /Too many attempts/);
  assert.doesNotMatch(JSON.stringify(f.controller.view()), /synthetic-provider-detail/);
});

test("registration availability must be verified before account creation", async () => {
  for (const value of [null, {}, available({ schema_version: 2 }),
    available({ billing: "disabled" }), available({ plan_catalog_available: false }),
    available({ deployment: "self_hosted" }), available({ registration: "closed" })]) {
    const f = fixture({ "/v1/service/availability": () => response(value) });
    assert.equal(f.controller.select("hosted").phase, "availability_unknown");
    await assert.rejects(f.controller.register("owner@example.test", "synthetic-password"));
    assert.equal(f.calls.some((call) => call.path === "/v1/auth/register"), false);
    assert.equal(f.controller.view().checkoutAvailable, undefined);
  }
});

test("invite-only setup requires an invitation while closed registration permits existing sign-in", async () => {
  const f = fixture({ "/v1/service/availability": () => response(available({ registration: "invite_only" })) });
  f.controller.select("hosted");
  assert.equal((await f.controller.availability()).phase, "account_setup");
  await assert.rejects(f.controller.register("owner@example.test", "synthetic-password"), /invitation/);
  assert.equal(f.calls.some((call) => call.path === "/v1/auth/register"), false);
  await f.controller.register("owner@example.test", "synthetic-password", "synthetic-invite");
  const closed = fixture({ "/v1/service/availability": () => response(available({ registration: "closed" })) });
  closed.controller.select("hosted");
  assert.equal((await closed.controller.availability()).phase, "registration_closed");
  await closed.controller.login("owner@example.test", "synthetic-password");
  assert.equal(closed.controller.view().phase, "choose_test_subscription");
});

test("checkout rechecks deployment availability immediately before the handoff", async () => {
  let value = available();
  const f = fixture({ "/v1/service/availability": () => response(value) });
  f.controller.select("hosted");
  await f.controller.refresh();
  value = available({ checkout_available: false });
  await assert.rejects(f.controller.handoff("checkout"), /Checkout is unavailable/);
  assert.equal(f.calls.some((call) => call.path === "/v1/billing/checkout"), false);
});

test("live availability never authorizes this TEST-only controller to checkout", async () => {
  const f = fixture({ "/v1/service/availability": () => response(available({ billing: "live" })) });
  f.controller.select("hosted");
  await f.controller.refresh();
  assert.equal(f.controller.view().phase, "billing_unavailable");
  assert.equal(f.controller.view().checkoutAvailable, undefined);
  await assert.rejects(f.controller.handoff("checkout"), /Refresh billing/);
  await assert.rejects(f.controller.handoff("portal"), /Refresh billing/);
  assert.equal(f.calls.some((call) => call.path.startsWith("/v1/billing/")), false);
});

test("availability requires exactly the six version-one fields", async () => {
  const missing = available();
  delete missing.plan_catalog_available;
  for (const value of [available({ private_detail: "synthetic-extra" }), missing,
    available({ schema_version: "1" }), available({ checkout_available: "true" }),
    [], "synthetic-response"]) {
    const f = fixture({ "/v1/service/availability": () => response(value) });
    f.controller.select("hosted");
    await assert.rejects(f.controller.availability(), /could not be verified/);
    await assert.rejects(f.controller.register("owner@example.test", "synthetic-password"), /could not be verified/);
    assert.equal(f.calls.some((call) => call.path === "/v1/auth/register"), false);
    assert.equal(f.controller.view().checkoutAvailable, undefined);
  }
});

test("valid disabled and self-hosted availability preserves sign-in without billing reads", async () => {
  for (const value of [available({ billing: "disabled", checkout_available: false, plan_catalog_available: false }),
    available({ deployment: "self_hosted", billing: "disabled", checkout_available: false, plan_catalog_available: false })]) {
    const f = fixture({ "/v1/service/availability": () => response(value) });
    f.controller.select("hosted");
    await f.controller.login("owner@example.test", "synthetic-password");
    assert.equal(f.controller.view().phase, "billing_unavailable");
    assert.equal(f.calls.some((call) => call.path === "/v1/auth/login"), true);
    assert.equal(f.calls.filter((call) => call.path === "/v1/auth/session").length, 2);
    await f.controller.refresh();
    assert.equal(f.controller.view().phase, "billing_unavailable");
    assert.equal(f.controller.view().checkoutAvailable, undefined);
    assert.equal(f.controller.view().portalAvailable, undefined);
    await assert.rejects(f.controller.handoff("checkout"), /Refresh billing/);
    await assert.rejects(f.controller.handoff("portal"), /Refresh billing/);
    assert.equal(f.calls.some((call) => call.path.startsWith("/v1/billing/")), false);
  }
});

test("portal rechecks availability and refuses replacement deployment or billing mode", async () => {
  for (const replacement of [available({ billing: "live" }),
    available({ billing: "disabled", checkout_available: false, plan_catalog_available: false }),
    available({ deployment: "self_hosted", billing: "disabled", checkout_available: false, plan_catalog_available: false })]) {
    let value = available();
    const f = fixture({ "/v1/service/availability": () => response(value) });
    f.controller.select("hosted");
    f.snapshot(active());
    await f.controller.refresh();
    assert.equal(f.controller.view().portalAvailable, true);
    value = replacement;
    await assert.rejects(f.controller.handoff("portal"), /TEST billing is unavailable/);
    assert.equal(f.calls.some((call) => call.path === "/v1/billing/portal"), false);
    assert.equal(f.controller.view().portalAvailable, undefined);
  }
});

test("TEST portal remains available when registration, catalog and checkout are closed", async () => {
  const f = fixture({ "/v1/service/availability": () => response(available({ registration: "closed",
    checkout_available: false, plan_catalog_available: false })) });
  f.controller.select("hosted");
  f.snapshot(active());
  await f.controller.refresh();
  assert.equal(f.controller.view().checkoutAvailable, false);
  assert.equal(f.controller.view().portalAvailable, true);
  assert.equal(await f.controller.handoff("portal"), "https://billing.stripe.com/p/session/test_fixture");
  assert.equal(f.controller.view().billingMode, "test");
});
