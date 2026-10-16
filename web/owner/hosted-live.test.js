// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
// HOSTED-TERMS-01 HOSTED-CHECKOUT-01 HOSTED-MODE-01 SETUP-UNKNOWN-01 SETUP-FRESH-01
const test = require("node:test"), assert = require("node:assert/strict");
const { create, runtimeBillingView } = require("./hosted-onboarding.js");
const now = 2000000000000;
const expected = { account: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" };
const checkoutUrl = "https://checkout.stripe.com/c/pay/cs_test_synthetic#fidkdWxSynthetic%2Fopaque";
const observed = (mode = "live", changes = {}) => ({ schema_version: 1, mode, account_id: expected.account,
  session_id: expected.id, observed_at_ms: now, customer_bound: false,
  checkout: { state: "none", url: null, expires_at_ms: null },
  entitlement: { phase: "pending", valid_until_ms: now, first_failure_at_ms: null,
    outbound_limit: 0, device_cap: 0, payment_hold: false, review_required: false },
  reconciliation_pending: false, ...changes });
const plan = (mode = "live") => ({ schema_version: 1, mode, currency: "usd", unit_amount: 1900,
  interval: "year", interval_count: 1, outbound_limit: 19, device_cap: 1,
  tax_behavior: "exclusive", automatic_tax: true, allowance_period: "subscription_invoice" });
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => body });
function fixture(mode = "live", options = {}) {
  const state = { status: observed(mode), plan: plan(mode), mode, calls: [], attempts: 0, ...options.state };
  const controller = create({ now: () => now, checkoutReturn: options.checkoutReturn,
    cookie: options.cookie || (() => "__Host-zrotext_csrf=proof-a"), randomUUID: () => expected.id,
    onCheckoutAttempt: () => { state.attempts++; },
    fetch: async (path, init) => {
      state.calls.push({ path, ...init });
      if (path === "/v1/auth/session") {
        if (state.sessionUnavailable) throw new Error("synthetic network failure");
        if (state.sessionBarrier) await state.sessionBarrier;
        return response(state.sessionDto || { role: "owner", account_id: expected.account, session_id: expected.id }, state.sessionStatus || 200);
      }
      if (path === "/v1/service/availability") return response({ schema_version: 1, deployment: "hosted", registration: "open",
        billing: state.mode, checkout_available: true, plan_catalog_available: true });
      if (path === "/v1/billing/status") {
        assert.equal(init.headers["x-zrotext-csrf"], "proof-a");
        assert.equal(init.headers.Origin, undefined, "same-origin GET needs cookie proof, not invented Origin");
        if (state.statusBarrier) await state.statusBarrier;
        return response(state.status, state.statusCode || 200);
      }
      if (path === "/v1/billing/plan") return response(state.plan);
      if (["/v1/billing/checkout", "/v1/billing/checkout/recover", "/v1/billing/portal"].includes(path)) {
        assert.equal(init.method, "POST"); assert.equal(init.headers["x-zrotext-csrf"], "proof-a");
        assert.equal(init.body, undefined, "browser cannot choose provider identity or price");
        if (state.lostReply) throw new Error("synthetic dropped response");
        if (path.endsWith("/recover")) {
          assert.equal(init.headers["idempotency-key"], undefined, "server owns the existing operation key");
          if (state.recoveryClosed) {
            state.status.checkout.state = "reconciliation_required"; state.status.reconciliation_pending = true;
            return response({ url: null });
          }
          return response({ url: checkoutUrl });
        }
        return response({ url: path.endsWith("checkout") ? checkoutUrl : "https://billing.stripe.com/p/session/synthetic" });
      }
      throw new Error("Unexpected fixture endpoint");
    } });
  controller.select("hosted");
  return { controller, state };
}
test("served runtime TEST and LIVE modes review authoritative terms before explicit handoff", async () => {
  for (const mode of ["test", "live"]) {
    const { controller, state } = fixture(mode);
    await controller.refresh();
    assert.equal(controller.view().phase, mode === "live" ? "choose_subscription" : "choose_test_subscription");
    assert.deepEqual(await controller.plan(), plan(mode));
    assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
    assert.equal(await controller.handoff("checkout"), checkoutUrl);
    assert.equal(state.attempts, 1);
    assert.equal(controller.view().billingMode, mode);
    assert.doesNotMatch(JSON.stringify(controller.view()), /stripe\.com|fidkdWx|proof-a/);
  }
});
test("active and grace require fresh clean positive entitlement and never repeat checkout", async () => {
  for (const phase of ["active", "grace"]) {
    const { controller, state } = fixture();
    state.status.customer_bound = true;
    Object.assign(state.status.entitlement, { phase, valid_until_ms: now + 30000, outbound_limit: 19, device_cap: 1 });
    await controller.refresh();
    assert.equal(controller.view().phase, "subscription_observed");
    assert.equal(controller.view().phoneSetupAvailable, true);
    assert.equal(controller.view().portalAvailable, true);
    assert.equal(controller.view().productionReady, false, "subscription UI never certifies device or carrier readiness");
    await assert.rejects(controller.handoff("checkout"));
    assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  }
});
test("lost sign-in proof and expired sessions expose sign-in without repeating any mutation", async () => {
  for (const loss of ["cookie", "empty_cookie", "expired"]) {
    let cookie = "__Host-zrotext_csrf=proof-a";
    const { controller, state } = fixture("live", { cookie: () => cookie });
    Object.assign(state.status.entitlement, { phase: "active", valid_until_ms: now + 30000, outbound_limit: 19, device_cap: 1 });
    await controller.refresh();
    assert.equal(controller.view().phase, "subscription_observed");
    if (loss === "expired") state.sessionStatus = 401;
    else cookie = loss === "empty_cookie" ? "__Host-zrotext_csrf=" : "";
    await assert.rejects(controller.refresh(), error => error.status === 401);
    assert.equal(controller.view().phase, "sign_in", loss);
    assert.equal(controller.view().recoverBilling, false);
    assert.equal(controller.view().phoneSetupAvailable, undefined);
    assert.equal(controller.view().checkoutAvailable, undefined);
    assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  }
});
test("transient session network failure retains billing recovery without sign-in or mutations", async () => {
  const { controller, state } = fixture();
  await controller.refresh();
  state.sessionUnavailable = true;
  await assert.rejects(controller.refresh(), /Could not reach/);
  assert.equal(controller.view().phase, "unavailable");
  assert.equal(controller.view().recoverBilling, true);
  assert.equal(controller.view().billingMode, "live");
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
});
test("an observed observer replacement leaves LIVE billing for its fixed workspace without further billing reads", async () => {
  let cookie = "__Host-zrotext_csrf=proof-a";
  const { controller, state } = fixture("live", { cookie: () => cookie });
  Object.assign(state.status.entitlement, { phase: "active", valid_until_ms: now + 30000, outbound_limit: 19, device_cap: 1 });
  await controller.refresh(); assert.equal(controller.view().phase, "subscription_observed");
  cookie = "__Host-zrotext_csrf=proof-b";
  state.sessionDto = { role: "observer", account_id: expected.account, session_id: expected.account, workspacePath: "https://untrusted.example.test" };
  const before = state.calls.length;
  await assert.rejects(controller.refresh(), /signed in as an observer/);
  assert.equal(controller.view().phase, "existing_session");
  assert.equal(controller.view().workspacePath, "/owner/observer");
  for (const key of ["billingMode", "recoverBilling", "checkoutAvailable", "resumeAvailable", "recoverAvailable", "portalAvailable", "phoneSetupAvailable"]) assert.equal(controller.view()[key], undefined, key);
  assert.deepEqual(state.calls.slice(before).map(c => [c.path, c.method]), [["/v1/auth/session", "GET"]]);
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  assert.equal(cookie, "__Host-zrotext_csrf=proof-b");
});
test("malformed observer identities and unknown roles cannot select observer recovery", async () => {
  for (const dto of [
    { role: "observer", account_id: "invalid", session_id: expected.id },
    { role: "observer", account_id: expected.account, session_id: "invalid" },
    { role: "observer", account_id: [expected.account], session_id: expected.id },
    { role: "observer", account_id: expected.account, session_id: [expected.id] },
    { role: "unrecognized", account_id: expected.account, session_id: expected.id },
  ]) {
    const { controller, state } = fixture(); await controller.refresh();
    state.sessionDto = dto; const before = state.calls.length;
    await assert.rejects(controller.refresh(), /owner account/);
    assert.notEqual(controller.view().phase, "existing_session");
    assert.equal(controller.view().workspacePath, undefined);
    assert.deepEqual(state.calls.slice(before).map(c => [c.path, c.method]), [["/v1/auth/session", "GET"]]);
    assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  }
});
test("a changed CSRF during an observer session read refuses the stale role observation", async () => {
  let cookie = "__Host-zrotext_csrf=proof-a", release;
  const { controller, state } = fixture("live", { cookie: () => cookie }); await controller.refresh();
  state.sessionDto = { role: "observer", account_id: expected.account, session_id: expected.id };
  state.sessionBarrier = new Promise(resolve => { release = resolve; });
  const before = state.calls.length, pending = controller.refresh(); await new Promise(setImmediate);
  cookie = "__Host-zrotext_csrf=proof-b"; release();
  await assert.rejects(pending, /session changed/);
  assert.notEqual(controller.view().phase, "existing_session");
  assert.equal(controller.view().workspacePath, undefined);
  assert.deepEqual(state.calls.slice(before).map(c => [c.path, c.method]), [["/v1/auth/session", "GET"]]);
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  assert.equal(cookie, "__Host-zrotext_csrf=proof-b");
});
test("risk, dirty, expired and zero-capacity observations retain progress without enabling phone setup", () => {
  for (const change of [
    v => { v.entitlement.payment_hold = true; }, v => { v.entitlement.review_required = true; },
    v => { v.entitlement.phase = "restricted"; }, v => { v.reconciliation_pending = true; },
    v => { v.entitlement.valid_until_ms = now; }, v => { v.entitlement.device_cap = 0; },
    v => { v.entitlement.outbound_limit = 0; },
  ]) {
    const value = observed(); Object.assign(value.entitlement, { phase: "active", valid_until_ms: now + 30000, outbound_limit: 19, device_cap: 1 });
    change(value);
    const view = runtimeBillingView(value, expected, now);
    assert.equal(view.phoneSetupAvailable, false); assert.equal(view.checkoutAvailable, false);
  }
});
test("resume re-reads the same open checkout and preserves its opaque fragment without any POST", async () => {
  const { controller, state } = fixture();
  state.status.customer_bound = true;
  state.status.checkout = { state: "resumable", url: checkoutUrl, expires_at_ms: now + 30000 };
  await controller.refresh();
  assert.equal(controller.view().phase, "checkout_resumable");
  assert.equal(controller.view().checkoutAvailable, false);
  assert.equal(await controller.handoff("resume"), checkoutUrl);
  assert.equal(state.calls.filter(c => c.path === "/v1/billing/status").length, 2);
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
});
test("expired or changed open checkout must reconcile before any replacement purchase", async () => {
  const { controller, state } = fixture();
  state.status.checkout = { state: "resumable", url: checkoutUrl, expires_at_ms: now + 30000 };
  await controller.refresh();
  state.status.checkout = { state: "pending", url: null, expires_at_ms: null };
  await assert.rejects(controller.handoff("resume"), /Checkout changed/);
  state.status.checkout = { state: "resumable", url: checkoutUrl, expires_at_ms: now };
  await controller.refresh(); assert.equal(controller.view().phase, "billing_pending");
  await assert.rejects(controller.handoff("checkout"));
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
});
test("return flags cannot turn pending into paid or prevent confirmed terminal replacement", async () => {
  const { controller, state } = fixture("live", { checkoutReturn: true });
  state.status.checkout = { state: "reconciliation_required", url: null, expires_at_ms: now - 1000 };
  await controller.refresh(); assert.equal(controller.view().phase, "billing_pending");
  assert.equal(controller.view().phoneSetupAvailable, false); assert.equal(controller.view().checkoutAvailable, false);
  state.status.checkout.state = "replaceable"; state.status.entitlement.phase = "terminal";
  await controller.refresh(); assert.equal(controller.view().phase, "choose_subscription");
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  await controller.plan(); await controller.handoff("checkout"); assert.equal(state.attempts, 1);
});
test("closed status shape, account, session, safe integers and freshness are independently required", () => {
  for (const change of [v => { v.account_id = expected.id; }, v => { v.session_id = expected.account; },
    v => { v.observed_at_ms = now - 120001; }, v => { v.observed_at_ms = now + 5001; },
    v => { v.customer_bound = "true"; }, v => { v.extra = true; }, v => { delete v.entitlement.review_required; },
    v => { v.entitlement.device_cap = Number.MAX_SAFE_INTEGER + 1; }, v => { v.checkout.state = "unknown"; },
    v => { v.checkout.url = checkoutUrl; }, v => { v.entitlement.first_failure_at_ms = -1; },
  ]) { const value = observed(); change(value); assert.throws(() => runtimeBillingView(value, expected, now), /invalid/); }
});
test("resume URLs reject hostile authorities and raw controls while allowing provider fragments", () => {
  for (const url of ["http://checkout.stripe.com/c/pay/synthetic", "https://checkout.stripe.com.evil.test/c/pay/synthetic",
    "https://synthetic@checkout.stripe.com/c/pay/synthetic", "https://checkout.stripe.com:444/c/pay/synthetic",
    "https://checkout.stripe.com/c/pay/synthetic\n", " https://checkout.stripe.com/c/pay/synthetic"]) {
    const value = observed(); value.checkout = { state: "resumable", url, expires_at_ms: now + 30000 };
    assert.throws(() => runtimeBillingView(value, expected, now), /invalid/);
  }
});
test("LIVE terms reject missing tax, wrong billing period, wrong mode and nullable allowance", async () => {
  for (const change of [v => { delete v.tax_behavior; }, v => { v.automatic_tax = "true"; },
    v => { v.allowance_period = "calendar_month"; }, v => { v.outbound_limit = null; },
    v => { v.mode = "test"; }, v => { v.device_cap = 0; }, v => { v.unit_amount = 0; }]) {
    const { controller, state } = fixture(); change(state.plan); await controller.refresh();
    await assert.rejects(controller.plan(), /invalid/); assert.equal(controller.view().checkoutAvailable, undefined);
  }
});
test("availability mode drift prevents both checkout and portal from using another namespace", async () => {
  for (const kind of ["checkout", "portal"]) {
    const { controller, state } = fixture(); state.status.customer_bound = true;
    await controller.refresh(); state.mode = "test";
    await assert.rejects(controller.handoff(kind), /mode changed/);
    assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  }
});
test("lost checkout reply exposes only recovery and never retries POST on its own", async () => {
  const { controller, state } = fixture(); await controller.refresh(); state.lostReply = true;
  await assert.rejects(controller.handoff("checkout"), /Could not reach/);
  assert.equal(controller.view().recoverBilling, true);
  assert.equal(controller.view().checkoutAvailable, undefined);
  state.status.checkout.state = "pending"; await controller.refresh();
  assert.equal(controller.view().phase, "billing_pending");
  await assert.rejects(controller.handoff("checkout"));
  assert.equal(state.calls.filter(c => c.method === "POST").length, 1);
});

test("only an authoritative recoverable observation permits an explicit existing-operation replay", async () => {
  const { controller, state } = fixture();
  state.status.checkout.state = "recoverable"; state.status.reconciliation_pending = true;
  await controller.refresh();
  assert.equal(controller.view().phase, "checkout_recoverable");
  assert.equal(controller.view().recoverAvailable, true); assert.equal(controller.view().checkoutAvailable, false);
  assert.equal(state.calls.filter(c => c.method === "POST").length, 0);
  assert.equal(await controller.handoff("recover"), checkoutUrl);
  assert.equal(state.calls.filter(c => c.path === "/v1/billing/checkout/recover").length, 1);
  assert.equal(state.calls.filter(c => c.path === "/v1/billing/checkout").length, 0);
  assert.equal(state.attempts, 0);
});

test("recovering an already completed attempt refreshes status without navigating or replacing it", async () => {
  const { controller, state } = fixture();
  state.status.checkout.state = "recoverable"; state.recoveryClosed = true;
  await controller.refresh(); assert.equal(await controller.handoff("recover"), null);
  assert.equal(controller.view().phase, "billing_pending"); assert.equal(controller.view().recoverAvailable, false);
  assert.equal(state.calls.filter(c => c.path === "/v1/billing/checkout/recover").length, 1);
  assert.equal(state.calls.filter(c => c.path === "/v1/billing/checkout").length, 0);
});

test("leaving hosted setup during a held recovery read prevents the old recovery mutation", async () => {
  for (const leave of [controller => controller.invalidate(), controller => controller.select("self_hosted")]) {
    const { controller, state } = fixture(); state.status.checkout.state = "recoverable";
    await controller.refresh();
    let release; state.statusBarrier = new Promise(resolve => { release = resolve; });
    const pending = controller.handoff("recover"); await new Promise(setImmediate);
    leave(controller); release();
    await assert.rejects(pending, /Onboarding changed/);
    assert.equal(state.calls.filter(c => c.path === "/v1/billing/checkout/recover").length, 0);
  }
});
