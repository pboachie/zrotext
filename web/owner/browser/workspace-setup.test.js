// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const { webcrypto, createPublicKey, verify } = require("node:crypto");
const signing = require("../sms-line-signing.js");
const contract = require("../../../protocol/v1/setup-journey-contract.json");
const root = path.resolve(__dirname, "..");
const account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", session = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const pairing = "cccccccc-cccc-4ccc-8ccc-cccccccccccc", device = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const line = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", opening = "ffffffff-ffff-4fff-8fff-ffffffffffff";
const proof = "AB".repeat(32);
let browser, captureRoot;
test.before(async () => { browser = await chromium.launch(); if (process.env.ZT_OWNER_SCREENSHOTS === "1") { captureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-workspace-review-")); console.log("Workspace screenshots: " + captureRoot); } });
test.after(async () => { await browser.close(); });
function requires(...ids) { for (const id of ids) assert.ok(contract.requirements.some(r => r.id === id), id); }
async function fixture(destination = "setup?new=1", width = 1440, changes = {}) {
  const page = await browser.newPage({ viewport: { width, height: width <= 390 ? 844 : 900 }, reducedMotion: "reduce" });
  await page.clock.install();
  const state = { signedIn: true, session, requests: [], pair: null, approved: false, connected: false, lostApproval: false,
    billing: "new", deployment: "hosted", registration: "open", mode: "test", catalog: true, ...changes };
  if (state.lineFixture) {
    const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const point = new Uint8Array(await webcrypto.subtle.exportKey("raw", keys.publicKey));
    state.keyFingerprint = signing.base64url(await signing.sha256(point));
    state.ownerPublic = createPublicKey({ key: await webcrypto.subtle.exportKey("jwk", keys.publicKey), format: "jwk" });
    const jwk = await webcrypto.subtle.exportKey("jwk", keys.privateKey);
    await page.addInitScript(({ jwk, fingerprint }) => {
      const key = crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
      globalThis.ZtSmsKeyStore = { get: async () => ({ privateKey: await key, fingerprint }) };
    }, { jwk, fingerprint: state.keyFingerprint });
    const observation = Buffer.alloc(121); observation.writeUInt16BE(33, 0); observation.writeUInt16BE(2, 2); observation.writeInt32BE(11, 4); observation[8] = 2;
    for (const offset of [9, 25, 49, 73]) observation.set(signing.uuidBytes(account), offset);
    observation.writeInt32BE(0, 41); observation.writeInt32BE(1, 45); observation.writeBigInt64BE(1n, 65); observation.fill(9, 89);
    state.observation = new Uint8Array(observation);
    state.statement = signing.deviceStatementV2({ accountId: account, lineId: line, deviceId: device,
      challengeId: pairing, generation: "1", nonce: new Uint8Array(32).fill(9), observation: state.observation });
    const phoneKey = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    state.phoneSignature = signing.p1363ToDer(new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, phoneKey.privateKey, state.statement)));
    state.ownerStatement = await signing.ownerApprovalStatementV2(state.statement, state.phoneSignature);
    state.linePhase = "awaiting_owner";
    state.expires = Date.now() + 300000;
  }
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    state.requests.push({ path: url.pathname, method, body: request.postData(), headers: request.headers() });
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    if (url.hostname === "checkout.stripe.com") return route.fulfill({ contentType: "text/html", body: "<p>Synthetic TEST provider</p>" });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const name = url.pathname.slice(7), file = ["devices", "phones", "activity", "integrations", "security", "setup"].includes(name) ? "devices.html" : name.includes(".") ? name : name + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType: file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/service/availability") return json({ schema_version: 1, deployment: state.deployment, registration: state.registration,
      billing: state.mode, checkout_available: state.catalog && state.mode === "test", plan_catalog_available: state.catalog });
    if (url.pathname === "/v1/auth/session") return state.signedIn ? json({ role: "owner", account_id: account, session_id: state.session, user_id: account }) : json({}, 401);
    if (url.pathname === "/v1/auth/login") { state.signedIn = true; return route.fulfill({ status: 204 }); }
    if (["/v1/auth/register", "/v1/auth/resend-verification"].includes(url.pathname)) return route.fulfill({ status: 202 });
    if (url.pathname === "/v1/auth/verify-email") return route.fulfill({ status: 204 });
    if (url.pathname === "/v1/auth/logout") { state.signedIn = false; return route.fulfill({ status: 204 }); }
    if (url.pathname === "/v1/account/setup" && state.progressUnavailable) return json({}, 503);
    if (url.pathname === "/v1/account/setup") return json({ schema_version: 1, account_id: account, session_id: state.session, observed_at_ms: Date.now(),
      sms_line_activation_available: true, pairings: state.pair ? [{ pairing_id: pairing, created_at_ms: Date.now() - 1000,
        display_name: "Synthetic gateway", status: state.approved ? "approved" : "awaiting_approval", expires_at_ms: Date.now() + 300000,
        approved_device_id: state.approved ? device : null, comparison_code: state.approved ? null : "12345678", key_fingerprint: state.approved ? null : proof }] : [],
      line_activations: state.lineStarted ? [{ line_id: line, challenge_id: pairing, opening_id: opening, device_id: device, generation: "1",
        expires_at_ms: state.expires, same_session: state.session === session, status: state.linePhase === "activated" ? "approved" : state.session === session ? "awaiting_owner" : "session_changed" }] : [], devices: state.approved ? [{ device_id: device, pairing_id: pairing, revoked: false, key_fingerprint: proof,
        setup_line_id: line, setup_opening_id: opening, line_activation_version: state.connected ? 2 : null }] : [], truncated: false });
    if (url.pathname === "/v1/enrollment/devices") return json({ devices: state.approved ? [{ device_id: device, display_name: "Synthetic gateway", revoked: false,
      active_socket_lease: state.connected, status_observed_at_ms: Date.now(), pending_messages: 0, in_flight_messages: 0 }] : [], next_cursor: null });
    if (url.pathname === "/v1/enrollment/pairings" && method === "POST") { state.pair = true; return json({ pairing_id: pairing, token: "synthetic-only" }, 201); }
    if (url.pathname.endsWith("/approve") && url.pathname.includes("/pairings/")) { state.approved = true; return json({ device_id: device }, state.lostApproval ? 503 : 201); }
    if (url.pathname.endsWith("/cancel")) { state.pair = null; return route.fulfill({ status: 204 }); }
    if (url.pathname.startsWith("/v1/enrollment/pairings/")) return json({ claimed: state.proofReady !== false, proof_verified: state.proofReady !== false, comparison_code: "12345678", key_fingerprint: proof, approved_device_id: state.approved ? device : null });
    if (url.pathname === "/v1/billing/status") return json({ mode: "test", customerBound: state.billing !== "new", pendingReconciliations: state.billing === "pending" ? 1 : 0,
      reviewReconciliations: 0, reviewRiskEvents: 0, nonterminalSubscriptions: state.billing === "active" ? 1 : 0,
      projectedEntitlement: { reason: state.billing === "active" ? "active" : null, outboundLimit: 19, deviceCap: 1, paymentHold: false } });
    if (url.pathname === "/v1/billing/plan") return state.catalog ? json({ schema_version: 1, mode: "test", currency: state.currency || "usd", unit_amount: state.unitAmount === undefined ? 1900 : state.unitAmount, interval: "month", interval_count: 1, outbound_limit: 19, device_cap: 1 }) : json({}, 503);
    if (url.pathname === "/v1/billing/checkout") { state.billing = "pending"; return json({ url: "https://checkout.stripe.com/c/pay/test_synthetic" }); }
    if (url.pathname === "/v1/auth/sms-line-owner-keys") return json(state.lineFixture ? [{ active: true, fingerprint: state.keyFingerprint }] : []);
    if (url.pathname.includes("/activations-v2") && state.lineFixture) {
      if (method === "POST" && !url.pathname.endsWith("/approve")) {
        state.lineStarted = true;
        assert.deepEqual(JSON.parse(request.postData()), { device_id: device, opening_id: opening });
        return json({ challenge_id: pairing, account_id: account, line_id: line, device_id: device, generation: "1", expires_at_ms: state.expires }, 201);
      }
      if (url.pathname.endsWith("/approve")) {
        const body = JSON.parse(request.postData());
        assert.equal(verify("sha256", state.ownerStatement, { key: state.ownerPublic, dsaEncoding: "der" }, signing.fromBase64url(body.owner_signature_der_b64url)), true);
        state.linePhase = "activated";
        return route.fulfill({ status: 204 });
      }
      return json({ challenge_id: pairing, device_id: device, generation: "1", expires_at_ms: state.expires, status: state.linePhase,
        observation_b64url: signing.base64url(state.observation), device_statement_b64url: signing.base64url(state.statement),
        device_signature_der_b64url: signing.base64url(state.phoneSignature), owner_statement_b64url: signing.base64url(state.ownerStatement) });
    }
    if (url.pathname === "/v1/auth/mfa/enroll") { state.mfaPending = true; return json({ secret_base32: "A".repeat(32), provisioning_uri: "otpauth://totp/Synthetic?secret=" + "A".repeat(32) }); }
    if (url.pathname === "/v1/auth/mfa/confirm") {
      if (JSON.parse(request.postData()).code !== "123456") return json({}, 400);
      state.mfaEnabled = true; state.mfaPending = false;
      return json({ recovery_codes: ["synthetic-recovery-one", "synthetic-recovery-two"] });
    }
    if (url.pathname === "/v1/auth/mfa") return json({ enabled: Boolean(state.mfaEnabled), pending: Boolean(state.mfaPending) });
    if (url.pathname === "/v1/auth/sessions") return json({ sessions: [] });
    if (url.pathname === "/v1/owner/message-summary") return json({}, 404);
    return json({ devices: [], messages: [], holds: [], keys: [], endpoints: [], lines: [], next_cursor: null });
  });
  await page.goto("https://example.test/owner/" + destination);
  if (!destination.startsWith("hosted")) await page.waitForFunction(() => !document.getElementById("owner-content").hidden);
  return { page, state, count: (route, method = "POST") => state.requests.filter(r => r.path === route && r.method === method).length };
}
for (const width of [320, 390, 1440]) test(`UX-NAV-01 UX-A11Y-01 real destinations hide inactive forms at ${width}px and enlarged text`, async () => {
  requires("UX-NAV-01", "UX-A11Y-01", "UX-STYLE-01");
  const { page, state } = await fixture("devices", width);
  try {
    assert.equal(await page.locator("#pair-phone").isVisible(), false);
    assert.equal(await page.locator("#connection-details").isVisible(), false);
    assert.equal(await page.locator("#account-security").isVisible(), false);
    if (width < 960) await page.locator(".owner-menu > summary").click();
    await page.getByRole("link", { name: "Integrations", exact: true }).click();
    await page.waitForURL("**/owner/integrations");
    assert.equal(await page.locator("#connection-details").isVisible(), true);
    assert.equal(await page.locator("#approved-devices").isVisible(), false);
    const before = state.requests.filter(r => r.path === "/v1/enrollment/devices").length;
    await page.clock.fastForward(30000);
    assert.equal(state.requests.filter(r => r.path === "/v1/enrollment/devices").length, before, "inactive fleet does not poll");
    await page.goBack();
    await page.waitForURL("**/owner/devices");
    assert.equal(await page.locator(".owner-nav [aria-current=page]").textContent(), "Overview");
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    assert.equal(await page.locator("body").evaluate(e => getComputedStyle(e).backgroundColor), "rgb(11, 15, 12)");
  } finally { await page.close(); }
});
test("SETUP-PAIR-01 REC-APPROVAL explicit displayed comparison survives unknown approval and reload without another pairing", async () => {
  requires("SETUP-PAIR-01", "SETUP-RESUME-01", "SETUP-UNKNOWN-01");
  const { page, state, count } = await fixture("setup?new=1", 390, { lostApproval: true });
  try {
    await page.waitForFunction(() => !document.querySelector("#create-form button").disabled);
    await page.locator("#create-form button").click();
    await page.clock.fastForward(3000);
    await page.waitForFunction(() => !document.getElementById("approve-form").hidden);
    assert.equal(await page.locator("#phone-code, #phone-fingerprint, #compared").count(), 0);
    assert.equal(await page.locator("#browser-fingerprint").textContent(), proof);
    assert.equal(count("/v1/enrollment/pairings"), 1);
    assert.ok(await page.locator("#approve-form button[type=submit]").evaluate(node => node.getBoundingClientRect().bottom <= innerHeight), "comparison and approval fit ordinary portrait");
    await page.getByRole("button", { name: "Values match — approve phone" }).click();
    await page.waitForFunction(() => document.getElementById("pair-status").textContent.includes("outcome is unknown"));
    assert.equal(count(`/v1/enrollment/pairings/${pairing}/approve`), 1);
    await page.reload();
    await page.waitForFunction(() => document.body.dataset.setupStage === "connect");
    assert.match(await page.locator("#setup-connection-status").textContent(), /Start connection/);
    assert.equal(count("/v1/enrollment/pairings"), 1);
    assert.equal(count(`/v1/enrollment/pairings/${pairing}/approve`), 1);
    assert.equal(state.requests.filter(r => r.method !== "GET" && !r.path.includes("pairings")).length, 0);
  } finally { await page.close(); }
});
test("SETUP-FRESH-01 replacement owner session refuses old comparison before mutation", async () => {
  requires("SETUP-FRESH-01");
  const { page, state, count } = await fixture("setup?new=1");
  try {
    await page.waitForFunction(() => !document.querySelector("#create-form button").disabled);
    await page.locator("#create-form button").click(); await page.clock.fastForward(3000);
    await page.waitForFunction(() => !document.getElementById("approve-form").hidden);
    state.session = account;
    await page.getByRole("button", { name: "Values match — approve phone" }).click();
    await page.waitForFunction(() => document.getElementById("pair-status").textContent.includes("sign-in changed"));
    assert.equal(count(`/v1/enrollment/pairings/${pairing}/approve`), 0);
    assert.equal(await page.locator("#approve-form").isVisible(), false);
  } finally { await page.close(); }
});
test("HOSTED-ACCOUNT-01 HOSTED-TERMS-01 HOSTED-CHECKOUT-01 served account and TEST checkout return reconcile without repeat purchase", async () => {
  requires("HOSTED-ACCOUNT-01", "HOSTED-TERMS-01", "HOSTED-CHECKOUT-01", "HOSTED-MODE-01");
  const { page, state, count } = await fixture("hosted", 390, { signedIn: false });
  try {
    await page.getByRole("button", { name: "Create account", exact: true }).first().click();
    await page.locator("#hosted-register-email").fill("owner@example.test"); await page.locator("#hosted-register-password").fill("synthetic-password");
    await page.locator("#hosted-register-form button").click();
    await page.locator("#hosted-verification-code").fill("synthetic-code"); await page.locator("#hosted-verify-password").fill("synthetic-password");
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(() => !document.getElementById("hosted-login-form").hidden && document.getElementById("hosted-verify").hidden);
    assert.equal(await page.locator("#hosted-email").inputValue(), "owner@example.test");
    await page.locator("#hosted-password").fill("synthetic-password"); await page.locator("#hosted-login-form button").click();
    await page.waitForFunction(() => !document.getElementById("hosted-checkout").hidden);
    assert.match(await page.locator("#hosted-plan-price").textContent(), /19.00.*month/);
    assert.match(await page.locator("#hosted-mode").textContent(), /TEST/);
    assert.ok(await page.locator("#hosted-checkout").evaluate(node => node.getBoundingClientRect().bottom <= innerHeight), "reviewed plan and purchase action fit ordinary portrait");
    await page.locator("#hosted-checkout").click();
    await page.waitForURL("https://checkout.stripe.com/**");
    await page.goto("https://example.test/owner/hosted?checkout=return");
    await page.waitForFunction(() => document.getElementById("hosted-billing-state").textContent.includes("Confirming your subscription"));
    assert.equal(await page.locator("#hosted-checkout").isVisible(), false);
    assert.equal(await page.locator("#hosted-phone").isVisible(), false);
    await page.clock.fastForward(10000);
    assert.equal(count("/v1/billing/checkout"), 1);
    state.billing = "active"; await page.locator("#hosted-refresh").click();
    await page.waitForFunction(() => !document.getElementById("hosted-phone").hidden);
    assert.match(await page.locator("#hosted-phone-status").textContent(), /TEST/);
    assert.equal(count("/v1/auth/register"), 1);
  } finally { await page.close(); }
});
test("HOSTED-CHECKOUT-01 success and canceled returns with stale empty projections wait without another purchase", async () => {
  requires("HOSTED-CHECKOUT-01");
  for (const result of ["return", "cancel"]) {
    const { page, state, count } = await fixture("hosted?checkout=" + result, 390, { billing: "new" });
    try {
      await page.waitForFunction(() => document.body.dataset.hostedPhase === "billing_pending");
      assert.equal(await page.locator("#hosted-checkout").isVisible(), false);
      assert.equal(await page.locator("#hosted-phone").isVisible(), false);
      await page.clock.fastForward(10000);
      assert.equal(count("/v1/billing/checkout"), 0);
      state.billing = "active";
      await page.locator("#hosted-refresh").click();
      await page.waitForFunction(() => !document.getElementById("hosted-phone").hidden);
      assert.equal(count("/v1/billing/checkout"), 0);
    } finally { await page.close(); }
  }
});

test("HOSTED-MODE-01 closed or LIVE service keeps sign-in and recovery without TEST purchase", async () => {
  requires("HOSTED-MODE-01", "HOSTED-SELF-01");
  for (const changes of [{ registration: "closed", signedIn: false }, { mode: "live", catalog: false }]) {
    const { page, count } = await fixture("hosted", 320, changes);
    try {
      await page.waitForFunction(() => !document.getElementById("hosted-status").textContent.startsWith("Checking"));
      assert.equal(await page.locator("#hosted-checkout").isVisible(), false);
      assert.equal(count("/v1/billing/checkout"), 0);
      assert.equal(await page.getByRole("link", { name: "Recover account access" }).count(), 1);
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    } finally { await page.close(); }
  }
});


test("SETUP-LINE-01 SETUP-LINE-02 current phone capability opens one generated ceremony and approves its exact SIM declaration", async () => {
  requires("SETUP-LINE-01", "SETUP-LINE-02", "HONEST-STATUS-01");
  const { page, count } = await fixture("setup", 390, { pair: true, approved: true, connected: true, lineFixture: true });
  try {
    await page.waitForFunction(() => !document.getElementById("activation-review").hidden);
    assert.equal(await page.locator("#activation-line").inputValue(), line);
    assert.equal(await page.locator("#activation-device").inputValue(), device);
    assert.equal(await page.locator("#review-count").textContent(), "2");
    assert.match(await page.locator("#review-kind").textContent(), /eSIM/);
    assert.equal(await page.locator("#activation-form").isVisible(), false, "known capability needs no manual setup request");
    assert.ok(await page.locator("#activation-approve").evaluate(node => node.getBoundingClientRect().bottom <= innerHeight), "line review and its action fit ordinary portrait");
    assert.equal(count(`/v1/auth/sms-lines/${line}/activations-v2`), 1);
    await page.reload();
    await page.waitForFunction(() => !document.getElementById("activation-review").hidden);
    assert.equal(count(`/v1/auth/sms-lines/${line}/activations-v2`), 1, "reload resumes the original public locator");
    await page.getByRole("button", { name: "Approve this phone and SIM", exact: true }).click();
    await page.waitForFunction(() => document.body.dataset.setupStage === "complete");
    assert.equal(count(`/v1/auth/sms-lines/${line}/activations-v2/${pairing}/approve`), 1);
    assert.match(await page.locator("#setup-complete").textContent(), /Carrier testing remains a separate/);
  } finally { await page.close(); }
});


test("SETUP-UNKNOWN-01 new-phone URL cannot replace an unfinished or unavailable saved attempt", async () => {
  requires("SETUP-UNKNOWN-01", "SETUP-RESUME-01");
  const pending = await fixture("setup?new=1", 390, { pair: true });
  try {
    await pending.page.waitForFunction(() => !document.getElementById("approve-form").hidden);
    await pending.page.locator("#create-form").evaluate(form => form.requestSubmit());
    assert.equal(pending.count("/v1/enrollment/pairings"), 0);
    assert.match(await pending.page.locator("#pair-status").textContent(), /Finish or cancel/);
  } finally { await pending.page.close(); }
  const unavailable = await fixture("setup?new=1", 390, { progressUnavailable: true });
  try {
    await unavailable.page.waitForFunction(() => document.getElementById("setup-resume-status").textContent.includes("Could not check"));
    assert.equal(await unavailable.page.locator("#create-form button").isDisabled(), true);
    assert.equal(unavailable.count("/v1/enrollment/pairings"), 0);
  } finally { await unavailable.page.close(); }
});


test("rendered workspace review captures use current served controllers and synthetic observations", async () => {
  if (!captureRoot) return;
  async function capture(page, name, width) {
    for (const scale of [1, 2]) {
      if (scale === 2) await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({ path: path.join(captureRoot, `${name}-${width}-${scale * 100}.png`), fullPage: true });
    }
  }
  for (const width of [390, 1440]) {
    const overview = await fixture("devices", width, { pair: true, approved: true, connected: true });
    try {
      await overview.page.getByRole("button", { name: "View details for Synthetic gateway", exact: true }).waitFor();
      await overview.page.waitForFunction(() => !document.getElementById("setup-resume-status").textContent.startsWith("Checking"));
      await capture(overview.page, "overview", width);
      await overview.page.addStyleTag({ content: "html { font-size: 100% !important; }" });
      await overview.page.getByRole("button", { name: "View details for Synthetic gateway", exact: true }).click();
      await capture(overview.page, "phone-details", width);
    } finally { await overview.page.close(); }
    const scan = await fixture("setup?new=1", width, { proofReady: false });
    try {
      await scan.page.waitForFunction(() => !document.querySelector("#create-form button").disabled);
      await scan.page.locator("#create-form button").click();
      await scan.page.waitForFunction(() => !document.getElementById("pair-ticket").hidden);
      await capture(scan.page, "setup-scan", width);
      scan.state.proofReady = true; await scan.page.addStyleTag({ content: "html { font-size: 100% !important; }" });
      await scan.page.clock.fastForward(3000);
      await scan.page.waitForFunction(() => !document.getElementById("approve-form").hidden);
      await capture(scan.page, "setup-compare", width);
    } finally { await scan.page.close(); }
    for (const [name, changes] of [["setup-connect", { pair: true, approved: true }], ["setup-security", { pair: true, approved: true, connected: true }],
      ["setup-line", { pair: true, approved: true, connected: true, lineFixture: true }], ["setup-recovery", { pair: true }]]) {
      const f = await fixture(name === "setup-recovery" ? `setup?pairing=${pairing}&approval=checking` : "setup", width, changes);
      try { await f.page.waitForFunction(() => !document.getElementById("setup-resume-status").textContent.startsWith("Checking"));
        if (name === "setup-line") await f.page.waitForFunction(() => !document.getElementById("activation-review").hidden);
        await capture(f.page, name, width);
      } finally { await f.page.close(); }
    }
    for (const [name, changes] of [["hosted-account", { signedIn: false }], ["hosted-plan", {}], ["hosted-pending", { billing: "pending" }]]) {
      const f = await fixture("hosted", width, changes);
      try { await f.page.waitForFunction(() => !document.getElementById("hosted-status").textContent.startsWith("Checking"));
        if (name === "hosted-plan") await f.page.waitForFunction(() => !document.getElementById("hosted-plan").hidden);
        if (name === "hosted-pending") await f.page.waitForFunction(() => document.getElementById("hosted-billing-state").textContent.includes("Confirming"));
        await capture(f.page, name, width);
      } finally { await f.page.close(); }
    }
  }
});


test("HOSTED-TERMS-01 rendered plan uses Stripe charge units for USD JPY ISK and UGX without rounding", async () => {
  requires("HOSTED-TERMS-01");
  for (const [currency, unitAmount, expected] of [["usd", 500, /5\.00/], ["jpy", 500, /500/], ["isk", 500, /5/], ["ugx", 500, /5/]]) {
    const { page, count } = await fixture("hosted", 390, { currency, unitAmount });
    try {
      await page.waitForFunction(() => !document.getElementById("hosted-plan").hidden);
      const price = await page.locator("#hosted-plan-price").textContent();
      assert.match(price, expected); assert.match(price, /every month/);
      if (["isk", "ugx"].includes(currency)) assert.doesNotMatch(price, /500/);
      assert.equal(await page.locator("#hosted-checkout").isVisible(), true);
      assert.equal(count("/v1/billing/checkout"), 0);
    } finally { await page.close(); }
  }
  const unsupported = await fixture("hosted", 390, { currency: "isk", unitAmount: 501 });
  try {
    await unsupported.page.waitForFunction(() => document.getElementById("hosted-plan-terms").textContent.includes("cannot be displayed exactly"));
    assert.equal(await unsupported.page.locator("#hosted-checkout").isVisible(), false);
  } finally { await unsupported.page.close(); }
});


test("HOSTED-ACCOUNT-01 SETUP-LINE-02 inline authenticator failure resumes the same step and saves recovery before the browser key", async () => {
  requires("HOSTED-ACCOUNT-01", "SETUP-LINE-02");
  const { page, count } = await fixture("setup", 390, { pair: true, approved: true, connected: true });
  try {
    await page.locator("#setup-mfa-password").fill("synthetic-password");
    await page.locator("#setup-mfa-enroll button").click();
    await page.locator("#setup-mfa-code").fill("000000"); await page.locator("#setup-mfa-confirm button").click();
    await page.waitForFunction(() => document.getElementById("setup-mfa-status").textContent.includes("same setup"));
    assert.equal(await page.locator("#setup-mfa-confirm").isVisible(), true);
    assert.equal(count("/v1/auth/mfa/enroll"), 1);
    await page.locator("#setup-mfa-code").fill("123456"); await page.locator("#setup-mfa-confirm button").click();
    await page.waitForFunction(() => !document.getElementById("setup-mfa-recovery").hidden);
    assert.equal(await page.locator("#key-form").isVisible(), false);
    await page.locator("#setup-mfa-saved").click();
    await page.waitForFunction(() => !document.getElementById("key-form").hidden);
    assert.equal(await page.locator("#setup-mfa-recovery-codes").textContent(), "");
    await page.reload();
    await page.waitForFunction(() => !document.getElementById("key-form").hidden);
    assert.equal(await page.locator("#setup-mfa-secret").textContent(), "");
    assert.equal(count("/v1/auth/mfa/enroll"), 1);
  } finally { await page.close(); }
});


test("UX-NAV-01 UX-OVERVIEW-01 six primary destinations and a bounded desktop inspector preserve the overview position", async () => {
  requires("UX-NAV-01", "UX-OVERVIEW-01");
  const { page, state } = await fixture("devices", 1440, { pair: true, approved: true, connected: true });
  try {
    assert.deepEqual(await page.locator(".owner-nav > a").allTextContents(), ["Overview", "Phones & lines", "Activity", "Integrations", "Team", "Settings"]);
    await page.getByRole("button", { name: "View details for Synthetic gateway", exact: true }).waitFor();
    const before = await page.locator("#approved-devices").evaluate(node => node.getBoundingClientRect().height);
    const summaryTop = await page.locator("#message-summary").evaluate(node => node.getBoundingClientRect().top);
    await page.getByRole("button", { name: "View details for Synthetic gateway", exact: true }).click();
    assert.equal(await page.locator("#approved-devices").evaluate(node => node.getBoundingClientRect().height), before);
    assert.equal(await page.locator("#message-summary").evaluate(node => node.getBoundingClientRect().top), summaryTop);
    assert.equal(await page.locator("#device-detail").evaluate(node => getComputedStyle(node).overflowY), "auto");
    const messages = state.requests.filter(r => r.path === "/v1/owner/messages").length;
    await page.getByRole("link", { name: "Phones & lines", exact: true }).click();
    await page.waitForURL("**/owner/phones");
    assert.equal(await page.locator("#phone-line-tools").isVisible(), true);
    assert.equal(await page.locator("#message-summary").isVisible(), false);
    await page.clock.fastForward(30000);
    assert.equal(state.requests.filter(r => r.path === "/v1/owner/messages").length, messages);
    await page.goBack(); await page.waitForURL("**/owner/devices");
    assert.equal(await page.locator(".owner-nav [aria-current=page]").textContent(), "Overview");
  } finally { await page.close(); }
});
