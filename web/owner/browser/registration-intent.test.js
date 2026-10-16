// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
const account = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", session = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const intent = "ztri_" + Buffer.alloc(32, 3).toString("base64url");
const proof = "ztrc_" + Buffer.alloc(32, 4).toString("base64url");
const ordinary = "ztc_" + Buffer.alloc(32, 5).toString("base64url");
let browser, captureRoot;
test.before(async () => { browser = await chromium.launch(); if (process.env.ZT_OWNER_SCREENSHOTS === "1") { captureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-registration-review-")); console.log("Registration screenshots: " + captureRoot); } });
test.after(async () => { await browser.close(); });
async function fixture(width = 390, changes = {}) {
  const page = await browser.newPage({ viewport: { width, height: width === 390 ? 844 : 900 } });
  const state = { requests: [], signedIn: false, registered: false, verified: false, code: "synthetic-email-code", ...changes };
  async function registrationCookies() {
    await page.context().addCookies([
      { name: "__Host-zrotext_registration_intent", value: intent, url: "https://example.test", secure: true, httpOnly: true, sameSite: "Strict", expires: Date.now() / 1000 + 900 },
      { name: "__Host-zrotext_registration_csrf", value: proof, url: "https://example.test", secure: true, sameSite: "Strict", expires: Date.now() / 1000 + 900 }
    ]);
  }
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), headers = await request.allHeaders();
    const body = request.postDataJSON();
    state.requests.push({ path: url.pathname, method: request.method(), body, headers });
    const json = (value, status = 200) => route.fulfill({ status, json: value });
    if (url.pathname.startsWith("/owner/")) {
      const file = url.pathname === "/owner/hosted" ? "hosted.html" : url.pathname.slice(7);
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType: file.endsWith("js") ? "text/javascript" : file.endsWith("css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/service/availability") return json({ schema_version: 1, deployment: "hosted", registration: "open", billing: "disabled", checkout_available: false, plan_catalog_available: false });
    if (url.pathname === "/v1/auth/session") return state.signedIn ? json({ role: "owner", account_id: account, session_id: session, user_id: account }) : json({}, 401);
    if (request.method() !== "POST" || headers.origin !== "https://example.test") return json({}, 403);
    if (url.pathname === "/v1/auth/register") {
      assert.deepEqual(Object.keys(body).sort(), ["email", "password"]);
      state.registered = true; await registrationCookies();
      if (state.lostRegistrationReply) return route.abort("connectionreset");
      return route.fulfill({ status: 202 });
    }
    if (url.pathname.startsWith("/v1/auth/registration-intent/")) {
      const cookies = (headers.cookie || "").split(";").map(value => value.trim());
      if (!cookies.includes("__Host-zrotext_registration_intent=" + intent) || !cookies.includes("__Host-zrotext_registration_csrf=" + proof) || headers["x-zrotext-registration-csrf"] !== proof) return json({}, 403);
      if (url.pathname.endsWith("/resend")) { assert.deepEqual(body, {}); state.code = "fresh-synthetic-email-code"; return route.fulfill({ status: 202 }); }
      assert.deepEqual(Object.keys(body), ["token"]);
      if (state.otherAccount) { state.signedIn = true; await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: ordinary, url: "https://example.test", secure: true, sameSite: "Strict" }]); return json({}, 409); }
      if (!state.registered || state.verified || body.token !== state.code) return json({}, 400);
      state.verified = true;
      if (state.lostReply) return route.abort("connectionreset");
      return route.fulfill({ status: 204 });
    }
    if (url.pathname === "/v1/auth/verify-email") { assert.deepEqual(Object.keys(body).sort(), ["password", "token"]); state.verified = true; return route.fulfill({ status: 204 }); }
    if (url.pathname === "/v1/auth/resend-verification") { assert.deepEqual(Object.keys(body).sort(), ["email", "password"]); return route.fulfill({ status: 202 }); }
    if (url.pathname === "/v1/auth/login") {
      assert.ok(state.verified, "normal sign-in happens after verification");
      assert.equal(body.password, "synthetic-password");
      state.signedIn = true;
      await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: ordinary, url: "https://example.test", secure: true, sameSite: "Strict" }]);
      return route.fulfill({ status: 204 });
    }
    return json({}, 404);
  });
  await page.goto("https://example.test/owner/hosted");
  await page.waitForFunction(() => ["sign_in", "unavailable"].includes(document.body.dataset.hostedPhase));
  const count = pathname => state.requests.filter(value => value.path === pathname && value.method === "POST").length;
  return { page, state, count, registrationCookies };
}
async function capture(page, name) {
  if (!captureRoot) return;
  const width = page.viewportSize().width;
  await page.screenshot({ path: path.join(captureRoot, `${name}-${width}-100.png`), fullPage: true });
  const style = await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
  await page.screenshot({ path: path.join(captureRoot, `${name}-${width}-200.png`), fullPage: true });
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  await style.evaluate(node => node.remove());
}
async function register(page) {
  await page.getByRole("button", { name: "Create account", exact: true }).first().click();
  await capture(page, "registration");
  await page.locator("#hosted-register-email").fill("owner@example.test");
  await page.locator("#hosted-register-password").fill("synthetic-password");
  await page.locator("#hosted-register-form button").click();
  await page.waitForFunction(() => document.body.dataset.hostedPhase === "verification_requested");
}
for (const width of [390, 1440]) test(`original-browser cookies support code-only verify and resend then explicit sign-in at ${width}px`, async () => {
  const { page, state, count } = await fixture(width);
  try {
    await register(page);
    await capture(page, "verification");
    assert.equal(await page.locator("#hosted-verify-password").isVisible(), false);
    assert.equal(await page.locator("#hosted-register-password").inputValue(), "");
    const cookie = await page.evaluate(() => document.cookie);
    assert.ok(cookie.includes("__Host-zrotext_registration_csrf="));
    assert.ok(!cookie.includes("__Host-zrotext_registration_intent="), "HttpOnly intent is unavailable to JavaScript");
    await page.locator("#hosted-verification-code").fill("wrong-code");
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(() => document.getElementById("hosted-status").textContent.includes("could not be verified"));
    await page.locator("#hosted-verify details summary").click();
    assert.equal(await page.locator("#hosted-resend-password").isVisible(), false);
    await page.locator("#hosted-resend-form button").click();
    await page.waitForFunction(() => document.getElementById("hosted-status").textContent.includes("fresh code"));
    await page.locator("#hosted-verification-code").fill(state.code);
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(() => document.body.dataset.hostedPhase === "sign_in");
    await capture(page, "sign-in");
    assert.equal(count("/v1/auth/login"), 0, "verification never signs in implicitly");
    assert.equal(await page.locator("#hosted-email").inputValue(), "owner@example.test");
    assert.equal(await page.locator("#hosted-password").inputValue(), "");
    assert.equal(await page.locator("#hosted-verification-code").inputValue(), "");
    assert.equal(count("/v1/auth/registration-intent/verify"), 2);
    assert.equal(count("/v1/auth/registration-intent/resend"), 1);
    assert.equal(count("/v1/auth/verify-email"), 0);
    assert.equal(count("/v1/auth/register"), 1);
    assert.ok(!(await page.context().cookies()).some(value => value.name === "__Host-zrotext_csrf"));
    await page.locator("#hosted-password").fill("synthetic-password");
    await page.locator("#hosted-login-form button").click();
    await page.waitForFunction(() => document.body.dataset.hostedPhase === "billing_unavailable");
    assert.equal(count("/v1/auth/login"), 1);
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  } finally { await page.close(); }
});
test("reload resumes with code only while another browser uses unchanged password verification", async () => {
  const original = await fixture();
  const other = await fixture();
  try {
    await register(original.page);
    await original.page.reload();
    await original.page.waitForFunction(() => ["sign_in", "unavailable"].includes(document.body.dataset.hostedPhase));
    await original.page.getByRole("button", { name: "Continue email verification" }).click();
    await original.page.waitForFunction(() => document.body.dataset.hostedPhase === "verification_requested");
    assert.equal(await original.page.locator("#hosted-verify-password").isVisible(), false);
    await other.page.getByRole("button", { name: "Continue email verification" }).click();
    await other.page.waitForFunction(() => document.body.dataset.hostedPhase === "verification_requested");
    assert.equal(await other.page.locator("#hosted-verify-password").isVisible(), true);
    await other.page.locator("#hosted-verification-code").fill("synthetic-email-code");
    await other.page.locator("#hosted-verify-password").fill("synthetic-password");
    await other.page.locator("#hosted-verify-form button").click();
    await other.page.waitForFunction(() => document.body.dataset.hostedPhase === "sign_in");
    assert.equal(other.count("/v1/auth/verify-email"), 1);
    assert.equal(other.count("/v1/auth/registration-intent/verify"), 0);
  } finally { await original.page.close(); await other.page.close(); }
});
test("expired original browser intent offers explicit password fallback without creating another account", async () => {
  const { page, state, count } = await fixture();
  try {
    await register(page); state.registered = false;
    await page.locator("#hosted-verification-code").fill(state.code);
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(() => document.getElementById("hosted-status").textContent.includes("could not be verified"));
    await page.getByRole("button", { name: "Use password verification instead" }).click();
    await page.waitForFunction(() => !document.getElementById("hosted-verify-password-field").hidden);
    await capture(page, "verification-fallback");
    await page.locator("#hosted-verification-code").fill(state.code);
    await page.locator("#hosted-verify-password").fill("synthetic-password");
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(() => document.body.dataset.hostedPhase === "sign_in");
    assert.equal(count("/v1/auth/register"), 1);
    assert.equal(count("/v1/auth/verify-email"), 1);
  } finally { await page.close(); }
});
for (const otherAccount of [false, true]) test(`uncertain verification checks current session without replay and preserves another account=${otherAccount}`, async () => {
  const { page, state, count } = await fixture(390, { lostReply: true, otherAccount });
  try {
    await register(page);
    const before = state.requests.filter(value => value.path === "/v1/auth/session").length;
    await page.locator("#hosted-verification-code").fill(state.code);
    await page.locator("#hosted-verify-form button").click();
    await page.waitForFunction(expected => document.body.dataset.hostedPhase === expected, otherAccount ? "existing_session" : "sign_in");
    assert.equal(state.requests.filter(value => value.path === "/v1/auth/session").length, before + 1);
    assert.equal(count("/v1/auth/register"), 1);
    assert.equal(count("/v1/auth/registration-intent/verify"), 1);
    assert.equal(count("/v1/auth/login"), 0);
    assert.equal(await page.locator("#hosted-password").inputValue(), "");
    assert.equal(await page.locator("#hosted-verification-code").inputValue(), "");
    if (otherAccount) {
      await capture(page, "existing-session");
      assert.equal(await page.getByRole("link", { name: "Open current workspace" }).isVisible(), true);
      assert.equal((await page.context().cookies()).find(value => value.name === "__Host-zrotext_csrf").value, ordinary);
    }
  } finally { await page.close(); }
});

test("lost registration reply checks the session and resumes verification without registering again", async () => {
  const { page, state, count } = await fixture(390, { lostRegistrationReply: true });
  try {
    await page.getByRole("button", { name: "Create account", exact: true }).first().click();
    await page.locator("#hosted-register-email").fill("owner@example.test");
    await page.locator("#hosted-register-password").fill("synthetic-password");
    const before = state.requests.filter(value => value.path === "/v1/auth/session").length;
    await page.locator("#hosted-register-form button").click();
    await page.waitForFunction(() => document.body.dataset.hostedPhase === "sign_in");
    assert.match(await page.locator("#hosted-status").textContent(), /registration result could not be confirmed/);
    assert.equal(state.requests.filter(value => value.path === "/v1/auth/session").length, before + 1);
    await page.getByRole("button", { name: "Continue email verification" }).click();
    await page.waitForFunction(() => document.body.dataset.hostedPhase === "verification_requested");
    assert.equal(await page.locator("#hosted-verify-password").isVisible(), false);
    assert.equal(count("/v1/auth/register"), 1);
  } finally { await page.close(); }
});
