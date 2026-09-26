// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const fs = require("node:fs");
const { randomUUID } = require("node:crypto");
const core = require("./template-preview-core.js");
const source = fs.readFileSync(require.resolve("./template-preview.js"), "utf8");
const tick = () => new Promise(setImmediate);
const identity = () => ({ account_id: randomUUID(), user_id: randomUUID(), session_id: randomUUID() });
const response = (body, status = 200) => ({ ok: status === 200, status, json: async () => body });
function deferred() { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; }

async function page({ signedIn = true } = {}) {
  const elements = new Map(), windowEvents = {}, documentEvents = {}, intervals = new Map();
  const calls = [];
  let sequence = 0, session = identity(), nextResponse = null;
  function element(id) {
    if (!elements.has(id)) elements.set(id, {
      value: "", textContent: "", disabled: true, listeners: {},
      addEventListener(event, listener) { this.listeners[event] = listener; },
      set innerHTML(_) { throw new Error("HTML rendering is forbidden"); },
    });
    return elements.get(id);
  }
  const document = { hidden: false, cookie: signedIn ? "__Host-zrotext_csrf=ztc_synthetic" : "",
    getElementById: element, addEventListener(event, listener) { documentEvents[event] = listener; } };
  const context = vm.createContext({
    document, window: { addEventListener(event, listener) { windowEvents[event] = listener; } },
    ZtTemplatePreview: core, AbortController,
    setTimeout: () => ++sequence, clearTimeout() {},
    setInterval(fn) { const id = ++sequence; intervals.set(id, fn); return id; },
    clearInterval(id) { intervals.delete(id); },
    console: { log() { throw new Error("logging is forbidden"); }, error() { throw new Error("logging is forbidden"); } },
    fetch: async (path, options) => {
      calls.push({ path, options });
      if (nextResponse) { const reply = nextResponse; nextResponse = null; return reply; }
      if (path === "/v1/auth/session") return response(session);
      if (path === "/v1/auth/logout") { document.cookie = ""; return response(null); }
      throw new Error("Unexpected network request");
    },
  });
  for (const name of ["localStorage", "sessionStorage", "indexedDB"]) Object.defineProperty(context, name, {
    get() { throw new Error("persistence is forbidden"); },
  });
  vm.runInContext(source, context);
  await tick();
  return { element, calls, document, windowEvents, documentEvents, intervals,
    session() { return { ...session }; },
    reply(value) { nextResponse = value; }, changeOwner() { session = identity(); },
    click(id) { return element(id).listeners.click(); },
    enter(id, value) { element(id).value = value; element(id).listeners.input(); },
  };
}

test("signed-out owner cannot enter or render text", async () => {
  const p = await page({ signedIn: false });
  assert.equal(p.element("editor").disabled, true);
  await p.click("preview");
  assert.equal(p.element("output").textContent, "");
  assert.equal(p.calls.length, 0);
});

test("preview uses literal text only and never uploads inputs", async () => {
  const p = await page();
  assert.equal(p.element("editor").disabled, false);
  p.enter("template", "Hello {{name}}");
  p.enter("substitutions", "name=<img src=x onerror=alert(1)>😀");
  await p.click("preview");
  assert.equal(p.element("output").textContent, "Hello <img src=x onerror=alert(1)>😀");
  p.enter("template", "{{missing}}");
  assert.equal(p.element("output").textContent, "");
  await p.click("preview");
  assert.match(p.element("preview-status").textContent, /no value/);
  for (const call of p.calls) {
    assert.equal(call.path, "/v1/auth/session");
    assert.equal(call.options.body, undefined);
    assert.equal(call.options.cache, "no-store");
    assert.equal(call.options.redirect, "error");
  }
  assert.equal(JSON.stringify(p.calls).includes("<img"), false);
});

test("a changed owner or session clears old text before rendering", async () => {
  const p = await page();
  p.enter("template", "private fixture");
  p.changeOwner();
  await p.click("preview");
  assert.equal(p.element("template").value, "");
  assert.equal(p.element("output").textContent, "");
});

test("cookie change or session failure clears all inputs and output", async () => {
  for (const result of [response({}, 401), response({}, 403), response({}), "offline"]) {
    const p = await page();
    p.enter("template", "fixture"); p.enter("substitutions", "name=value");
    p.reply(result === "offline" ? Promise.reject(new Error("offline")) : result);
    await p.click("preview");
    assert.equal(p.element("template").value, "");
    assert.equal(p.element("substitutions").value, "");
    assert.equal(p.element("output").textContent, "");
    assert.equal(p.element("editor").disabled, true);
  }
  const p = await page();
  p.document.cookie = "__Host-zrotext_csrf=ztc_other_synthetic";
  p.enter("template", "fixture");
  assert.equal(p.element("template").value, "");
});

test("old auth completion cannot restore text after navigation and a new owner", async () => {
  const p = await page();
  p.enter("template", "old fixture");
  const old = deferred(); p.reply(old.promise);
  const pending = p.click("preview");
  p.windowEvents.pagehide();
  assert.equal(p.element("template").value, "");
  p.changeOwner(); p.windowEvents.pageshow(); await tick();
  p.enter("template", "new fixture");
  old.resolve(response(identity())); await pending;
  assert.equal(p.element("template").value, "new fixture");
  assert.equal(p.element("output").textContent, "");
});

test("signout clears immediately and ignores older authentication", async () => {
  const p = await page();
  p.enter("template", "private fixture");
  const old = deferred(); p.reply(old.promise);
  const pending = p.click("preview");
  await p.click("sign-out");
  old.resolve(response(identity())); await pending;
  assert.equal(p.element("template").value, "");
  assert.equal(p.element("editor").disabled, true);
  const logout = p.calls.find((call) => call.path === "/v1/auth/logout");
  assert.equal(logout.options.method, "POST");
  assert.equal(logout.options.body, undefined);
  assert.equal(logout.options.headers["x-zrotext-csrf"], "ztc_synthetic");
});

test("clear and editing invalidate an in-flight preview", async () => {
  for (const action of ["clear", "edit"]) {
    const p = await page();
    p.enter("template", "old fixture");
    const old = deferred(); p.reply(old.promise);
    const pending = p.click("preview");
    if (action === "clear") await p.click("clear");
    else p.enter("template", "new fixture");
    old.resolve(response(p.session())); await pending;
    assert.equal(p.element("output").textContent, "");
  }
});

test("a cookie change during authentication cannot authorize old text", async () => {
  const p = await page();
  p.enter("template", "old fixture");
  const old = deferred(); p.reply(old.promise);
  const pending = p.click("preview");
  p.document.cookie = "__Host-zrotext_csrf=ztc_next_synthetic";
  old.resolve(response(p.session())); await pending;
  assert.equal(p.element("template").value, "");
  assert.equal(p.element("editor").disabled, true);
});

test("unload and periodic session loss erase the page", async () => {
  for (const action of ["unload", "poll"]) {
    const p = await page();
    p.enter("template", "private fixture");
    await p.click("preview");
    if (action === "unload") p.windowEvents.beforeunload();
    else { p.reply(response({}, 401)); await [...p.intervals.values()][0](); }
    assert.equal(p.element("template").value, "");
    assert.equal(p.element("output").textContent, "");
    assert.equal(p.element("editor").disabled, true);
  }
});


test("switching tabs preserves a hidden draft only after the same session is verified", async () => {
  const p = await page();
  p.enter("template", "Hello {{name}}"); p.enter("substitutions", "name=Alex");
  await p.click("preview");
  p.document.hidden = true; p.documentEvents.visibilitychange();
  assert.equal(p.element("editor").disabled, true);
  assert.equal(p.element("editor").hidden, true);
  assert.equal(p.element("output").hidden, true);
  assert.equal(p.intervals.size, 0);
  const check = deferred(); p.reply(check.promise);
  p.document.hidden = false; p.documentEvents.visibilitychange();
  assert.equal(p.element("editor").hidden, true);
  check.resolve(response(p.session())); await tick();
  assert.equal(p.element("editor").disabled, false);
  assert.equal(p.element("editor").hidden, false);
  assert.equal(p.element("template").value, "Hello {{name}}");
  assert.equal(p.element("substitutions").value, "name=Alex");
  assert.equal(p.element("output").textContent, "Hello Alex");
});

test("owner changes and revocation while hidden clear drafts before revealing the editor", async () => {
  for (const action of ["owner", "revoke", "cookie"]) {
    const p = await page();
    p.enter("template", "private fixture"); await p.click("preview");
    const stale = deferred(); p.reply(stale.promise);
    const pending = p.click("check-session");
    p.document.hidden = true; p.documentEvents.visibilitychange();
    stale.resolve(response(p.session())); await pending;
    assert.equal(p.element("editor").hidden, true);
    if (action === "owner") p.changeOwner();
    else if (action === "cookie") p.document.cookie = "__Host-zrotext_csrf=ztc_new_synthetic";
    else p.reply(response({}, 401));
    p.document.hidden = false; p.documentEvents.visibilitychange(); await tick();
    assert.equal(p.element("template").value, "");
    assert.equal(p.element("output").textContent, "");
    assert.equal(p.element("editor").disabled, action === "revoke");
  }
});
