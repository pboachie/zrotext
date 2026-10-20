// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), path = require("node:path");
const { createRequire } = require("node:module"), { pathToFileURL } = require("node:url");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const recovery = require("./conversation-manifest03-recovery.js"), controller = require("./conversation-manifest03-history.js");
const load = n => import(pathToFileURL(path.join(__dirname, "../../sdk/typescript/dist", n + ".js")).href);
const hex = b => Buffer.from(b).toString("hex"), b64 = b => Buffer.from(b).toString("base64url");
async function fixture() {
  const helpers = await import("../../sdk/typescript/test/manifest-history03-fixture.mjs"), f = await helpers.fixture({ originalProofs: true });
  const text = helpers.text, key = await helpers.key(); await f.step(key);
  const name = "manifest-history-test-" + crypto.randomUUID(), calls = [], instances = [];
  f.sessionId = text(f.session); f.mono = 0;
  f.document = { hidden: false, cookie: "__Host-zrotext_csrf=ztc_" + b64(new Uint8Array(32).fill(11)), addEventListener() {}, removeEventListener() {} };
  f.window = { location: { origin: f.origin }, addEventListener() {}, removeEventListener() {} };
  f.selection = { enabled: true, retentionConsent: true, compared: true, origin: f.origin, account_id: text(f.account), device_id: text(f.device), line_id: text(f.line),
    rootFingerprint: hex(f.fingerprint), pairedFingerprint: hex(await helpers.sha(f.phone.point)), manifestVersion: "1", manifestDigest: hex(f.compared.priorDigest) };
  f.file = { size: 65, arrayBuffer: async () => f.phone.point.slice().buffer };
  f.fetch = async (url, options = {}) => {
    const route = new URL(url, f.origin).pathname; calls.push({ route, body: options.body && JSON.parse(options.body) });
    let value;
    if (route === "/v1/auth/session") value = { role: "owner", account_id: text(f.account), user_id: text(f.user), session_id: f.sessionId };
    else if (route.endsWith("/original")) value = { v: 1, kind: "manifest_original03", line_id: text(f.line), binding_id: text(f.binding), evidence: f.evidence };
    else if (route.endsWith("/history")) {
      const after = BigInt(JSON.parse(options.body).after_version), start = Number(after - 2n);
      value = f.page(start, Math.min(start + 8, f.rows.length));
    } else if (route.endsWith("/current")) { value = await f.wireCurrent(); value.owner_session_id = f.sessionId;
      value.owner_session_digest = b64(await helpers.hash("ZTSE/line/payload-profile/owner-session/v1", f.account, f.user, Uint8Array.from(Buffer.from(f.sessionId.replaceAll("-", ""), "hex"))));
    } else throw Error("Unexpected synthetic route");
    return new Response(JSON.stringify(value), { headers: { "content-type": "application/json" } });
  };
  f.openStore = options => recovery.open({ ...options, name });
  f.create = (extra = {}) => { const c = controller.create({ enabled: true, readSelection: () => f.selection, document: f.document, window: f.window,
    fetch: f.fetch, monotonic: () => f.mono, importSdk: load, openRecovery: f.openStore, ...extra }); instances.push(c); return c; };
  f.calls = calls; f.close = () => instances.forEach(c => c.close()); f.key = key; return f;
}
test("actual fixed original proofs history and committed browser highwater compose before current selection", async () => {
  const f = await fixture(); try {
    const c = f.create(); await c.open(f.file); assert.equal(c.state().phase, "reading_history");
    await assert.rejects(c.current()); await c.next(); assert.equal(c.state().durable, true);
    assert.equal(c.state().phase, "verified_history"); const current = await c.current();
    assert.equal(current.currentAuthority.manifestVersion, 3n); assert.equal(c.checkpoint().position.version, 3n);
    assert.deepEqual(f.calls.filter(v => v.body).map(v => v.route.split("/").at(-1)), ["original", "history", "current"]);
    assert.equal(f.calls.some(v => v.body && ("password" in v.body || "factor" in v.body || "signature" in v.body)), false);
  } finally { f.close(); }
});
test("fresh same-user sign-in restores public highwater and rechecks originals without an old opening or new key", async () => {
  const f = await fixture(); try {
    const c = f.create(); await c.open(f.file); await c.next(); c.close(); f.sessionId = crypto.randomUUID();
    const again = f.create(); await again.open(f.file); assert.equal(again.state().durable, false);
    await again.next(); assert.equal(again.state().durable, true); await again.current();
    assert.equal(f.calls.filter(v => v.route.endsWith("/original")).length, 2);
    assert.equal(f.calls.filter(v => v.body && "opening_id" in v.body).length, 0);
  } finally { f.close(); }
});
test("history work stays bounded across explicit pages and a retained middle highwater", async () => {
  const f = await fixture(); try {
    const c = f.create(); await c.open(f.file); await c.next(); c.close();
    for (let i = 1; i < 19; i++) await f.step(f.key);
    const again = f.create(); await again.open(f.file);
    await again.next(); assert.equal(again.state().complete, false); assert.equal(again.state().version, "10");
    assert.throws(() => again.checkpoint()); await again.next(); assert.equal(again.state().complete, false);
    await again.next(); assert.equal(again.state().complete, true); assert.equal(again.state().version, "21");
  } finally { f.close(); }
});
test("saved higher checkpoint prevents actual original-server rollback before any current permission read", async () => {
  const f = await fixture(); try {
    const c = f.create(); await c.open(f.file); await c.next(); c.close();
    f.rows = []; f.version = 2n; f.digest = f.firstPosition.digest; f.prefix = f.firstPosition.ancestry; f.acceptedMs = 10000n;
    const again = f.create(); await again.open(f.file); await assert.rejects(again.next()); await assert.rejects(again.current());
    assert.equal(again.state().durable, false); assert.equal(f.calls.some(v => v.route.endsWith("/current")), false);
  } finally { f.close(); }
});
test("unknown durable commit exposes no current value and fresh reopen reconciles actual retained checkpoint", async () => {
  const f = await fixture(); try {
    const c = f.create({ openRecovery: async options => { const store = await f.openStore(options); return { ...store, compareAndSet: async (...args) => { await store.compareAndSet(...args); throw Error("Synthetic response lost after durable commit"); } }; } });
    await c.open(f.file); await assert.rejects(c.next()); await assert.rejects(c.current()); assert.equal(c.state().durable, false); c.close();
    const again = f.create(); await again.open(f.file); await again.next(); assert.equal(again.state().durable, true);
  } finally { f.close(); }
});
test("changed independently compared point original evidence or sign-in withdraws setup", async () => {
  const f = await fixture(); try {
    const c = f.create(); await c.open(f.file); f.sessionId = crypto.randomUUID(); await assert.rejects(c.next());
    assert.equal(c.state().durable, false); c.close();
    const bad = f.create(); f.evidence.activation_evidence = "AQ"; await assert.rejects(bad.open(f.file));
    assert.equal(f.calls.some(v => v.route.endsWith("/current")), false);
  } finally { f.close(); }
});
test("hidden page csrf replacement and monotonic rollback close history before another request", async () => {
  for (const mode of ["hidden", "csrf", "clock"]) {
    const f = await fixture(); try {
      const c = f.create(); f.mono = 10; await c.open(f.file); const count = f.calls.length;
      if (mode === "hidden") f.document.hidden = true; else if (mode === "csrf") f.document.cookie = ""; else f.mono = 9;
      await assert.rejects(c.next()); assert.equal(c.state().closed, true); assert.equal(f.calls.length, count);
    } finally { f.close(); }
  }
});
test("one bounded operation closes and rejects even when a session transport ignores cancellation", async () => {
  const f = await fixture(); try {
    const c = f.create({ fetch: () => new Promise(() => {}), timeoutMs: 10 });
    await assert.rejects(c.open(f.file)); assert.equal(c.state().closed, true); assert.equal(c.state().busy, false);
  } finally { f.close(); }
});
