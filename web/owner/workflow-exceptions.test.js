// SPDX-License-Identifier: AGPL-3.0-only
// Proposed response metadata and transport are synthetic, not PostgreSQL/auth acceptance.
"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { create, parsePage, parseSession } = require("./workflow-exceptions.js");
const A = "11111111-1111-4111-8111-111111111111", B = "22222222-2222-4222-8222-222222222222", C = "33333333-3333-4333-8333-333333333333";
const id = n => "44444444-4444-4444-8444-" + String(n).padStart(12, "0"), selection = { account: A, context: C };
const enc = value => new TextEncoder().encode(typeof value === "string" ? value : JSON.stringify(value));
const row = n => ({ account_id: A, context_id: C, id: id(n), context_revision: 1, source_kind: 1, source_id: id(90), reason: 1, request_digest: "\\x" + "ab".repeat(32), revision: 1, state: "pending", resolution_request_id: null, resolved_at: null, created_at: "2024-02-29T12:34:56.123456+00:00" });
const page = (items = [], next = null) => ({ account_id: A, context_id: C, items, next_cursor: next });
const owner = () => ({ account_id: A, user_id: id(91), session_id: id(92), role: "owner" });
test("extended empty binds independent account/context while all legacy pages refuse", () => {
  assert.equal(parsePage(enc(page()), selection).items.length, 0);
  for (const value of [{ items: [], next_cursor: null }, { items: [row(1)], next_cursor: null }, { ...page(), account_id: B }, { ...page(), context_id: B }]) assert.throws(() => parsePage(enc(value), selection));
});
test("all thirteen fields and actual source/reason and resolution combinations are closed", () => {
  for (const [kind, reason] of [[1, 1], [1, 5], [2, 2], [2, 3], [2, 4]]) assert.equal(parsePage(enc(page([{ ...row(1), source_kind: kind, reason }])), selection).items[0].reason, reason);
  assert.equal(parsePage(enc(page([{ ...row(1), revision: 2, state: "resolved", resolution_request_id: id(95), resolved_at: "2024-03-01T00:00:00Z" }])), selection).items[0].state, "resolved");
  for (const delta of [{ actor_user_id: A }, { context_revision: 129 }, { source_kind: 1, reason: 2 }, { resolution_request_id: id(96) }, { state: "resolved" }, { revision: 2 }, { account_id: B }, { context_id: B }, { source_id: "00000000-0000-0000-0000-000000000000" }]) assert.throws(() => parsePage(enc(page([{ ...row(1), ...delta }])), selection));
  const missing = row(1); delete missing.created_at; assert.throws(() => parsePage(enc(page([missing])), selection));
});
test("raw duplicate decoded keys, integer alternatives, nesting and UTF8 refuse", () => {
  const valid = JSON.stringify(page([row(1)]));
  for (const text of [valid.replace('"context_revision":1', '"context_revision":1,"context_revis\\u0069on":1'), valid.replace('"context_revision":1', '"context_revision":1e0'), valid.replace('"context_revision":1', '"context_revision":1.0'), valid.replace('"context_revision":1', '"context_revision":-1'), valid + "null", valid.replace('"state":"pending"', '"state":"\\ud800"'), valid.replace('"items":[{', '"items":[[{')]) assert.throws(() => parsePage(enc(text), selection));
  assert.throws(() => parsePage(Uint8Array.of(255), selection)); assert.throws(() => parsePage(Uint8Array.from([239, 187, 191, ...enc(page())]), selection));
  assert.throws(() => parsePage(enc('{"__proto__":{},"account_id":"' + A + '","context_id":"' + C + '","items":[],"next_cursor":null}'), selection));
});
test("provisional bytea/timestamps remain lexical and unsupported encodings refuse", () => {
  for (const delta of [{ request_digest: "ab".repeat(32) }, { request_digest: "\\x" + "AB".repeat(32) }, { created_at: "2023-02-29T00:00:00Z" }, { created_at: "infinity" }, { created_at: "2024-01-01T00:00:60Z" }, { created_at: "2024-01-01T00:00:00" }, { created_at: "<img src=x>" }]) assert.throws(() => parsePage(enc(page([{ ...row(1), ...delta }])), selection));
  assert.equal(parsePage(enc(page([{ ...row(1), created_at: "2000-02-29 00:00:00-03:30" }])), selection).items.length, 1);
});
test("ascending continuation is last of full twenty, without accumulated pages", () => {
  const items = Array.from({ length: 20 }, (_, n) => row(n + 1));
  assert.equal(parsePage(enc(page(items, id(20))), selection).next_cursor, id(20));
  assert.equal(parsePage(enc(page(items)), selection).next_cursor, null);
  assert.equal(parsePage(enc(page([row(21)])), selection, id(20)).items[0].id, id(21));
  for (const value of [page([], id(1)), page([row(1)], id(1)), page(items, id(19)), page([...items, row(21)]), page([row(2), row(1)]), page([row(1), row(1)])]) assert.throws(() => parsePage(enc(value), selection));
  assert.throws(() => parsePage(enc(page([row(20)])), selection, id(20)));
});
test("session is a closed owner observation, never the independently intended account", () => {
  assert.equal(parseSession(enc(owner()), A).account_id, A);
  for (const delta of [{ account_id: B }, { role: "member" }, { extra: true }, { session_id: "bad" }]) assert.throws(() => parseSession(enc({ ...owner(), ...delta }), A));
});

class Element extends EventTarget {
  constructor(name) { super(); this.name = name; this.value = ""; this.checked = false; this.disabled = false; this.textContent = ""; this.children = []; }
  append(...nodes) { for (const node of nodes) if (node.name === "fragment") this.children.push(...node.children); else this.children.push(node); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
}
function fixture(transport) {
  const elements = Object.fromEntries(["account", "context", "ack", "rows", "status", "read", "next", "clear"].map(k => ["exceptions-" + k, new Element(k)]));
  const document = new EventTarget(); document.cookie = "__Host-zrotext_csrf=synthetic-token"; document.hidden = false; document.getElementById = id => elements[id]; document.createElement = name => new Element(name); document.createDocumentFragment = () => new Element("fragment");
  const window = new EventTarget(); window.location = { origin: "https://exceptions.invalid" }; const requests = [];
  const client = create({ document, window, fetch: async (url, options) => { requests.push({ url, options }); return transport(url, options, requests.length); } });
  elements["exceptions-account"].value = A; elements["exceptions-context"].value = C; elements["exceptions-ack"].checked = true;
  return { client, document, window, elements, requests };
}
const response = value => Response.json(value);
const turn = () => new Promise(resolve => setTimeout(resolve, 0));
async function untilHeld(condition) {
  const end = performance.now() + 10000;
  while (!condition()) { assert.ok(performance.now() < end, "controlled held operation did not start"); await turn(); }
}
test("actual DOM controller renders only extended data with Cookie-only session and content CSRF", async () => {
  const f = fixture(url => response(url.endsWith("/session") ? owner() : page([row(1)])));
  try { await f.client.read(); assert.equal(f.elements["exceptions-rows"].children.length, 1); assert.match(f.elements["exceptions-rows"].children[0].textContent, /pending/); assert.equal(f.requests.length, 3); assert.equal(f.requests[0].options.headers["x-zrotext-csrf"], undefined); assert.equal(f.requests[1].options.headers["x-zrotext-csrf"], "synthetic-token"); assert.ok(f.requests.every(r => r.options.method === "GET" && r.options.credentials === "same-origin" && r.options.cache === "no-store" && !r.options.headers.authorization)); }
  finally { f.client.close(); }
});
test("silent remote session drift is detected by final observation, not synchronous Cookie magic", async () => {
  const f = fixture((url, _options, count) => response(url.endsWith("/session") ? count === 3 ? { ...owner(), session_id: id(93) } : owner() : page()));
  await f.client.read(); assert.equal(f.client.state().closed, true); assert.equal(f.elements["exceptions-rows"].children.length, 0);
});
test("session A-to-B-to-A never accepts even an empty independently B envelope", async () => {
  const f = fixture(url => response(url.endsWith("/session") ? owner() : { ...page(), account_id: B })); await f.client.read(); assert.equal(f.client.state().closed, true); assert.equal(f.elements["exceptions-rows"].children.length, 0);
});
test("Next copies its validated cursor then synchronously scrubs old rows before a held read", async () => {
  let release, calls = 0;
  const f = fixture(url => { calls++; if (calls === 4) return new Promise(resolve => { release = () => resolve(response(owner())); }); return response(url.endsWith("/session") ? owner() : page(Array.from({ length: 20 }, (_, n) => row(n + 1)), id(20))); });
  await f.client.read(); assert.equal(f.elements["exceptions-rows"].children.length, 20);
  const next = f.client.next(); assert.equal(f.elements["exceptions-rows"].children.length, 0); assert.equal(f.elements["exceptions-next"].disabled, true); f.client.close(); release(); await next; await turn(); assert.equal(f.elements["exceptions-rows"].children.length, 0);
});
test("local clear scrubs before abort and held actual fetch stays busy until late settlement", async () => {
  let release;
  const f = fixture(url => url.endsWith("/session") ? response(owner()) : new Promise(resolve => { release = () => resolve(response(page([row(1)]))); }));
  const work = f.client.read(); await untilHeld(() => release); f.client.close(); await work;
  assert.equal(f.client.state().busy, true); assert.equal(f.elements["exceptions-rows"].children.length, 0); const text = f.elements["exceptions-status"].textContent;
  release(); await turn(); await turn(); assert.equal(f.client.state().busy, false); assert.equal(f.client.state().closed, true); assert.equal(f.elements["exceptions-status"].textContent, text); assert.equal(f.elements["exceptions-rows"].children.length, 0); await f.client.read(); assert.equal(f.requests.length, 2);
});
test("silent token rotation at actual body check refuses, plus body cap independently of length header", async () => {
  for (const mode of ["token", "cap", "legacy", "bad-media"]) {
    let f;
    f = fixture(url => {
      if (url.endsWith("/session")) return response(owner());
      if (mode === "token") f.document.cookie = "__Host-zrotext_csrf=changed-token";
      if (mode === "cap") return new Response(new Uint8Array(65537), { headers: { "content-type": "application/json", "content-length": "1" } });
      if (mode === "bad-media") return new Response(enc(page()), { headers: { "content-type": "text/plain" } });
      return response(mode === "legacy" ? { items: [], next_cursor: null } : page());
    });
    await f.client.read(); assert.equal(f.client.state().closed, true, mode); assert.equal(f.elements["exceptions-rows"].children.length, 0, mode);
  }
});
test("observed local context, acknowledgement and hidden lifecycle close the actual controller", async () => {
  for (const mode of ["context", "ack", "hidden"]) {
    let release; const f = fixture(url => url.endsWith("/session") ? response(owner()) : new Promise(resolve => { release = () => resolve(response(page([row(1)]))); }));
    const work = f.client.read(); await untilHeld(() => release);
    if (mode === "context") { f.elements["exceptions-context"].value = B; f.elements["exceptions-context"].dispatchEvent(new Event("input")); }
    if (mode === "ack") { f.elements["exceptions-ack"].checked = false; f.elements["exceptions-ack"].dispatchEvent(new Event("change")); }
    if (mode === "hidden") { f.document.hidden = true; f.document.dispatchEvent(new Event("visibilitychange")); }
    assert.equal(f.client.state().closed, true, mode); assert.equal(f.elements["exceptions-rows"].children.length, 0, mode); await work; release(); await turn(); assert.equal(f.elements["exceptions-rows"].children.length, 0, mode);
  }
});
test("actual streamed body cancellation stays charged until its owned cancellation promise settles", async () => {
  let releaseCancel, bodyRead = false;
  const stream = new ReadableStream({ pull() { bodyRead = true; }, cancel() { return new Promise(resolve => { releaseCancel = resolve; }); } }, { highWaterMark: 0 });
  const f = fixture(url => url.endsWith("/session") ? response(owner()) : new Response(stream, { headers: { "content-type": "application/json" } }));
  const work = f.client.read(); await untilHeld(() => bodyRead); f.client.close(); await work; await untilHeld(() => releaseCancel);
  assert.equal(f.client.state().busy, true); assert.equal(f.elements["exceptions-rows"].children.length, 0); releaseCancel(); await turn(); await turn();
  assert.equal(f.client.state().busy, false); assert.equal(f.client.state().closed, true); assert.equal(f.elements["exceptions-rows"].children.length, 0);
});
test("original ten-second cutoff closes without a forcing method and late work cannot revive", { timeout: 15000 }, async () => {
  let release; const f = fixture(() => new Promise(resolve => { release = () => resolve(response(owner())); })); const work = f.client.read();
  // A fixed upper bound captured just AFTER dispatch; never a fresh horizon after refusal.
  const cutoff = performance.now() + 10000; await new Promise(resolve => setTimeout(resolve, Math.max(0, cutoff - performance.now()))); await turn();
  assert.equal(f.elements["exceptions-status"].textContent, "Exceptions page closed. Reload for a fresh selection."); assert.equal(f.client.state().busy, true); await work; release(); await turn(); assert.equal(f.client.state().closed, true); await f.client.read(); assert.equal(f.requests.length, 1);
});
