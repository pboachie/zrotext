// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { OwnerReviewedSendClient03, captureReviewedSendRecovery03 } from "../dist/owner-reviewed-send03.js";
import { captureTrustedReviewContext03, prepareReviewedIntent03V2, reviewedIntentTranscript03V2, verifyReviewedIntent03V2,
  prepareReviewedIntent03, reviewedIntentTranscript03, verifyReviewedIntent03 } from "../dist/reviewed-intent03.js";
import { fixture, inputFor, uuid, enc, present, clone, composeSealedOutboundEnvelope03, canonicalP256Signature, sha } from "./fixtures/profile03-outbound-fixture.mjs";
const b64 = bytes => Buffer.from(bytes).toString("base64url");
const id = bytes => Buffer.from(bytes).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
const json = (value, status = 201) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const sign = async (f, bytes) => canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.privateKey, bytes)));
async function packet(smsCeiling = 1) {
  const f = await fixture(), composition = inputFor(f), out = await composeSealedOutboundEnvelope03(composition);
  const context = await captureTrustedReviewContext03({ currentAuthority: clone(f.authority), manifest: f.currentManifest, acceptedElection: f.proof,
    accountSelectionEpoch: 1n, ownerUserId: uuid(140), ownerSessionId: uuid(160), canonicalOrigin: "https://example.test", intervalId: uuid(180),
    intervalFromMs: 20_000n, intervalUntilMs: 60_000n, peer: enc.encode("+12"), signerKeyId: f.records[4].id.slice(),
    recipients: f.records.slice(0, 3).map(r => ({ role: r.role, keyId: r.id.slice() })), nowMs: present });
  const input = { context, envelope: out.envelope, reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling, nowMs: present };
  const intent = await prepareReviewedIntent03V2(input), signature = await sign(f, reviewedIntentTranscript03V2(intent));
  const proof = await verifyReviewedIntent03V2({ context, envelope: out.envelope, intent, signature, nowMs: present });
  const scope = { origin: "https://example.test", accountId: id(f.authority.accountId), userId: id(uuid(140)), ownerSessionId: id(uuid(160)),
    deviceId: id(f.authority.deviceId), lineId: id(f.authority.lineId), rootFingerprint: f.fingerprint.slice() };
  const receipt = { v: 1, message_id: id(composition.messageId), interval_id: id(uuid(180)), accepted_ms: "30000", expires_ms: "40000",
    selection_epoch: "1", envelope_sha256: b64(await sha(out.envelope)), reviewed_intent_sha256: b64(await sha(intent)),
    reviewed_signature_sha256: b64(await sha(signature)), sms_ceiling: smsCeiling };
  const record = { v: 1, origin: scope.origin, account_id: scope.accountId, user_id: scope.userId, owner_session_id: scope.ownerSessionId,
    device_id: scope.deviceId, line_id: scope.lineId, root_fingerprint: b64(scope.rootFingerprint),
    packet: { v: 1, envelope: b64(out.envelope), reviewed_intent: b64(intent), reviewed_signature: b64(signature) } };
  return { f, context, input, composition, proof, record, receipt, scope };
}
function client(p, changes = {}) {
  const c = { saved: [], calls: [], events: [], now: present, csrf: "ztc_" + b64(new Uint8Array(32).fill(1)), abort: new AbortController() };
  c.options = { ...p.scope, signal: c.abort.signal, currentCsrf: () => c.csrf, nowMs: () => c.now,
    saveBeforeSubmit: async r => { c.events.push("saved"); c.saved.push(structuredClone(r)); },
    fetchImpl: async (url, options) => { c.events.push("fetch"); c.calls.push({ url, options }); return json(p.receipt); }, ...changes };
  c.client = new OwnerReviewedSendClient03(c.options); return c;
}

test("genuine V2 sends exact public packet only after retention with fixed cookie/CSRF transport", async () => {
  const p = await packet(), c = client(p), receipt = await c.client.send(p.proof);
  assert.deepEqual(receipt, p.receipt); assert.deepEqual(c.events, ["saved", "fetch"]);
  assert.deepEqual(c.saved, [p.record]); assert.equal(c.calls.length, 1);
  const { url, options: o } = c.calls[0]; assert.equal(url, "https://example.test/v1/owner/conversation/send03");
  assert.deepEqual(JSON.parse(o.body), p.record.packet); assert.equal(o.method, "POST"); assert.equal(o.mode, "same-origin");
  assert.equal(o.credentials, "same-origin"); assert.equal(o.redirect, "error"); assert.equal(o.cache, "no-store");
  assert.equal(o.headers["x-zrotext-csrf"], c.csrf); assert.equal(Object.hasOwn(o.headers, "authorization"), false);
  assert.equal(JSON.stringify(c.saved).includes(p.composition.content), false);
});

test("all six authenticated segment ceilings survive the receipt grammar", async () => {
  for (let ceiling = 1; ceiling <= 6; ceiling++) {
    const p = await packet(ceiling), c = client(p);
    assert.equal((await c.client.send(p.proof)).sms_ceiling, ceiling);
  }
});

test("receipt parser rejects escaped duplicates, non-integers, extra records and invalid UTF-8", async () => {
  const p = await packet(), raw = JSON.stringify(p.receipt);
  const bad = [raw.replace('"v":1', '"v":1,"\\u0076":1'), raw + '{}', raw.replace('"v":1', '"v":1.0'),
    raw.replace('"v":1', '"v":1e0'), raw.replace('"v":1', '"v":true'), raw.replace('"sms_ceiling":1', '"sms_ceiling":7'),
    raw.replace('"sms_ceiling":1', '"sms_ceiling":12'), raw.replace('"v":1', '"v":01'), raw.slice(0, -1),
    new Uint8Array([0xff, 0xfe]), new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode(raw)])];
  for (const body of bad) {
    const c = client(p, { fetchImpl: async () => new Response(body, { status: 201, headers: { 'content-type': 'application/json' } }) });
    await assert.rejects(c.client.send(p.proof)); assert.deepEqual(c.saved, [p.record]);
  }
});

test("passive exact-original status works after expiry and a later same-user sign-in without a device clock", async () => {
  const p = await packet(), c = client(p, { ownerSessionId: id(uuid(210)), nowMs: () => { throw Error("no live device clock"); },
    fetchImpl: async (url, o) => { c.calls.push({ url, options: o }); return json(p.receipt, 200); } });
  assert.deepEqual(await c.client.status(p.record), p.receipt); assert.equal(c.saved.length, 0);
  assert.equal(c.calls[0].url, "https://example.test/v1/owner/conversation/send03/status");
  assert.deepEqual(JSON.parse(c.calls[0].options.body), { v: 1, message_id: p.receipt.message_id, interval_id: p.receipt.interval_id,
    envelope_sha256: p.receipt.envelope_sha256, reviewed_intent_sha256: p.receipt.reviewed_intent_sha256, reviewed_signature_sha256: p.receipt.reviewed_signature_sha256 });
  await assert.rejects(c.client.send(p.proof)); assert.equal(c.calls.length, 1);
});

test("genuine V1 proof/packet and forged V2 handles cannot enter new submission or recovery", async () => {
  const p = await packet(), intent = await prepareReviewedIntent03({ ...p.input, body: p.composition.content });
  const signature = await sign(p.f, reviewedIntentTranscript03(intent));
  const proof = await verifyReviewedIntent03({ context: p.context, envelope: p.input.envelope, intent, signature, nowMs: present });
  for (const bad of [proof, {}, structuredClone(p.proof)]) {
    const c = client(p); await assert.rejects(c.client.send(bad)); assert.equal(c.calls.length, 0); assert.equal(c.saved.length, 0);
  }
  await assert.rejects(captureReviewedSendRecovery03({ ...p.record, packet: { ...p.record.packet, reviewed_intent: b64(intent), reviewed_signature: b64(signature) } }));
});

test("configured origin/root/owner/session/device/line must match before persistence and network", async () => {
  const p = await packet();
  for (const changes of [{ origin: "https://other.test" }, { accountId: id(uuid(210)) }, { userId: id(uuid(210)) },
    { ownerSessionId: id(uuid(210)) }, { deviceId: id(uuid(210)) }, { lineId: id(uuid(210)) }, { rootFingerprint: new Uint8Array(32).fill(8) }]) {
    const c = client(p, changes); await assert.rejects(c.client.send(p.proof)); assert.equal(c.calls.length, 0); assert.equal(c.saved.length, 0);
  }
});

test("callback failure, rotated CSRF, expiry, clock rollback and abort after retention prevent upload", async () => {
  const p = await packet();
  for (const mode of ["save", "csrf", "expired", "rollback", "abort"]) {
    const c = client(p, { saveBeforeSubmit: async r => {
      c.saved.push(r);
      if (mode === "save") throw Error("synthetic storage failure");
      if (mode === "csrf") c.csrf = "ztc_" + b64(new Uint8Array(32).fill(2));
      if (mode === "expired") c.now = 35_000n;
      if (mode === "rollback") c.now--;
      if (mode === "abort") c.abort.abort();
    } });
    await assert.rejects(c.client.send(p.proof)); assert.equal(c.saved.length, 1); assert.equal(c.calls.length, 0);
  }
});

test("closed receipt compares all original identities, three hashes, times, epoch and authenticated ceiling", async () => {
  const p = await packet();
  for (const change of [{ message_id: id(uuid(210)) }, { interval_id: id(uuid(210)) }, { accepted_ms: "35000" }, { accepted_ms: "29999" },
    { accepted_ms: "30001" }, { expires_ms: "40001" }, { selection_epoch: "2" }, { sms_ceiling: 6 }, { sms_ceiling: "1" },
    { envelope_sha256: b64(new Uint8Array(32).fill(8)) }, { reviewed_intent_sha256: b64(new Uint8Array(32).fill(8)) },
    { reviewed_signature_sha256: b64(new Uint8Array(32).fill(8)) }, { accepted_ms: 30000 }, { extra: true }]) {
    const c = client(p, { fetchImpl: async () => json({ ...p.receipt, ...change }) });
    await assert.rejects(c.client.send(p.proof)); assert.equal(c.saved.length, 1);
  }
});

test("corrupt public recovery, extra fields and noncanonical encoding cannot become status authority", async () => {
  const p = await packet(); assert.deepEqual(await captureReviewedSendRecovery03(p.record), p.record);
  for (const record of [{ ...p.record, unexpected: true }, { ...p.record, user_id: id(uuid(210)) },
    { ...p.record, packet: { ...p.record.packet, reviewed_intent: p.record.packet.reviewed_intent + "=" } },
    { ...p.record, packet: { ...p.record.packet, signature: p.record.packet.reviewed_signature } },
    { ...p.record, packet: { ...p.record.packet, envelope: b64(Buffer.from(p.record.packet.envelope, "base64url").map((b, i) => i === 200 ? b ^ 1 : b)) } }]) {
    const c = client(p); await assert.rejects(c.client.status(record)); assert.equal(c.calls.length, 0);
  }
});

test("duplicate JSON, redirects, wrong URL/media and actual chunk cap refuse without trusting length headers", async () => {
  const p = await packet();
  for (const mode of ["duplicate", "redirect", "url", "media", "cap", "status"]) {
    const c = client(p, { fetchImpl: async () => {
      if (mode === "duplicate") return new Response(JSON.stringify(p.receipt).replace('"v":1', '"v":1,"v":1'), { status: 201, headers: { "content-type": "application/json" } });
      if (mode === "media") return new Response(JSON.stringify(p.receipt), { status: 201, headers: { "content-type": "text/plain" } });
      if (mode === "cap") return new Response(" ".repeat(192 * 1024 + 1), { status: 201, headers: { "content-type": "application/json", "content-length": "1" } });
      if (mode === "status") return json(p.receipt, 202);
      const r = json(p.receipt); Object.defineProperty(r, mode === "redirect" ? "redirected" : "url", { value: mode === "redirect" ? true : "https://other.test" }); return r;
    } });
    await assert.rejects(c.client.send(p.proof)); assert.equal(c.saved.length, 1);
  }
});

test("service refusal and unavailable result preserve exact original and never retry automatically", async () => {
  const p = await packet();
  for (const status of [401, 404, 409, 429, 503]) {
    let calls = 0;
    const c = client(p, { fetchImpl: async () => { calls++; return json({ error: ({ 401: "authentication_required", 404: "not_found", 409: "conflict", 429: "rate_limited" })[status] ?? "unavailable" }, status); } });
    await assert.rejects(c.client.send(p.proof)); assert.equal(calls, 1); assert.deepEqual(c.saved, [p.record]);
    await assert.rejects(c.client.status(p.record)); assert.equal(calls, 1); // A refused client is closed; explicit reconciliation uses a new one.
  }
});

test("timeout closes client and late transport completion cannot publish or submit a second packet", async () => {
  const p = await packet(); let release, calls = 0;
  const c = client(p, { timeoutMs: 30, fetchImpl: async () => { calls++; return new Promise(resolve => { release = resolve; }); } });
  await assert.rejects(c.client.send(p.proof)); assert.equal(calls, 1); assert.deepEqual(c.saved, [p.record]);
  release(json(p.receipt)); await new Promise(resolve => setTimeout(resolve, 5));
  await assert.rejects(c.client.status(p.record)); assert.equal(calls, 1);
});

test("Proxy getters never replace descriptor-selected options, recovery body or original packet", async () => {
  const p = await packet(); let reads = 0;
  const c = client(p), options = new Proxy(c.options, { get() { reads++; throw Error("get must not run"); } });
  const actual = new OwnerReviewedSendClient03(options);
  await actual.send(p.proof); assert.equal(reads, 0);
  const record = new Proxy(p.record, { get() { reads++; throw Error("get must not run"); } });
  const status = client(p, { fetchImpl: async () => json(p.receipt, 200) });
  assert.deepEqual(await status.client.status(record), p.receipt); assert.equal(reads, 0);
});
