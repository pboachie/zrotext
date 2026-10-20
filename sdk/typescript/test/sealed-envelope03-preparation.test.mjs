// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { prepareSealedOutboundEnvelope03, preparedOutboundEnvelopeSnapshot03,
  completeSealedOutboundEnvelope03 } from "../dist/sealed-envelope03.js";
import { fixture, inputFor, present, canonicalP256Signature, verifyAndOpen, frame, sha } from "./fixtures/profile03-outbound-fixture.mjs";

function input(f) { const { signerPrivateKey: unused, ...p } = inputFor(f); return p; }
async function signature(f, bytes) {
  return canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    f.records[4].k.pair.privateKey, bytes)));
}

test("actual preparation performs zero ECDSA signatures and completion preserves exact unsigned ciphertext", async () => {
  const f = await fixture(), composition = input(f), subtle = crypto.subtle;
  const original = Object.getOwnPropertyDescriptor(subtle, "sign"), native = subtle.sign.bind(subtle);
  let calls = 0, macs = 0;
  Object.defineProperty(subtle, "sign", { configurable: true, value: (...args) => {
    const algorithm = typeof args[0] === "string" ? args[0] : args[0].name;
    if (algorithm === "ECDSA") calls++; else if (algorithm === "HMAC") macs++;
    return native(...args);
  } });
  try {
    const handle = await prepareSealedOutboundEnvelope03(composition), snapshot = preparedOutboundEnvelopeSnapshot03(handle);
    assert.equal(calls, 0); assert.ok(macs > 0); // HPKE's HKDF uses symmetric HMAC.
    assert.deepEqual(snapshot.transcript, frame("ZTSE/sign/v3", snapshot.unsignedEnvelope));
    assert.deepEqual(snapshot.unsignedDigest, await sha(snapshot.unsignedEnvelope));
    assert.deepEqual(Object.keys(snapshot).sort(), ["signerPublicPoint", "transcript", "unsignedDigest", "unsignedEnvelope"]);
    const generated = await signature(f, snapshot.transcript); assert.equal(calls, 1);
    const completed = await completeSealedOutboundEnvelope03({ prepared: handle, signature: generated, nowMs: present });
    assert.equal(calls, 1); assert.deepEqual(completed.envelope.subarray(0, -64), snapshot.unsignedEnvelope);
    assert.deepEqual(completed.envelope.subarray(-64), generated);
    await verifyAndOpen(f, completed, composition.content);
  } finally {
    if (original) Object.defineProperty(subtle, "sign", original); else delete subtle.sign;
  }
});

test("opaque preparation cannot be forged, restored from public bytes or changed through owned projections", async () => {
  const f = await fixture(), handle = await prepareSealedOutboundEnvelope03(input(f));
  assert.deepEqual(Object.keys(handle), []);
  const snapshot = preparedOutboundEnvelopeSnapshot03(handle), expected = snapshot.unsignedEnvelope.slice();
  for (const value of Object.values(snapshot)) value.fill(0);
  assert.deepEqual(preparedOutboundEnvelopeSnapshot03(handle).unsignedEnvelope, expected);
  for (const forged of [{}, structuredClone(handle), snapshot]) {
    assert.throws(() => preparedOutboundEnvelopeSnapshot03(forged), /prepared unsigned/);
    await assert.rejects(completeSealedOutboundEnvelope03({ prepared: forged, signature: new Uint8Array(64), nowMs: present }));
  }
  const sig = await signature(f, preparedOutboundEnvelopeSnapshot03(handle).transcript);
  const complete = await completeSealedOutboundEnvelope03({ prepared: handle, signature: sig, nowMs: present });
  complete.envelope.fill(0); complete.unsignedDigest.fill(0);
  assert.deepEqual(preparedOutboundEnvelopeSnapshot03(handle).unsignedEnvelope, expected);
});

test("valid role5 signatures over wrong bytes/domain or another prepared packet never complete this packet", async () => {
  const f = await fixture(), first = await prepareSealedOutboundEnvelope03(input(f)), second = await prepareSealedOutboundEnvelope03(input(f));
  const a = preparedOutboundEnvelopeSnapshot03(first), b = preparedOutboundEnvelopeSnapshot03(second);
  assert.notDeepEqual(a.unsignedEnvelope, b.unsignedEnvelope);
  for (const bytes of [b.transcript, frame("ZTSE/sign/v2", a.unsignedEnvelope), frame("zrotext/conversation/reviewed-send03/v2", a.unsignedEnvelope)]) {
    await assert.rejects(completeSealedOutboundEnvelope03({ prepared: first, signature: await signature(f, bytes), nowMs: present }), /mismatch/);
  }
  const sig = await signature(f, a.transcript);
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const high = sig.slice(), s = BigInt("0x" + Buffer.from(sig.subarray(32)).toString("hex"));
  high.set(Buffer.from((order - s).toString(16).padStart(64, "0"), "hex"), 32);
  for (const bad of [high, new Uint8Array(63), new Uint8Array(65), new Uint8Array(64)]) {
    await assert.rejects(completeSealedOutboundEnvelope03({ prepared: first, signature: bad, nowMs: present }));
  }
});

test("completion cannot backdate captured context or renew the original whole-message expiry", async () => {
  const f = await fixture(), handle = await prepareSealedOutboundEnvelope03(input(f));
  const sig = await signature(f, preparedOutboundEnvelopeSnapshot03(handle).transcript);
  await completeSealedOutboundEnvelope03({ prepared: handle, signature: sig, nowMs: 39_999n });
  for (const nowMs of [present - 1n, 40_000n, 60_000n, 0n, 1n << 63n, Number(present)]) {
    await assert.rejects(completeSealedOutboundEnvelope03({ prepared: handle, signature: sig, nowMs }));
  }
});

test("preparation/completion capture caller values before waits and accept no secret or deterministic override fields", async () => {
  const f = await fixture(), p = input(f), body = p.content, pending = prepareSealedOutboundEnvelope03(p);
  p.messageId.fill(0); p.peer.fill(0); p.signerPublicPoint.fill(0); p.currentAuthority.bindingId.fill(0);
  p.recipients.forEach(r => r.keyId.fill(0)); p.content = "changed"; p.nowMs = 1n;
  const handle = await pending, snapshot = preparedOutboundEnvelopeSnapshot03(handle), sig = await signature(f, snapshot.transcript);
  const finishing = { prepared: handle, signature: sig, nowMs: present }, complete = completeSealedOutboundEnvelope03(finishing);
  sig.fill(0); finishing.prepared = {}; finishing.nowMs = 1n;
  await verifyAndOpen(f, await complete, body);
  for (const extra of [{ signerPrivateKey: f.records[4].k.pair.privateKey }, { deterministicKeyMaterial: new Uint8Array(32) }, { permission: true }]) {
    await assert.rejects(prepareSealedOutboundEnvelope03({ ...input(f), ...extra }), /closed/);
  }
  const accessor = input(f); Object.defineProperty(accessor, "content", { get() { throw Error("getter invoked"); } });
  await assert.rejects(prepareSealedOutboundEnvelope03(accessor), /accessor/);
  const ordinary = input(f), preparation = await prepareSealedOutboundEnvelope03(ordinary);
  const s = await signature(f, preparedOutboundEnvelopeSnapshot03(preparation).transcript);
  await assert.rejects(completeSealedOutboundEnvelope03({ prepared: preparation, signature: s, nowMs: present, retry: true }), /closed/);
});
