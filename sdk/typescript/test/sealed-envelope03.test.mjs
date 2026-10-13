import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { canonicalP256Signature, keyId, enrollRootPin02, verifyManifest02, verifyManifest03From02, verifyManifest03Successor, verifyAcceptedPayloadProfileElection03, requireCurrentElection03, composeSealedOutboundEnvelope03, enc, at, present, uuid, account, device, line, zero16, zero32, clone, join, u16, u32, u64, sha, frame, key, sign, manifest, fixture, suite, inputFor, parseOutput, recipientKey, openWrap, verifyAndOpen } from "./fixtures/profile03-outbound-fixture.mjs";

const timePolicy = JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/sealed-profile03-outbound-time-policy.json', import.meta.url)));
for (const scenario of timePolicy.cases) {
  test(`outbound03 shared time policy: ${scenario.name}`, async () => {
    const policy = { ...timePolicy.defaults, ...scenario }, f = await fixture(policy), input = inputFor(f);
    input.observedMs = BigInt(policy.observed_ms); input.nowMs = BigInt(policy.now_ms); input.expiresMs = BigInt(policy.expires_ms);
    input.currentAuthority.comparedAtMs = input.nowMs;
    if (policy.accept) await verifyAndOpen(f, await composeSealedOutboundEnvelope03(input), input.content);
    else await assert.rejects(composeSealedOutboundEnvelope03(input), policy.late_role ? /authority lifetime start/ : undefined);
  });
}

test("public composer produces fresh ciphertext after accepted challenge expiry and all explicit readers open it", async () => {
  const f = await fixture(), input = inputFor(f);
  const a = await composeSealedOutboundEnvelope03(input), b = await composeSealedOutboundEnvelope03(input);
  assert.deepEqual(Object.keys(a).sort(), ["envelope", "envelopeDigest", "unsignedDigest"]);
  assert.notDeepEqual(a.envelope, b.envelope); assert.notDeepEqual(a.unsignedDigest, b.unsignedDigest);
  await verifyAndOpen(f, a, input.content); await verifyAndOpen(f, b, input.content);
  const hooked = inputFor(f);
  for (const name of ["map", Symbol.iterator, "constructor"]) {
    Object.defineProperty(hooked.recipients, name, { get() { throw Error("caller array hook invoked"); } });
  }
  await verifyAndOpen(f, await composeSealedOutboundEnvelope03(hooked), hooked.content);
  class SpeciesArray extends Array { static get [Symbol.species]() { throw Error("caller species invoked"); } }
  const species = inputFor(f); species.recipients = new SpeciesArray(...species.recipients);
  await verifyAndOpen(f, await composeSealedOutboundEnvelope03(species), species.content);
  const minimum = inputFor(f); minimum.content = "a"; minimum.recipients = minimum.recipients.filter(r => r.role !== 3);
  assert.equal((await composeSealedOutboundEnvelope03(minimum)).envelope.length, 557);
  const records = [...f.records];
  for (let n = 0; n < 5; n++) { const k = await key(); records.push({ role: 3, k, id: await keyId(0x10, k.point), scope: 4 }); }
  const larger = await manifest(f, 3, 3n, f.first.digest, records), maximum = inputFor(f);
  maximum.manifest = await verifyManifest03Successor(larger.bytes, f.currentManifest, present);
  maximum.currentAuthority.manifestVersion = 3n; maximum.currentAuthority.manifestDigest = larger.digest;
  maximum.content = "a".repeat(32768); maximum.peer = new Uint8Array(16).fill(49); maximum.peer[0] = 43;
  maximum.recipients = records.filter(r => r.role <= 3).map(r => ({ role: r.role, keyId: r.id }));
  assert.equal((await composeSealedOutboundEnvelope03(maximum)).envelope.length, 34213);
  maximum.content += "a"; await assert.rejects(composeSealedOutboundEnvelope03(maximum), /body/);
});

test("actual generated HPKE ciphertext rejects empty or changed AAD and old-profile info", async () => {
  const f = await fixture(), p = parseOutput((await composeSealedOutboundEnvelope03(inputFor(f))).envelope);
  for (const w of p.wraps) {
    await assert.rejects(openWrap(f, p, w, "ZTSE/wrap/v3", ""));
    await assert.rejects(openWrap(f, p, w, "ZTSE/wrap/v3", "ZTSE/wrap-aad/v2"));
    await assert.rejects(openWrap(f, p, w, "ZTSE/wrap/v2"));
    const altered = { ...p, prefix: p.prefix.slice() }; altered.prefix[20] ^= 1;
    await assert.rejects(openWrap(f, altered, w));
  }
  const cek = await openWrap(f, p, p.wraps[0]), aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  await assert.rejects(crypto.subtle.decrypt({ name: "AES-GCM", iv: p.nonce, additionalData: join(enc.encode("ZTSE/body/v2\0"), p.prefix) }, aes, p.body));
});

test("later genuine03 refresh uses current keys rather than historical election signer authority", async () => {
  const f = await fixture(), newSigner = await key();
  const records = f.records.map(r => r.role === 5 ? { ...r, k: newSigner } : r);
  records[4].id = await keyId(0x101, newSigner.point);
  const later = await manifest(f, 3, 3n, f.first.digest, records);
  const handle = await verifyManifest03Successor(later.bytes, f.currentManifest, present);
  const input = inputFor(f); input.manifest = handle; input.currentAuthority.manifestVersion = 3n; input.currentAuthority.manifestDigest = later.digest;
  await assert.rejects(composeSealedOutboundEnvelope03(input), /signer authority/);
  input.signerPublicPoint = newSigner.point; input.signerPrivateKey = newSigner.pair.privateKey;
  f.records = records; f.authority = input.currentAuthority;
  await verifyAndOpen(f, await composeSealedOutboundEnvelope03(input), input.content);
});

test("invalid current permission, readers, provenance and runtime overrides fail before encryption or signing", async () => {
  const f = await fixture(), changes = [
    i => { i.acceptedElection = {}; }, i => { i.manifest = {}; },
    i => { i.currentAuthority.bindingId[0] ^= 1; }, i => { i.currentAuthority.permissionExpiresAtMs = present; },
    i => { i.currentAuthority.manifestDigest[0] ^= 1; }, i => { i.currentAuthority.profile = 2; },
    i => { i.recipients[0].keyId.fill(3); }, i => { i.recipients.push(i.recipients[0]); }, i => { i.recipients[1].role = 4; },
    i => { i.expiresMs = 60_001n; }, i => { i.nowMs = Number(present); }, i => { i.messageId.fill(0); },
    i => { i.content = "\ufeffbad"; }, i => { i.content = "\ud800"; }, i => { i.peer = enc.encode("+01"); },
    i => { i.deterministicKeyMaterial = {}; }, i => { Object.setPrototypeOf(i, { deterministicKeyMaterial: {} }); },
  ];
  const originalEncrypt = crypto.subtle.encrypt, originalSign = crypto.subtle.sign; let calls = 0;
  crypto.subtle.encrypt = async () => { calls++; throw new Error("unexpected encryption"); };
  crypto.subtle.sign = async () => { calls++; throw new Error("unexpected signing"); };
  try { for (const change of changes) { const i = inputFor(f); change(i); await assert.rejects(composeSealedOutboundEnvelope03(i)); } assert.equal(calls, 0); }
  finally { crypto.subtle.encrypt = originalEncrypt; crypto.subtle.sign = originalSign; }
});

test("snapshot remains bound to original caller bytes across async digest and returned tuple mutation", async () => {
  const f = await fixture(), input = inputFor(f), originalText = input.content;
  const pending = composeSealedOutboundEnvelope03(input);
  input.messageId.fill(0); input.peer.fill(0); input.signerPublicPoint.fill(0); input.content = "Changed";
  input.recipients.forEach(r => r.keyId.fill(0)); input.recipients.length = 0;
  input.currentAuthority.bindingId.fill(0); input.currentAuthority.manifestDigest.fill(0); input.expiresMs = 1n;
  const result = await pending, p = await verifyAndOpen(f, result, originalText);
  assert.deepEqual(p.protectedBytes.slice(16, 32), uuid(120));
});

test("wrong private signing key, unavailable randomness and disguised byte kinds never yield output", async () => {
  const f = await fixture(), wrong = inputFor(f); wrong.signerPrivateKey = (await key()).pair.privateKey;
  await assert.rejects(composeSealedOutboundEnvelope03(wrong), /private\/public/);
  const originalRandom = crypto.getRandomValues;
  crypto.getRandomValues = () => { throw new Error("synthetic CSPRNG failure"); };
  try { await assert.rejects(composeSealedOutboundEnvelope03(inputFor(f)), /CSPRNG failure/); }
  finally { crypto.getRandomValues = originalRandom; }
  for (const field of ["messageId", "peer", "signerPublicPoint"]) {
    const i = inputFor(f), shared = new SharedArrayBuffer(i[field].length), bytes = new Uint8Array(shared); bytes.set(i[field]);
    Object.setPrototypeOf(shared, ArrayBuffer.prototype); i[field] = bytes;
    await assert.rejects(composeSealedOutboundEnvelope03(i), /unsupported byte/);
    const j = inputFor(f), clamped = new Uint8ClampedArray(j[field]); Object.setPrototypeOf(clamped, Uint8Array.prototype); j[field] = clamped;
    await assert.rejects(composeSealedOutboundEnvelope03(j), /unsupported byte/);
  }
});
