import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalP256Signature, keyId } from "../dist/draft01.js";
import { enrollRootPin02, verifyManifest02 } from "../dist/draft02-manifest.js";
import { verifyManifest03From02, verifyManifest03Successor } from "../dist/draft03-manifest.js";
import { verifyAcceptedPayloadProfileElection03, requireCurrentElection03 } from "../dist/payload-profile-election03.js";

const enc = new TextEncoder(), at = 10_000n, present = 30_000n;
const uuid = n => Uint8Array.from({ length: 16 }, (_, i) => n + i);
const account = uuid(1), device = uuid(20), line = uuid(40), zero16 = new Uint8Array(16), zero32 = new Uint8Array(32);
const clone = x => structuredClone(x);
function join(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let n = 0; for (const p of parts) { out.set(p, n); n += p.length; } return out; }
function u16(n) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n); return b; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function u64(n) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; }
const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const frame = (label, p) => join(enc.encode(label + "\0"), u32(p.length), p);
async function key() { const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]); return { pair, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) }; }
async function sign(k, label, p) { return canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.pair.privateKey, frame(label, p)))); }
async function manifest(f, profile, version, previous, records = f.records) {
  records = [...records].sort((a, b) => a.role - b.role || Buffer.compare(a.id, b.id));
  const body = join(enc.encode("ZTMA"), Uint8Array.of(profile), ...(profile === 3 ? [Uint8Array.of(3, version === 2n ? 2 : 3)] : []),
    account, u64(1n), u64(version), u64(9_000n), u64(2_000_000n), previous, f.root.point, Uint8Array.of(records.length),
    ...records.map(r => join(Uint8Array.of(r.role), r.id, r.k.point, r.role === 1 || r.role === 4 ? device : zero16,
      [1, 4, 5].includes(r.role) ? line : zero16, u16(r.scope), u64(r.from ?? 9_000n), u64(r.until ?? 2_000_000n), Uint8Array.of(r.state ?? 1))));
  return { bytes: join(body, await sign(f.root, `ZTSE/manifest/v${profile}`, body)), digest: await sha(body) };
}
async function fixture() {
  const f = { root: await key(), records: [], enrollment: await key(), approval: await key() };
  for (let role = 1; role <= 6; role++) { const k = role === 6 ? f.root : await key(); f.records.push({ role, k, id: await keyId(role <= 3 ? 0x10 : 0x101, k.point), scope: [0, 4, 12, 12, 2, 1, 0][role] }); }
  const pinBytes = join(enc.encode("ZTRP"), Uint8Array.of(2), account, u64(1n), f.root.point);
  f.fingerprint = await sha(join(enc.encode("ZTSE/root-pin/v2\0"), pinBytes));
  f.pin = await enrollRootPin02(pinBytes, f.fingerprint);
  f.old = await manifest(f, 2, 1n, zero32); f.prior = await verifyManifest02(f.old.bytes, f.pin, at);
  f.first = await manifest(f, 3, 2n, f.old.digest); f.currentManifest = await verifyManifest03From02(f.first.bytes, f.prior, f.old.bytes, at);
  const digest = n => new Uint8Array(32).fill(n);
  f.core = join(enc.encode("ZTPE"), Uint8Array.of(3, 1, 2, 3), account, device, line, uuid(60), uuid(80), u64(4n), u64(7n), digest(1),
    f.fingerprint, u64(1n), u64(1n), f.old.digest, u64(2n), f.first.digest, f.records[0].id,
    await keyId(0x101, f.enrollment.point), await keyId(0x101, f.approval.point), digest(2), u64(9_000n), u64(20_000n), digest(3), digest(4), digest(5), new Uint8Array(4));
  const ds = await sign(f.enrollment, "ZTSE/line/payload-profile/device/v1", f.core);
  f.bundle = join(f.core, ds, await sign(f.approval, "ZTSE/line/payload-profile/owner/v1", join(f.core, await sha(ds))));
  f.accepted = { accountId: account, deviceId: device, lineId: line, rootFingerprint: f.fingerprint, vaultGeneration: 1n,
    oldBindingId: uuid(80), oldBindingGeneration: 4n, oldBindingProofDigest: digest(1), newBindingId: uuid(100), newBindingGeneration: 7n,
    selectedReaderKeyId: f.records[0].id, priorManifestVersion: 1n, priorManifestDigest: f.old.digest, priorSignedManifestSha256: await sha(f.old.bytes),
    acceptedManifestVersion: 2n, acceptedManifestDigest: f.first.digest, acceptedSignedManifestSha256: await sha(f.first.bytes),
    electionCoreSha256: await sha(f.core), electionCommitment: await sha(frame("ZTSE/line/payload-profile/commitment/v1", f.core)), electionBundleSha256: await sha(f.bundle), acceptedAtMs: at };
  f.proofInput = () => ({ bundle: f.bundle, expectedCore: f.core, acceptedRecord: f.accepted, predecessor02: f.prior,
    priorSignedManifest02: f.old.bytes, acceptedSignedManifest03: f.first.bytes, deviceSigningPointAtAcceptance: f.enrollment.point, ownerApprovalPointAtAcceptance: f.approval.point });
  f.authority = { profile: 3, manifestProfile: 3, accountId: account, deviceId: device, lineId: line, bindingId: uuid(100), bindingGeneration: 7n,
    selectedReaderKeyId: f.records[0].id, rootFingerprint: f.fingerprint, vaultGeneration: 1n, manifestVersion: 2n, manifestDigest: f.first.digest,
    electionCommitment: f.accepted.electionCommitment, electionBundleSha256: f.accepted.electionBundleSha256, comparedAtMs: present, permissionExpiresAtMs: 60_000n };
  f.proof = await verifyAcceptedPayloadProfileElection03(f.proofInput()); return f;
}

import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { composeSealedOutboundEnvelope03 } from "../dist/sealed-envelope03.js";

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
function inputFor(f) {
  return { manifest: f.currentManifest, acceptedElection: f.proof, currentAuthority: clone(f.authority), nowMs: present,
    messageId: uuid(120), observedMs: present, expiresMs: 40_000n, peer: enc.encode("+12"), content: "Synthetic outbound text 🌱",
    signerPrivateKey: f.records[4].k.pair.privateKey, signerPublicPoint: f.records[4].k.point.slice(),
    recipients: [2, 1, 3].map(role => ({ role, keyId: f.records[role - 1].id.slice() })) };
}
function parseOutput(envelope) {
  assert.ok(envelope.length >= 557 && envelope.length <= 34213);
  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  assert.deepEqual(envelope.slice(0, 8), Uint8Array.of(90, 84, 83, 69, 3, 1, 0, 0));
  const protectedLength = view.getUint16(8), end = 10 + protectedLength;
  const protectedBytes = envelope.slice(10, end), peerLength = protectedBytes[153];
  assert.equal(protectedLength, 154 + peerLength); assert.equal(protectedBytes[152], 1);
  assert.equal(new TextDecoder().decode(protectedBytes.slice(154)), "+12");
  const bodyLength = view.getUint32(end + 12), bodyEnd = end + 16 + bodyLength;
  assert.ok(bodyLength >= 17 && bodyLength <= 32784);
  const count = envelope[bodyEnd]; assert.ok(count >= 2 && count <= 8);
  assert.equal(bodyEnd + 1 + 146 * count + 64, envelope.length);
  const wraps = [];
  for (let i = 0; i < count; i++) {
    const n = bodyEnd + 1 + 146 * i;
    wraps.push({ role: envelope[n], id: envelope.slice(n + 1, n + 33), ephemeral: envelope.slice(n + 33, n + 98), ciphertext: envelope.slice(n + 98, n + 146) });
  }
  assert.deepEqual(wraps.map(w => w.role), [1, 2, 3]);
  return { prefix: envelope.slice(0, end), protectedBytes, nonce: envelope.slice(end, end + 12), body: envelope.slice(end + 16, bodyEnd),
    wraps, unsigned: envelope.slice(0, -64), signature: envelope.slice(-64) };
}
async function recipientKey(record) {
  const jwk = await crypto.subtle.exportKey("jwk", record.k.pair.privateKey);
  return crypto.subtle.importKey("jwk", { ...jwk, key_ops: ["deriveBits"] }, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}
async function openWrap(f, p, w, infoDomain = "ZTSE/wrap/v3", aadDomain = "ZTSE/wrap-aad/v3") {
  const suffix = join(p.prefix, Uint8Array.of(w.role), w.id);
  const record = f.records.find(r => r.role === w.role && Buffer.compare(r.id, w.id) === 0);
  const receiver = await suite.createRecipientContext({ recipientKey: await recipientKey(record), enc: w.ephemeral,
    info: join(enc.encode(infoDomain + "\0"), suffix) });
  return new Uint8Array(await receiver.open(w.ciphertext, aadDomain === "" ? new Uint8Array() : join(enc.encode(aadDomain + "\0"), suffix)));
}
async function verifyAndOpen(f, result, text) {
  const p = parseOutput(result.envelope);
  assert.deepEqual(p.protectedBytes.slice(0, 16), account); assert.deepEqual(p.protectedBytes.slice(32, 48), device);
  assert.deepEqual(p.protectedBytes.slice(48, 64), line); assert.deepEqual(p.protectedBytes.slice(72, 104), f.authority.manifestDigest);
  assert.equal(new DataView(p.protectedBytes.buffer).getBigUint64(64), f.authority.manifestVersion);
  assert.deepEqual(result.unsignedDigest, await sha(p.unsigned)); assert.deepEqual(result.envelopeDigest, await sha(result.envelope));
  const signatureInput = frame("ZTSE/sign/v3", p.unsigned);
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.publicKey, p.signature, signatureInput), true);
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.publicKey, p.signature, frame("ZTSE/sign/v2", p.unsigned)), false);
  const ceks = [];
  for (const w of p.wraps) {
    const cek = await openWrap(f, p, w); assert.equal(cek.length, 32); ceks.push(cek);
    const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
    const opened = await crypto.subtle.decrypt({ name: "AES-GCM", iv: p.nonce, additionalData: join(enc.encode("ZTSE/body/v3\0"), p.prefix) }, aes, p.body);
    assert.equal(new TextDecoder("utf-8", { fatal: true }).decode(opened), text);
  }
  assert.deepEqual(ceks[0], ceks[1]); assert.deepEqual(ceks[1], ceks[2]); return p;
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
