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

test("historical accepted proof survives challenge expiry while present authority remains independently valid", async () => {
  const f = await fixture();
  assert.equal(requireCurrentElection03(f.proof, f.currentManifest, f.authority, present).bindingGeneration, 7n);
  const later = await manifest(f, 3, 3n, f.first.digest);
  const handle = await verifyManifest03Successor(later.bytes, f.currentManifest, present);
  assert.equal(requireCurrentElection03(f.proof, handle, { ...f.authority, manifestVersion: 3n, manifestDigest: later.digest }, present).manifestVersion, 3n);
  assert.throws(() => requireCurrentElection03(f.proof, handle, f.authority, present), /manifest/);
});

test("exact original signed evidence and proof bytes cannot be replaced by semantic equivalence", async () => {
  const f = await fixture();
  const alternate = await manifest(f, 3, 2n, f.old.digest);
  assert.deepEqual(alternate.digest, f.first.digest); assert.notDeepEqual(alternate.bytes, f.first.bytes);
  await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), acceptedSignedManifest03: alternate.bytes }), /evidence/);
  for (const name of ["priorSignedManifestSha256", "electionCoreSha256", "electionCommitment", "electionBundleSha256"]) {
    const record = clone(f.accepted); record[name][0] ^= 1;
    await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), acceptedRecord: record }), /evidence/);
  }
});

test("valid owner signatures over a different device proof digest cannot approve this bundle", async () => {
  const f = await fixture(), changed = f.bundle.slice();
  const wrong = await sign(f.approval, "ZTSE/line/payload-profile/owner/v1", join(f.core, new Uint8Array(32).fill(9)));
  changed.set(wrong, 564);
  await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), bundle: changed,
    acceptedRecord: { ...f.accepted, electionBundleSha256: await sha(changed) } }), /signature/);
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const twin = f.bundle.slice(); let n = order - twin.subarray(532, 564).reduce((v, b) => v * 256n + BigInt(b), 0n);
  for (let i = 563; i >= 532; i--) { twin[i] = Number(n & 255n); n >>= 8n; }
  await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), bundle: twin,
    acceptedRecord: { ...f.accepted, electionBundleSha256: await sha(twin) } }), /signature/);
});

test("acceptance time and independently selected current binding refuse malformed, forged and stale inputs", async () => {
  const f = await fixture();
  for (const acceptedAtMs of [0n, 8_999n, 20_000n, 10_000, (1n << 63n)]) {
    await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), acceptedRecord: { ...f.accepted, acceptedAtMs } }));
  }
  for (const name of ["accountId", "deviceId", "lineId", "bindingId", "selectedReaderKeyId", "rootFingerprint", "manifestDigest", "electionCommitment", "electionBundleSha256"]) {
    const c = clone(f.authority); c[name][0] ^= 1;
    assert.throws(() => requireCurrentElection03(f.proof, f.currentManifest, c, present));
  }
  for (const c of [{ ...f.authority, profile: 2 }, { ...f.authority, bindingGeneration: 8n }, { ...f.authority, permissionExpiresAtMs: present },
    { ...f.authority, comparedAtMs: present + 1n }, { ...f.authority, manifestVersion: 1n }, { ...f.authority, extra: true }]) {
    assert.throws(() => requireCurrentElection03(f.proof, f.currentManifest, c, present));
  }
  assert.throws(() => requireCurrentElection03({}, f.currentManifest, f.authority, present), /exact/);
  assert.throws(() => requireCurrentElection03(f.proof, {}, f.authority, present));
});

test("proof captures every supplied evidence position before crypto suspension and refuses disguised storage", async () => {
  const f = await fixture();
  const fields = ["bundle", "expectedCore", "priorSignedManifest02", "acceptedSignedManifest03", "deviceSigningPointAtAcceptance", "ownerApprovalPointAtAcceptance"];
  for (const name of fields) {
    const input = f.proofInput(); input[name] = input[name].slice();
    const pending = verifyAcceptedPayloadProfileElection03(input); input[name].fill(0);
    assert.ok(await pending);
    for (const backing of [new SharedArrayBuffer(input[name].length), new ArrayBuffer(input[name].length)]) {
      let value;
      if (backing instanceof SharedArrayBuffer) { value = new Uint8Array(backing); Object.setPrototypeOf(backing, ArrayBuffer.prototype); }
      else { value = new Uint8ClampedArray(backing); Object.setPrototypeOf(value, Uint8Array.prototype); }
      value.set(f.proofInput()[name]);
      await assert.rejects(verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), [name]: value }), /unsupported byte/);
    }
  }
  const record = clone(f.accepted), pending = verifyAcceptedPayloadProfileElection03({ ...f.proofInput(), acceptedRecord: record });
  record.newBindingId.fill(0); record.acceptedAtMs = 1n;
  const handle = await pending;
  const exposed = requireCurrentElection03(handle, f.currentManifest, f.authority, present); exposed.bindingId.fill(0);
  assert.equal(requireCurrentElection03(handle, f.currentManifest, f.authority, present).bindingId[0], 100);
});
