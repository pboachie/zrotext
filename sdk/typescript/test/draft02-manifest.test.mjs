import assert from "node:assert/strict";
import { test } from "node:test";
import {
  canonicalSignature02, enrollRootPin02, verifyManifest02, advanceManifestTrust02,
  verifyRootTransition02, authorizeOutbound02,
} from "../dist/draft02-manifest.js";

const encoder = new TextEncoder();
const now = BigInt(Date.now());
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const zero32 = new Uint8Array(32);
const account = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const device = Uint8Array.from({ length: 16 }, (_, i) => i + 17);
const line = Uint8Array.from({ length: 16 }, (_, i) => i + 33);
const zero16 = new Uint8Array(16);

function join(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function u16(n) { return Uint8Array.of(n >> 8, n & 255); }
function u32(n) { return Uint8Array.of(n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255); }
function u64(n) { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, n, false); return out; }
function bytes32(n) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
function val(bytes) { return bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n); }
async function sha(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function key() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function id(role, point) {
  return sha(join(encoder.encode("ZTSE/key/v1\0"), role <= 3 ? u16(0x10) : u16(0x101), point));
}
async function sign(k, label, unsigned) {
  const input = join(encoder.encode(`${label}\0`), u32(unsigned.length), unsigned);
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, input)));
}
function highS(low) {
  const out = Uint8Array.from(low);
  out.set(bytes32(order - val(out.subarray(32))), 32);
  return out;
}
async function fixture() {
  const root = await key();
  const payload = await key();
  const archive = await key();
  const signer = await key();
  const records = [
    { role: 1, key: payload, device, line, scope: 4, state: 1 },
    { role: 2, key: archive, device: zero16, line: zero16, scope: 12, state: 1 },
    { role: 5, key: signer, device: zero16, line: zero16, scope: 1, state: 1 },
    { role: 6, key: root, device: zero16, line: zero16, scope: 0, state: 1 },
  ];
  for (const record of records) record.keyId = await id(record.role, record.key.point);
  return { root, payload, archive, signer, records };
}
async function manifest(f, options = {}) {
  const records = options.records ?? f.records;
  const issued = options.issued ?? now - 1_000n;
  const expires = options.expires ?? now + 3_600_000n;
  const version = options.version ?? 1n;
  const previous = options.previous ?? zero32;
  const sorted = [...records].sort((a, b) => a.role - b.role || Buffer.compare(a.keyId, b.keyId));
  const recordBytes = sorted.map((r) => join(
    Uint8Array.of(r.role), r.keyId, r.key.point, r.device, r.line,
    u16(r.scope), u64(r.from ?? issued), u64(r.until ?? expires), Uint8Array.of(r.state),
  ));
  const unsigned = join(encoder.encode("ZTMA"), Uint8Array.of(2), account,
    u64(options.generation ?? 1n), u64(version), u64(issued), u64(expires), previous,
    f.root.point, Uint8Array.of(sorted.length), ...recordBytes);
  return join(unsigned, await sign(options.signer ?? f.root, "ZTSE/manifest/v2", unsigned));
}
function pin(root) {
  return { accountId: account, generation: 1n, rootPoint: root.point,
    version: 0n, digest: zero32, anchorDigest: zero32 };
}
async function rootPinBytes(root, accountId = account) {
  const bytes = join(encoder.encode("ZTRP"), Uint8Array.of(2), accountId, u64(1n), root.point);
  const fingerprint = await sha(join(encoder.encode("ZTSE/root-pin/v2\0"), bytes));
  return { bytes, fingerprint };
}
async function transition(old, next, state, options = {}) {
  const unsigned = join(encoder.encode("ZTRT"), Uint8Array.of(2), account,
    u64(state.generation), u64(state.generation + 1n), old.point, next.point,
    options.previous ?? state.digest, u64(now - 1_000n), u64(now + 3_600_000n));
  return join(unsigned, await sign(options.oldSigner ?? old, "ZTSE/root-transition/v2", unsigned),
    await sign(options.newSigner ?? next, "ZTSE/root-transition/v2", unsigned));
}

test("pinned genesis, exact signed bytes, monotonic chain and authorized reader set", async () => {
  const f = await fixture();
  const enrollment = await rootPinBytes(f.root);
  const compared = await enrollRootPin02(enrollment.bytes, enrollment.fingerprint);
  const first = await verifyManifest02(await manifest(f), compared, now);
  assert.equal(first.version, 1n);
  const state = advanceManifestTrust02(pin(f.root), first);
  assert.deepEqual((await verifyManifest02(first.bytes, state, now)).digest, first.digest);
  const second = await verifyManifest02(await manifest(f, { version: 2n, previous: first.digest }), state, now);
  const claims = {
    accountId: account, deviceId: device, lineId: line,
    manifestDigest: second.digest, keysetVersion: 2n,
    signerKeyId: f.records[2].keyId,
    wraps: [{ role: 1, keyId: f.records[0].keyId }, { role: 2, keyId: f.records[1].keyId }],
  };
  assert.doesNotThrow(() => authorizeOutbound02(second, claims, now));
  assert.throws(() => authorizeOutbound02(second, { ...claims, lineId: device }, now), /selected device\/line/);
  assert.throws(() => authorizeOutbound02(second, { ...claims, signerKeyId: f.records[3].keyId }, now), /signer authority/);
  assert.throws(() => authorizeOutbound02(second, { ...claims, wraps: [...claims.wraps, claims.wraps[0]] }, now), /reader set/);
  assert.throws(() => authorizeOutbound02(second, { ...claims, wraps: claims.wraps.slice(0, 1) }, now), /reader set/);
  assert.throws(() => authorizeOutbound02(second, { ...claims, wraps: [...claims.wraps, { role: 3, keyId: f.records[0].keyId }] }, now), /reader authority/);
  assert.throws(() => authorizeOutbound02(second, { ...claims, manifestDigest: first.digest }, now), /manifest binding/);
  const revokedRecords = f.records.map((r) => r.role === 5 ? { ...r, state: 2 } : r);
  const revoked = await verifyManifest02(await manifest(f, { records: revokedRecords }), pin(f.root), now);
  assert.throws(() => authorizeOutbound02(revoked, { ...claims, keysetVersion: 1n, manifestDigest: revoked.digest }, now), /signer authority/);
});

test("out-of-band root pin binds account, generation and point", async () => {
  const root = await key();
  const enrollment = await rootPinBytes(root);
  assert.deepEqual((await enrollRootPin02(enrollment.bytes, enrollment.fingerprint)).rootPoint, root.point);
  const swapped = Uint8Array.from(enrollment.bytes); swapped[5] ^= 1;
  await assert.rejects(enrollRootPin02(swapped, enrollment.fingerprint), /root pin comparison/);
  const otherRoot = await key();
  const alternate = await rootPinBytes(otherRoot);
  await assert.rejects(enrollRootPin02(alternate.bytes, enrollment.fingerprint), /root pin comparison/);
  await assert.rejects(enrollRootPin02(enrollment.bytes.subarray(0, 93), enrollment.fingerprint), /root pin size/);
});

test("forged, altered, high-s, stale, future and wrong-account manifests fail", async () => {
  const f = await fixture();
  const trusted = pin(f.root);
  const good = await manifest(f);
  const attacker = await key();
  await assert.rejects(verifyManifest02(await manifest(f, { signer: attacker }), trusted, now), /signature verification/);
  const altered = Uint8Array.from(good); altered[60] ^= 1;
  await assert.rejects(verifyManifest02(altered, trusted, now), /signature verification/);
  const high = Uint8Array.from(good); high.set(highS(high.subarray(high.length - 64)), high.length - 64);
  await assert.rejects(verifyManifest02(high, trusted, now), /high-s signature/);
  await assert.rejects(verifyManifest02(good, { ...trusted, accountId: device }, now), /pin mismatch/);
  await assert.rejects(verifyManifest02(await manifest(f, { issued: now - 7_200_000n, expires: now - 1n }), trusted, now), /stale or future/);
  await assert.rejects(verifyManifest02(await manifest(f, { issued: now + 400_000n, expires: now + 500_000n }), trusted, now), /stale or future/);
  await assert.rejects(verifyManifest02(good.subarray(0, good.length - 1), trusted, now), /count or exact size/);
});

test("rollback, same-version fork, chain gap and forged prior digest fail", async () => {
  const f = await fixture();
  const first = await verifyManifest02(await manifest(f), pin(f.root), now);
  const state = advanceManifestTrust02(pin(f.root), first);
  assert.deepEqual((await verifyManifest02(await manifest(f), state, now)).digest, first.digest);
  await assert.rejects(verifyManifest02(await manifest(f, { issued: now - 2_000n }), state, now), /rollback, fork/);
  await assert.rejects(verifyManifest02(await manifest(f, { version: 3n, previous: first.digest }), state, now), /rollback, fork/);
  await assert.rejects(verifyManifest02(await manifest(f, { version: 2n, previous: zero32 }), state, now), /rollback, fork/);
  await assert.rejects(verifyManifest02(first.bytes, { ...state, version: 2n }, now), /rollback, fork/);
});

test("role, scope, subject, key-ID and point aliases are rejected even if owner signs", async () => {
  const f = await fixture();
  const checks = [
    [{ ...f.records[2], role: 6, scope: 0, keyId: await id(6, f.signer.point) }, /owner root record/],
    [{ ...f.records[0], scope: 1 }, /role\/scope/],
    [{ ...f.records[0], device: zero16 }, /role\/subject/],
    [{ ...f.records[0], keyId: zero32 }, /key id/],
    [{ ...f.records[2], key: f.root, keyId: await id(5, f.root.point) }, /point reused/],
  ];
  for (const [replacement, error] of checks) {
    const records = f.records.map((r, i) => i === (replacement.role === 6 && replacement.key === f.signer ? 2 :
      replacement.role === 5 ? 2 : 0) ? replacement : r);
    await assert.rejects(verifyManifest02(await manifest(f, { records }), pin(f.root), now), error);
  }
});

test("rotation requires both roots, pinned new root and linked next-generation manifest", async () => {
  const f = await fixture();
  const first = await verifyManifest02(await manifest(f), pin(f.root), now);
  const state = advanceManifestTrust02(pin(f.root), first);
  const nextRoot = await key();
  const encoded = await transition(f.root, nextRoot, state);
  const nextState = await verifyRootTransition02(encoded, state, now, nextRoot.point);
  assert.equal(nextState.generation, 2n);
  await assert.rejects(verifyRootTransition02(encoded, state, now, f.signer.point), /transition pin\/chain/);
  const forged = await transition(f.root, nextRoot, state, { newSigner: f.signer });
  await assert.rejects(verifyRootTransition02(forged, state, now, nextRoot.point), /signature verification/);
  const oldForged = await transition(f.root, nextRoot, state, { oldSigner: f.signer });
  await assert.rejects(verifyRootTransition02(oldForged, state, now, nextRoot.point), /signature verification/);
  const high = Uint8Array.from(encoded);
  high.set(highS(high.subarray(215, 279)), 215);
  await assert.rejects(verifyRootTransition02(high, state, now, nextRoot.point), /high-s signature/);
  const wrongPrior = await transition(f.root, nextRoot, state, { previous: zero32 });
  await assert.rejects(verifyRootTransition02(wrongPrior, state, now, nextRoot.point), /transition pin\/chain/);
  const newRecords = f.records.map((r) => r.role === 6 ? { ...r, key: nextRoot, keyId: null } : r);
  newRecords[3].keyId = await id(6, nextRoot.point);
  const newFixture = { ...f, root: nextRoot, records: newRecords };
  const firstNew = await manifest(newFixture, { generation: 2n, previous: nextState.anchorDigest });
  assert.equal((await verifyManifest02(firstNew, nextState, now)).generation, 2n);
  await assert.rejects(verifyManifest02(await manifest(newFixture, { generation: 2n }), nextState, now), /genesis\/transition chain/);
});
