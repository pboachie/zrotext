import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalSignature02, verifyManifest02, authorizeInbound02 } from "../dist/draft02-manifest.js";

const enc = new TextEncoder();
const now = BigInt(Date.now());
const account = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const device = Uint8Array.from({ length: 16 }, (_, i) => i + 17);
const line = Uint8Array.from({ length: 16 }, (_, i) => i + 33);
const event = Uint8Array.from({ length: 16 }, (_, i) => i + 49);
const zero16 = new Uint8Array(16);
const zero32 = new Uint8Array(32);

function join(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function u16(n) { return Uint8Array.of(n >> 8, n & 255); }
function u32(n) { return Uint8Array.of(n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255); }
function u64(n) { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, n, false); return out; }
async function sha(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function key() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function keyId(role, point) {
  return sha(join(enc.encode("ZTSE/key/v1\0"), u16(role <= 3 ? 0x10 : 0x101), point));
}
async function fixture(options = {}) {
  const root = await key();
  const payload = await key();
  const archive = await key();
  const reader = await key();
  const inboundSigner = await key();
  const outboundSigner = await key();
  const issued = now - 1_000n;
  const expires = now + 3_600_000n;
  const records = [
    { role: 1, key: payload, device, line, scope: 4, state: 1 },
    { role: 2, key: archive, device: zero16, line: zero16, scope: 12, state: options.archiveState ?? 1 },
    { role: 3, key: reader, device: zero16, line: zero16, scope: options.readerScope ?? 8, state: 1 },
    { role: 4, key: inboundSigner, device, line, scope: 2, state: options.signerState ?? 1 },
    { role: 5, key: outboundSigner, device: zero16, line: zero16, scope: 1, state: 1 },
    { role: 6, key: root, device: zero16, line: zero16, scope: 0, state: 1 },
  ];
  for (const record of records) record.keyId = await keyId(record.role, record.key.point);
  const encoded = records.map((r) => join(Uint8Array.of(r.role), r.keyId, r.key.point,
    r.device, r.line, u16(r.scope), u64(issued), u64(expires), Uint8Array.of(r.state)));
  const unsigned = join(enc.encode("ZTMA"), Uint8Array.of(2), account, u64(1n), u64(1n),
    u64(issued), u64(expires), zero32, root.point, Uint8Array.of(records.length), ...encoded);
  const transcript = join(enc.encode("ZTSE/manifest/v2\0"), u32(unsigned.length), unsigned);
  const signature = canonicalSignature02(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, root.privateKey, transcript)));
  const pin = { accountId: account, generation: 1n, rootPoint: root.point,
    version: 0n, digest: zero32, anchorDigest: zero32 };
  const manifest = await verifyManifest02(join(unsigned, signature), pin, now);
  const claims = { kind: 2, accountId: account, deviceId: device, lineId: line,
    messageId: event, eventId: event, localSequence: 7n, manifestDigest: Uint8Array.from(manifest.digest),
    keysetVersion: 1n, signerKeyId: records[3].keyId,
    wraps: [{ role: 2, keyId: records[1].keyId }, { role: 3, keyId: records[2].keyId }] };
  return { manifest, claims, records };
}

test("verified manifest authorizes only the device-bound inbound signer and archive/readers", async () => {
  const { manifest, claims, records } = await fixture();
  assert.doesNotThrow(() => authorizeInbound02(manifest, claims, now));
  assert.throws(() => authorizeInbound02({ ...manifest }, claims, now), /just-verified/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, signerKeyId: records[4].keyId }, now), /inbound signer authority/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, deviceId: account }, now), /inbound signer authority/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, lineId: device }, now), /inbound signer authority/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, accountId: device }, now), /manifest binding/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, manifestDigest: zero32 }, now), /manifest binding/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, keysetVersion: 2n }, now), /manifest binding/);
  assert.throws(() => authorizeInbound02(manifest, claims, now + 3_600_000n), /stale or future/);
});

test("inbound event identity, sequence and recipient set fail closed", async () => {
  const { manifest, claims, records } = await fixture();
  assert.throws(() => authorizeInbound02(manifest, { ...claims, eventId: device }, now), /identity\/sequence/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, kind: 1 }, now), /identity\/sequence/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, localSequence: 0n }, now), /identity\/sequence/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, localSequence: 1n << 63n }, now), /identity\/sequence/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, wraps: [claims.wraps[1]] }, now), /reader set/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims, wraps: [...claims.wraps, claims.wraps[0]] }, now), /reader set/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims,
    wraps: [{ role: 1, keyId: records[0].keyId }, ...claims.wraps] }, now), /reader authority/);
  assert.throws(() => authorizeInbound02(manifest, { ...claims,
    wraps: [{ role: 2, keyId: records[0].keyId }, claims.wraps[1]] }, now), /reader authority/);
  const wrongDirection = await fixture({ readerScope: 4 });
  assert.throws(() => authorizeInbound02(wrongDirection.manifest, wrongDirection.claims, now), /reader authority/);
  const revokedSigner = await fixture({ signerState: 2 });
  assert.throws(() => authorizeInbound02(revokedSigner.manifest, revokedSigner.claims, now), /signer authority/);
  await assert.rejects(fixture({ archiveState: 2 }), /owner\/archive cardinality/);
});

test("mutating returned manifest arrays cannot expand inbound authority", async () => {
  const { manifest, claims, records } = await fixture();
  manifest.keys.find((key) => key.role === 4).state = 2;
  manifest.digest.fill(0);
  manifest.bytes.fill(0);
  assert.doesNotThrow(() => authorizeInbound02(manifest, claims, now));
  assert.throws(() => authorizeInbound02(manifest, { ...claims, signerKeyId: records[4].keyId }, now), /signer authority/);
});
