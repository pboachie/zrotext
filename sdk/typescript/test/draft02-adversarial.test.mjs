// SPDX-License-Identifier: AGPL-3.0-only
// Fail-closed manifest verification against tampered, clock-skewed and
// malformed inputs. These vectors mirror the cross-client CI lane; every case
// must reject with a stable error instead of degrading to partial trust.
import assert from "node:assert/strict";
import { test } from "node:test";
import { authorizeOutbound02, canonicalSignature02, verifyManifest02 } from "../dist/draft02-manifest.js";

const encoder = new TextEncoder();
const now = BigInt(Date.now());
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
async function sha(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function key() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function keyId(role, point) {
  return sha(join(encoder.encode("ZTSE/key/v1\0"), role <= 3 ? u16(0x10) : u16(0x101), point));
}
async function sign(k, label, unsigned) {
  const input = join(encoder.encode(`${label}\0`), u32(unsigned.length), unsigned);
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, input)));
}
async function fixture() {
  const root = await key();
  const archive = await key();
  const signer = await key();
  const records = [
    { role: 1, key: await key(), device, line, scope: 4, state: 1 },
    { role: 2, key: archive, device: zero16, line: zero16, scope: 12, state: 1 },
    { role: 5, key: signer, device: zero16, line, scope: 1, state: 1 },
    { role: 6, key: root, device: zero16, line: zero16, scope: 0, state: 1 },
  ];
  for (const record of records) record.keyId = await keyId(record.role, record.key.point);
  return { root, records };
}
async function manifest(f, options = {}) {
  const issued = options.issued ?? now - 1_000n;
  const expires = options.expires ?? now + 3_600_000n;
  const previous = options.previous ?? zero32;
  const sorted = [...f.records].sort((a, b) => a.role - b.role || Buffer.compare(a.keyId, b.keyId));
  const unsigned = join(encoder.encode("ZTMA"), Uint8Array.of(2), account,
    u64(1n), u64(options.version ?? 1n), u64(issued), u64(expires), previous,
    f.root.point, Uint8Array.of(sorted.length), ...sorted.map((r) => join(
      Uint8Array.of(r.role), r.keyId, r.key.point, r.device, r.line,
      u16(r.scope), u64(issued), u64(expires), Uint8Array.of(r.state))));
  return join(unsigned, await sign(options.signer ?? f.root, "ZTSE/manifest/v2", unsigned));
}
function pin(root, digest = zero32, version = 0n) {
  return { accountId: Uint8Array.from(account), generation: 1n, rootPoint: Uint8Array.from(root.point),
    version, digest: Uint8Array.from(digest), anchorDigest: Uint8Array.from(zero32) };
}

test("expired, future and overly wide manifest windows fail closed", async () => {
  const f = await fixture();
  await verifyManifest02(await manifest(f), pin(f.root), now);
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { issued: now - 2n * 3_600_000n, expires: now - 1_000n }), pin(f.root), now), /ZTSE draft-02 manifest:/);
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { issued: now + 600_000n, expires: now + 900_000n }), pin(f.root), now), /ZTSE draft-02 manifest:/);
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { issued: now - 2n * 86_400_000n, expires: now + 3_600_000n }), pin(f.root), now), /ZTSE draft-02 manifest:/);
});

test("tampered manifest bytes and foreign signatures fail closed", async () => {
  const f = await fixture();
  const good = await manifest(f);
  const flipped = Uint8Array.from(good); flipped[flipped.length - 1] ^= 1;
  await assert.rejects(() => verifyManifest02(flipped, pin(f.root), now), /ZTSE draft-02 manifest:/);
  const attacker = await key();
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { signer: attacker }), pin(f.root), now), /ZTSE draft-02 manifest:/);
});

test("wrong chain position and account binding fail closed", async () => {
  const f = await fixture();
  const first = await verifyManifest02(await manifest(f), pin(f.root), now);
  // A genesis-pinned reader must refuse a manifest claiming to follow version 1.
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { version: 2n, previous: first.digest }), pin(f.root), now), /ZTSE draft-02 manifest:/);
  await assert.rejects(
    async () => verifyManifest02(await manifest(f, { previous: await sha(encoder.encode("wrong")) }),
      pin(f.root, first.digest, 1n), now), /ZTSE draft-02 manifest:/);
  const wrongAccount = { ...pin(f.root), accountId: Uint8Array.from({ length: 16 }, (_, i) => i + 90) };
  await assert.rejects(async () => verifyManifest02(await manifest(f), wrongAccount, now), /ZTSE draft-02 manifest:/);
});

test("truncated and oversized manifests fail closed without partial trust", async () => {
  const f = await fixture();
  const good = await manifest(f);
  await assert.rejects(() => verifyManifest02(good.slice(0, good.length - 1), pin(f.root), now), /ZTSE draft-02 manifest:/);
  await assert.rejects(() => verifyManifest02(good.slice(1), pin(f.root), now), /ZTSE draft-02 manifest:/);
  // Past the 9751-byte bound (215 + 149 * 64 records), so the size guard
  // itself rejects before any record is parsed.
  const oversized = join(good, new Uint8Array(9_752));
  await assert.rejects(() => verifyManifest02(oversized, pin(f.root), now), /ZTSE draft-02 manifest: size/);
});

test("envelope authorization rejects misaddressed, misroled and mismatched claims", async () => {
  const f = await fixture();
  const first = await verifyManifest02(await manifest(f), pin(f.root), now);
  const claims = {
    accountId: account, deviceId: device, lineId: line,
    manifestDigest: first.digest, keysetVersion: 1n,
    signerKeyId: f.records[2].keyId,
    wraps: [{ role: 1, keyId: f.records[0].keyId }, { role: 2, keyId: f.records[1].keyId }],
  };
  assert.doesNotThrow(() => authorizeOutbound02(first, claims, now));
  const stranger = await sha(encoder.encode("stranger-recipient"));
  for (const [why, changed] of [
    ["unknown recipient key", { ...claims, wraps: [{ role: 1, keyId: stranger }, claims.wraps[1]] }],
    ["dropped reader", { ...claims, wraps: [claims.wraps[0]] }],
    ["foreign account", { ...claims, accountId: Uint8Array.from({ length: 16 }, (_, i) => i + 90) }],
    ["root as envelope signer", { ...claims, signerKeyId: f.records[3].keyId }],
    ["wrong manifest digest", { ...claims, manifestDigest: stranger }],
    ["wrong keyset version", { ...claims, keysetVersion: 2n }],
  ]) {
    assert.throws(() => authorizeOutbound02(first, changed, now), /ZTSE draft-02 manifest:/, why);
  }
  // An extra wrap keyed to the archive key the manifest grants under role 2
  // keeps the key real and active, so only the ungranted role can reject it.
  // A stranger key id would collapse into the unknown-key case.
  assert.throws(
    () => authorizeOutbound02(first, { ...claims, wraps: [...claims.wraps, { role: 3, keyId: f.records[1].keyId }] }, now),
    /ZTSE draft-02 manifest: reader authority/,
    "ungranted extra role",
  );
});
