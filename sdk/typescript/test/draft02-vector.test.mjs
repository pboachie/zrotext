import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  enrollRootPin02, verifyManifest02, advanceManifestTrust02, verifyRootTransition02,
  authorizeOutbound02,
} from "../dist/draft02-manifest.js";

const vector = JSON.parse(readFileSync(new URL("./vectors/draft02-genesis.json", import.meta.url), "utf8"));
const rotation = JSON.parse(readFileSync(new URL("./vectors/draft02-rotation.json", import.meta.url), "utf8"));
const bytes = (field) => new Uint8Array(Buffer.from(vector[field], "base64"));
const rotatedBytes = (field) => new Uint8Array(Buffer.from(rotation[field], "base64"));
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

test("synthetic public genesis vector verifies exact profile-02 manifest and authority", async () => {
  const pin = await enrollRootPin02(bytes("root_pin_b64"), bytes("root_fingerprint_b64"));
  const now = BigInt(vector.now_ms);
  const manifest = await verifyManifest02(bytes("manifest_b64"), pin, now);
  assert.deepEqual(manifest.digest, bytes("semantic_manifest_digest_b64"));
  const signer = manifest.keys.find((key) => key.role === 5);
  const device = manifest.keys.find((key) => key.role === 1);
  const archive = manifest.keys.find((key) => key.role === 2);
  assert.ok(signer && device && archive);
  assert.deepEqual(signer.deviceId, new Uint8Array(16));
  assert.deepEqual(signer.lineId, bytes("line_id_b64"));
  assert.doesNotThrow(() => authorizeOutbound02(manifest, {
    accountId: pin.accountId,
    deviceId: bytes("device_id_b64"),
    lineId: bytes("line_id_b64"),
    manifestDigest: manifest.digest,
    keysetVersion: manifest.version,
    signerKeyId: signer.keyId,
    wraps: [{ role: 1, keyId: device.keyId }, { role: 2, keyId: archive.keyId }],
  }, now));
  assert.throws(() => authorizeOutbound02(manifest, {
    accountId: pin.accountId, deviceId: bytes("device_id_b64"), lineId: bytes("device_id_b64"),
    manifestDigest: manifest.digest, keysetVersion: manifest.version, signerKeyId: signer.keyId,
    wraps: [{ role: 1, keyId: device.keyId }, { role: 2, keyId: archive.keyId }],
  }, now), /outbound signer authority/);
});

test("synthetic public vector rejects wrong pin and high-s signature alias", async () => {
  const rootPin = bytes("root_pin_b64");
  const fingerprint = bytes("root_fingerprint_b64");
  const wrong = Uint8Array.from(fingerprint);
  wrong[0] ^= 1;
  await assert.rejects(enrollRootPin02(rootPin, wrong), /root pin comparison/);

  const pin = await enrollRootPin02(rootPin, fingerprint);
  const altered = bytes("manifest_b64");
  const s = altered.subarray(altered.length - 32).reduce((n, b) => (n << 8n) | BigInt(b), 0n);
  const high = order - s;
  for (let i = 0; i < 32; i++) altered[altered.length - 1 - i] = Number(high >> BigInt(8 * i) & 255n);
  await assert.rejects(verifyManifest02(altered, pin, BigInt(vector.now_ms)), /high-s signature/);
});

test("synthetic public rotation vector verifies both roots and linked new-generation manifest", async () => {
  const now = BigInt(rotation.now_ms);
  const initial = await enrollRootPin02(rotatedBytes("old_root_pin_b64"), rotatedBytes("old_root_fingerprint_b64"));
  const oldManifest = await verifyManifest02(rotatedBytes("old_manifest_b64"), initial, now);
  assert.deepEqual(oldManifest.digest, rotatedBytes("old_semantic_manifest_digest_b64"));
  const current = advanceManifestTrust02(initial, oldManifest);
  const expectedNewRoot = rotatedBytes("new_root_point_b64");
  const next = await verifyRootTransition02(rotatedBytes("transition_b64"), current, now, expectedNewRoot);
  assert.equal(next.generation, 2n);
  assert.equal(next.version, 0n);
  assert.deepEqual(next.anchorDigest, rotatedBytes("transition_anchor_digest_b64"));
  assert.deepEqual(next.rootPoint, expectedNewRoot);
  const newManifest = await verifyManifest02(rotatedBytes("new_manifest_b64"), next, now);
  assert.deepEqual(newManifest.digest, rotatedBytes("new_semantic_manifest_digest_b64"));
  assert.deepEqual(newManifest.previousDigest, next.anchorDigest);
  const signer = newManifest.keys.find((key) => key.role === 5);
  const device = newManifest.keys.find((key) => key.role === 1);
  const archive = newManifest.keys.find((key) => key.role === 2);
  assert.ok(signer && device && archive);
  assert.deepEqual(signer.lineId, rotatedBytes("line_id_b64"));
  assert.doesNotThrow(() => authorizeOutbound02(newManifest, {
    accountId: next.accountId,
    deviceId: rotatedBytes("device_id_b64"),
    lineId: rotatedBytes("line_id_b64"),
    manifestDigest: newManifest.digest,
    keysetVersion: 1n,
    signerKeyId: signer.keyId,
    wraps: [{ role: 1, keyId: device.keyId }, { role: 2, keyId: archive.keyId }],
  }, now));
});

test("synthetic public rotation vector rejects wrong root, signature alias and broken anchor", async () => {
  const now = BigInt(rotation.now_ms);
  const initial = await enrollRootPin02(rotatedBytes("old_root_pin_b64"), rotatedBytes("old_root_fingerprint_b64"));
  const oldManifest = await verifyManifest02(rotatedBytes("old_manifest_b64"), initial, now);
  const current = advanceManifestTrust02(initial, oldManifest);
  const expectedNewRoot = rotatedBytes("new_root_point_b64");
  const transition = rotatedBytes("transition_b64");
  await assert.rejects(verifyRootTransition02(transition, current, now, initial.rootPoint), /transition pin\/chain/);
  for (const offset of [215, 279]) {
    const high = Uint8Array.from(transition);
    const s = high.subarray(offset + 32, offset + 64).reduce((n, b) => (n << 8n) | BigInt(b), 0n);
    const twin = order - s;
    for (let i = 0; i < 32; i++) high[offset + 63 - i] = Number(twin >> BigInt(8 * i) & 255n);
    await assert.rejects(verifyRootTransition02(high, current, now, expectedNewRoot), /high-s signature/);
  }
  const broken = { ...current, digest: Uint8Array.from(current.digest) };
  broken.digest[0] ^= 1;
  await assert.rejects(verifyRootTransition02(transition, broken, now, expectedNewRoot), /transition pin\/chain/);
  const next = await verifyRootTransition02(transition, current, now, expectedNewRoot);
  const wrongAnchor = { ...next, anchorDigest: Uint8Array.from(next.anchorDigest) };
  wrongAnchor.anchorDigest[0] ^= 1;
  await assert.rejects(verifyManifest02(rotatedBytes("new_manifest_b64"), wrongAnchor, now), /genesis\/transition chain/);
});
