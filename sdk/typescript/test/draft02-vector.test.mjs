import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  enrollRootPin02, verifyManifest02, authorizeOutbound02,
} from "../dist/draft02-manifest.js";

const vector = JSON.parse(readFileSync(new URL("./vectors/draft02-genesis.json", import.meta.url), "utf8"));
const bytes = (field) => new Uint8Array(Buffer.from(vector[field], "base64"));
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
  assert.doesNotThrow(() => authorizeOutbound02(manifest, {
    accountId: pin.accountId,
    deviceId: bytes("device_id_b64"),
    lineId: bytes("line_id_b64"),
    manifestDigest: manifest.digest,
    keysetVersion: manifest.version,
    signerKeyId: signer.keyId,
    wraps: [{ role: 1, keyId: device.keyId }, { role: 2, keyId: archive.keyId }],
  }, now));
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
