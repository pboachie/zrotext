// SPDX-License-Identifier: AGPL-3.0-only
// Generate synthetic encrypted test inputs from independently pinned SQL setup.
// Keys are ephemeral test material; write output only to a temporary directory.
import assert from 'node:assert/strict';
import { createECDH, createHash, randomBytes, webcrypto } from 'node:crypto';
import { readFileSync, statSync, writeFileSync } from 'node:fs';

globalThis.crypto ??= webcrypto;
const [inputPath, outputPath] = process.argv.slice(2);
assert.ok(inputPath && outputPath, 'Provide the setup JSON and output JSON paths');
const { prepareOutboundEnvelope02, prepareInboundEnvelope02 } = await import('../../dist/draft02-envelope-prep.js');
const { verifyManifest02, canonicalSignature02 } = await import('../../dist/draft02-manifest.js');
assert.ok(statSync(inputPath).size <= 8192, 'Setup fixture exceeds its size bound');
const input = JSON.parse(readFileSync(inputPath, 'utf8'));
const fromHex = (s) => {
  assert.equal(typeof s, 'string');
  assert.ok(s.length <= 188, 'Setup byte field exceeds its size bound');
  assert.match(s, /^(?:[0-9a-f]{2})+$/);
  return Uint8Array.from(Buffer.from(s, 'hex'));
};
const hex = (b) => Buffer.from(b).toString('hex');
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((p) => Buffer.from(p))));
const ascii = (s) => new TextEncoder().encode(s);
const sha = (b) => Uint8Array.from(createHash('sha256').update(b).digest());
const ab = (b) => Uint8Array.from(b).buffer;
const u16 = (n) => Uint8Array.of(n >>> 8, n & 255);
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const u64 = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };
const keyId = (algorithm, point) => sha(concat(ascii('ZTSE/key/v1\0'), u16(algorithm), point));
assert.ok(Number.isSafeInteger(input.now) && input.now > 0 && Number.isSafeInteger(input.now + 300_000));
const now = BigInt(input.now);
const account = fromHex(input.account), device = fromHex(input.device), line = fromHex(input.line);
const message = fromHex(input.message), event = fromHex(input.event);
const rootPin = fromHex(input.rootPin), previousDigest = fromHex(input.previousDigest);
for (const id of [account, device, line, message, event]) assert.equal(id.length, 16);
assert.equal(previousDigest.length, 32);
assert.equal(fromHex(input.rootScalar).length, 32);
assert.equal(fromHex(input.outboundSignerScalar).length, 32);
assert.equal(rootPin.length, 94);
assert.equal(Number(input.previousVersion), 1);

async function signingKey(scalar) {
  const ec = createECDH('prime256v1'); ec.setPrivateKey(scalar);
  const point = Uint8Array.from(ec.getPublicKey(undefined, 'uncompressed'));
  const b64 = (b) => Buffer.from(b).toString('base64url');
  const privateKey = await crypto.subtle.importKey('jwk', {
    kty: 'EC', crv: 'P-256', x: b64(point.slice(1, 33)), y: b64(point.slice(33)),
    d: b64(scalar), ext: false, key_ops: ['sign'],
  }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  return { privateKey, publicPoint: point, id: keyId(0x0101, point) };
}
async function kemKey() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { point, id: keyId(0x0010, point), scalar: Buffer.from(jwk.d, 'base64url') };
}
const root = await signingKey(fromHex(input.rootScalar));
const outboundSigner = await signingKey(fromHex(input.outboundSignerScalar));
const inboundPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const inboundPoint = new Uint8Array(await crypto.subtle.exportKey('raw', inboundPair.publicKey));
const inboundSigner = { privateKey: inboundPair.privateKey, publicPoint: inboundPoint, id: keyId(0x0101, inboundPoint) };
const deviceKey = await kemKey(), archiveKey = await kemKey();
assert.deepEqual(root.publicPoint, rootPin.slice(29));
const zeroId = new Uint8Array(16);
const records = [
  [1, deviceKey.id, deviceKey.point, device, line, 4],
  [2, archiveKey.id, archiveKey.point, zeroId, zeroId, 12],
  [4, inboundSigner.id, inboundSigner.publicPoint, device, line, 2],
  [5, outboundSigner.id, outboundSigner.publicPoint, zeroId, line, 1],
  [6, root.id, root.publicPoint, zeroId, zeroId, 0],
];
const unsignedManifest = concat(ascii('ZTMA'), Uint8Array.of(2), account,
  u64(1), u64(2), u64(now - 1n), u64(now + 300_000n), previousDigest, root.publicPoint,
  Uint8Array.of(records.length), ...records.map(([role, id, point, dev, ln, scope]) =>
    concat(Uint8Array.of(role), id, point, dev, ln, u16(scope), u64(now - 1n), u64(now + 300_000n), Uint8Array.of(1))));
async function sign(key, transcript) {
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, ab(transcript))));
}
const manifestBytes = concat(unsignedManifest, await sign(root.privateKey,
  concat(ascii('ZTSE/manifest/v2\0'), u32(unsignedManifest.length), unsignedManifest)));
const manifest = await verifyManifest02(manifestBytes, {
  accountId: account, generation: 1n, rootPoint: root.publicPoint,
  version: 1n, digest: previousDigest, anchorDigest: new Uint8Array(32),
}, now);
const expectedText = 'Cross-client synthetic ciphertext ✓';
const common = { manifest, nowMs: now, deviceId: device, lineId: line,
  peer: ascii('+12'), observedMs: now, content: expectedText };
const outbound = await prepareOutboundEnvelope02({ ...common, kind: 1, messageId: message,
  expiresMs: now + 60_000n, cek: randomBytes(32), nonce: randomBytes(12), signer: outboundSigner,
  recipients: [
    { role: 1, keyId: deviceKey.id, point: deviceKey.point, ekm: randomBytes(32) },
    { role: 2, keyId: archiveKey.id, point: archiveKey.point, ekm: randomBytes(32) },
  ],
});
const inbound = await prepareInboundEnvelope02({ ...common, kind: 2, messageId: event, eventId: event,
  localSequence: 1n, cek: randomBytes(32), nonce: randomBytes(12), signer: inboundSigner,
  recipients: [{ role: 2, keyId: archiveKey.id, point: archiveKey.point, ekm: randomBytes(32) }],
});
for (const value of [outbound, inbound]) assert.deepEqual(sha(value.unsigned), value.unsignedSha256);
const wrongNonceUnsigned = Uint8Array.from(outbound.unsigned);
wrongNonceUnsigned[10 + new DataView(wrongNonceUnsigned.buffer).getUint16(8)] ^= 1;
const wrongNonce = concat(wrongNonceUnsigned, await sign(outboundSigner.privateKey,
  concat(ascii('ZTSE/sign/v2\0'), u32(wrongNonceUnsigned.length), wrongNonceUnsigned)));
const wrongSignature = Uint8Array.from(outbound.envelope); wrongSignature[wrongSignature.length - 1] ^= 1;
writeFileSync(outputPath, JSON.stringify({
  fixtureVersion: 1,
  now: Number(now), account: hex(account), device: hex(device), line: hex(line),
  message: hex(message), event: hex(event), peer: '+12', expectedText,
  rootPin: hex(rootPin), rootFingerprint: hex(sha(concat(ascii('ZTSE/root-pin/v2\0'), rootPin))),
  previousVersion: 1, previousDigest: hex(previousDigest), manifest: hex(manifestBytes),
  signerKeyId: hex(outboundSigner.id), inboundSignerKeyId: hex(inboundSigner.id),
  deviceKeyId: hex(deviceKey.id), archiveKeyId: hex(archiveKey.id), devicePoint: hex(deviceKey.point),
  devicePrivateScalar: hex(deviceKey.scalar), outboundEnvelope: hex(outbound.envelope),
  inboundEnvelope: hex(inbound.envelope), outboundUnsignedDigest: hex(outbound.unsignedSha256),
  inboundUnsignedDigest: hex(inbound.unsignedSha256), outboundWrongNonce: hex(wrongNonce),
  outboundWrongSignature: hex(wrongSignature),
}, null, 2));
