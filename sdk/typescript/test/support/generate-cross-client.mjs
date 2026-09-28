// SPDX-License-Identifier: AGPL-3.0-only
// Generate synthetic encrypted test inputs from independently pinned SQL setup.
// Keys are ephemeral test material. Setup JSON arrives on stdin and the fixture leaves on
// stdout, so this helper never opens a caller-chosen path.
import assert from 'node:assert/strict';
import { createECDH, createHash, randomBytes, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';

globalThis.crypto ??= webcrypto;
const { prepareOutboundEnvelope02, prepareInboundEnvelope02 } = await import('../../dist/draft02-envelope-prep.js');
const { verifyManifest02, canonicalSignature02 } = await import('../../dist/draft02-manifest.js');
const setup = readFileSync(0);
assert.ok(setup.length > 0 && setup.length <= 8192, 'Setup fixture must be nonempty and within its size bound');
const input = JSON.parse(setup.toString('utf8'));
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
async function sign(key, transcript) {
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, ab(transcript))));
}
// The primary manifest keeps the live window; adversarial manifests only vary
// the acceptance window or the anchored previous digest and stay fully signed.
function unsignedManifestBytes(start, end, digest) {
  return concat(ascii('ZTMA'), Uint8Array.of(2), account,
    u64(1), u64(2), u64(start), u64(end), digest, root.publicPoint,
    Uint8Array.of(records.length), ...records.map(([role, id, point, dev, ln, scope]) =>
      concat(Uint8Array.of(role), id, point, dev, ln, u16(scope), u64(start), u64(end), Uint8Array.of(1))));
}
async function signedManifest(start, end, digest) {
  const unsigned = unsignedManifestBytes(start, end, digest);
  return concat(unsigned, await sign(root.privateKey,
    concat(ascii('ZTSE/manifest/v2\0'), u32(unsigned.length), unsigned)));
}
async function expectManifestRejection(manifest, why) {
  try {
    await verifyManifest02(manifest, {
      accountId: account, generation: 1n, rootPoint: root.publicPoint,
      version: 1n, digest: previousDigest, anchorDigest: new Uint8Array(32),
    }, now);
  } catch {
    return; // Fail-closed verification is the expected outcome.
  }
  assert.fail(`adversarial manifest must fail closed: ${why}`);
}
const manifestBytes = await signedManifest(now - 1n, now + 300_000n, previousDigest);
const manifest = await verifyManifest02(manifestBytes, {
  accountId: account, generation: 1n, rootPoint: root.publicPoint,
  version: 1n, digest: previousDigest, anchorDigest: new Uint8Array(32),
}, now);
const manifestExpired = await signedManifest(now - 600_000n, now - 300_000n, previousDigest);
await expectManifestRejection(manifestExpired, 'expired window');
const manifestFuture = await signedManifest(now + 600_000n, now + 900_000n, previousDigest);
await expectManifestRejection(manifestFuture, 'future window');
const manifestWrongPreviousDigest = await signedManifest(now - 1n, now + 300_000n,
  Uint8Array.from(sha(ascii('adversarial-anchor'))));
await expectManifestRejection(manifestWrongPreviousDigest, 'wrong previous digest');
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
// A different inbound event reusing the same device sequence is the reorder
// vector: individually valid bytes that must still be refused as a regression.
const reorderedEvent = randomBytes(16);
const inboundReusedSequence = await prepareInboundEnvelope02({ ...common, kind: 2,
  messageId: reorderedEvent, eventId: reorderedEvent,
  localSequence: 1n, cek: randomBytes(32), nonce: randomBytes(12), signer: inboundSigner,
  recipients: [{ role: 2, keyId: archiveKey.id, point: archiveKey.point, ekm: randomBytes(32) }],
});
for (const value of [outbound, inbound, inboundReusedSequence]) {
  assert.deepEqual(sha(value.unsigned), value.unsignedSha256);
}
// Re-sign modified unsigned bytes so every rejection exercises the intended
// check instead of a bare signature failure; unsigned layout mirrors the reader:
// header(10) + protected, account at protected[0..16], profile at byte 4.
const resign = async (unsigned, signer) => concat(unsigned, await sign(signer.privateKey,
  concat(ascii('ZTSE/sign/v2\0'), u32(unsigned.length), unsigned)));
const mut = async (source, edit, signer) => {
  const unsigned = Uint8Array.from(source.unsigned);
  edit(unsigned);
  return resign(unsigned, signer);
};
// Protected fields sit at header(10)+offset; only the nonce follows protected.
const protectedAt = (unsigned, offset) => 10 + offset;
const wrongNonceUnsigned = Uint8Array.from(outbound.unsigned);
wrongNonceUnsigned[10 + new DataView(wrongNonceUnsigned.buffer).getUint16(8)] ^= 1;
const wrongNonce = await resign(wrongNonceUnsigned, outboundSigner);
const wrongSignature = Uint8Array.from(outbound.envelope); wrongSignature[wrongSignature.length - 1] ^= 1;
// Truncations, oversizing and last-byte signature flips are derived by each
// consumer from the primary envelopes, so only re-signed variants ship here.
const outboundDowngradeV1 = await mut(outbound, (u) => { u[4] = 1; }, outboundSigner);
// Unsigned tail layout: body | count(1) | wraps (count x 146); outbound has two wraps.
const outboundCountAt = (u) => {
  const at = u.length - 1 - 2 * 146;
  assert.equal(u[at], 2, 'outbound wrap count');
  return at;
};
const outboundWrongRecipient = await mut(outbound, (u) => {
  const wrapStart = outboundCountAt(u) + 1; // First wrap: role byte, then key id.
  for (let i = 0; i < 32; i += 1) u[wrapStart + 1 + i] = i; // Unknown key id, still signed.
}, outboundSigner);
const outboundWrongRole = await mut(outbound, (u) => {
  // Sort-order attack: role 3 before the archive wrap breaks wrap ordering,
  // so this vector pins the parser's ordering rejection, not grant checks.
  u[outboundCountAt(u) + 1] = 3;
}, outboundSigner);
// A third wrap with a parser-legal role the manifest never grants. The wrap
// order stays valid and recipient cardinality holds (one device, one archive),
// so this reaches the manifest authority check instead of the parser.
const ungrantedUnsigned = (() => {
  const u = Uint8Array.from(outbound.unsigned);
  const countAt = outboundCountAt(u);
  u[countAt] = 3;
  return concat(u, concat(Uint8Array.of(3), randomBytes(32), archiveKey.point, new Uint8Array(48)));
})();
const outboundUngrantedThirdWrap = await resign(ungrantedUnsigned, outboundSigner);
const outboundWrongAccount = await mut(outbound, (u) => { u[protectedAt(u, 0)] ^= 1; }, outboundSigner);
const outboundExpired = await mut(outbound, (u) => {
  new DataView(u.buffer).setBigUint64(protectedAt(u, 136), now - 600_000n);
  new DataView(u.buffer).setBigUint64(protectedAt(u, 144), now - 540_000n);
}, outboundSigner);
const outboundFuture = await mut(outbound, (u) => {
  new DataView(u.buffer).setBigUint64(protectedAt(u, 136), now + 600_000n);
  new DataView(u.buffer).setBigUint64(protectedAt(u, 144), now + 660_000n);
}, outboundSigner);
const inboundSequenceZero = await mut(inbound, (u) => {
  new DataView(u.buffer).setBigUint64(protectedAt(u, 160), 0n);
}, inboundSigner);
const inboundObservedStale = await mut(inbound, (u) => {
  new DataView(u.buffer).setBigUint64(protectedAt(u, 136), now - 8n * 24n * 60n * 60n * 1000n);
}, inboundSigner);
const inboundObservedFuture = await mut(inbound, (u) => {
  new DataView(u.buffer).setBigUint64(protectedAt(u, 136), now + 6n * 60n * 1000n);
}, inboundSigner);
// Same event identity, different validly signed bytes: the replay conflict vector.
const inboundReplayedDifferentBytes = await mut(inbound, (u) => {
  u[u.length - 1] ^= 1; // Last wrap ciphertext byte.
}, inboundSigner);
process.stdout.write(JSON.stringify({
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
  manifestExpired: hex(manifestExpired),
  manifestFuture: hex(manifestFuture), manifestWrongPreviousDigest: hex(manifestWrongPreviousDigest),
  inboundReusedSequence: hex(inboundReusedSequence.envelope),
  inboundSequenceZero: hex(inboundSequenceZero),
  inboundObservedStale: hex(inboundObservedStale), inboundObservedFuture: hex(inboundObservedFuture),
  inboundReplayedDifferentBytes: hex(inboundReplayedDifferentBytes),
  outboundDowngradeV1: hex(outboundDowngradeV1), outboundWrongRecipient: hex(outboundWrongRecipient),
  outboundMisorderedWrap: hex(outboundWrongRole), outboundUngrantedThirdWrap: hex(outboundUngrantedThirdWrap),
  outboundWrongAccount: hex(outboundWrongAccount),
  outboundExpired: hex(outboundExpired), outboundFuture: hex(outboundFuture),
}, null, 2));
