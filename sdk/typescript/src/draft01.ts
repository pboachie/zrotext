/** Experimental ZTSE draft-01 byte reader. No manifest trust or radio authority. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const wrapSize = 146;
const maxSigned = (1n << 63n) - 1n;

function label(value: string): Uint8Array { return encoder.encode(`${value}\0`); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function buffer(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
function fail(message: string): never { throw new Error(`ZTSE draft-01: ${message}`); }
function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function u32(value: number): Uint8Array {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}
function number64(data: Uint8Array, offset: number): bigint {
  const value = new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(offset, false);
  if (value > maxSigned) fail("u64 exceeds signed storage range");
  return value;
}
function pointShape(point: Uint8Array): void {
  if (point.length !== 65 || point[0] !== 4) fail("invalid P-256 point encoding");
}
function peerValue(bytes: Uint8Array): string {
  if (bytes.length < 3 || bytes.length > 16 || bytes[0] !== 43 || bytes[1] < 49 || bytes[1] > 57 ||
      !bytes.subarray(2).every((byte) => byte >= 48 && byte <= 57)) fail("invalid E.164 peer");
  return decoder.decode(bytes);
}

export type DraftWrap = Readonly<{ role: number; keyId: Uint8Array; enc: Uint8Array; ct: Uint8Array }>;
export type DraftEnvelope = Readonly<{
  kind: 1 | 2; bytes: Uint8Array; protected: Uint8Array; unsigned: Uint8Array;
  accountId: Uint8Array; messageId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  keysetVersion: bigint; manifestDigest: Uint8Array; signerKeyId: Uint8Array;
  observedMs: bigint; expiresMs?: bigint; eventId?: Uint8Array; localSequence?: bigint;
  peer: string; nonce: Uint8Array; bodyCt: Uint8Array; wraps: readonly DraftWrap[]; signature: Uint8Array;
}>;

/** Performs bounded syntax validation; cryptographic validity is a separate step. */
export function parseDraftEnvelope(input: Uint8Array): DraftEnvelope {
  if (input.length < 426 || input.length > 36_864) fail("envelope size");
  const bytes = Uint8Array.from(input);
  if (!equal(bytes.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x53, 0x45, 1))) fail("magic/profile");
  const kind = bytes[5];
  if (kind !== 1 && kind !== 2) fail("kind");
  if (bytes[6] !== 0 || bytes[7] !== 0) fail("flags");
  const view = new DataView(bytes.buffer);
  const protectedLen = view.getUint16(8, false);
  const minProtected = kind === 1 ? 157 : 172;
  const maxProtected = kind === 1 ? 170 : 185;
  if (protectedLen < minProtected || protectedLen > maxProtected) fail("protected length");
  const protectedEnd = 10 + protectedLen;
  if (protectedEnd + 12 + 4 + 17 + 1 + wrapSize + 64 > bytes.length) fail("truncated header/body");
  const protectedBytes = bytes.subarray(10, protectedEnd);
  const peerLengthAt = kind === 1 ? 153 : 168;
  const peerLen = protectedBytes[peerLengthAt];
  if (protectedLen !== (kind === 1 ? 154 : 169) + peerLen) fail("noncanonical protected length");
  const peer = peerValue(protectedBytes.subarray(peerLengthAt + 1));
  const keysetVersion = number64(protectedBytes, 64);
  const observedMs = number64(protectedBytes, 136);
  let expiresMs: bigint | undefined;
  let eventId: Uint8Array | undefined;
  let localSequence: bigint | undefined;
  if (kind === 1) {
    expiresMs = number64(protectedBytes, 144);
    if (protectedBytes[152] !== 1 || expiresMs <= observedMs || expiresMs - observedMs > 900_000n) fail("intent/expiry");
  } else {
    eventId = protectedBytes.subarray(144, 160);
    localSequence = number64(protectedBytes, 160);
    if (!equal(protectedBytes.subarray(16, 32), eventId) || localSequence === 0n) fail("inbound identity/sequence");
  }
  const nonce = bytes.subarray(protectedEnd, protectedEnd + 12);
  const bodyLen = view.getUint32(protectedEnd + 12, false);
  if (bodyLen < 17 || bodyLen > 32_784) fail("body length");
  const bodyEnd = protectedEnd + 16 + bodyLen;
  if (bodyEnd >= bytes.length) fail("truncated body");
  const count = bytes[bodyEnd];
  if (count < (kind === 1 ? 2 : 1) || count > (kind === 1 ? 8 : 7)) fail("wrap count");
  const unsignedEnd = bodyEnd + 1 + count * wrapSize;
  if (unsignedEnd + 64 !== bytes.length) fail("truncated/trailing wrap or signature");
  const wraps: DraftWrap[] = [];
  let deviceCount = 0;
  let archiveCount = 0;
  for (let index = 0; index < count; index++) {
    const start = bodyEnd + 1 + index * wrapSize;
    const role = bytes[start];
    const keyId = bytes.subarray(start + 1, start + 33);
    const enc = bytes.subarray(start + 33, start + 98);
    const ct = bytes.subarray(start + 98, start + wrapSize);
    if (role < 1 || role > 3) fail("wrap role");
    if (index > 0) {
      const last = wraps[index - 1];
      if (role < last.role || (role === last.role && compare(keyId, last.keyId) <= 0)) fail("wrap order/duplicate");
    }
    pointShape(enc);
    if (role === 1) deviceCount++;
    if (role === 2) archiveCount++;
    wraps.push({ role, keyId, enc, ct });
  }
  if (deviceCount !== (kind === 1 ? 1 : 0) || archiveCount !== 1) fail("recipient roles");
  return {
    kind, bytes, protected: protectedBytes, unsigned: bytes.subarray(0, unsignedEnd),
    accountId: protectedBytes.subarray(0, 16), messageId: protectedBytes.subarray(16, 32),
    deviceId: protectedBytes.subarray(32, 48), lineId: protectedBytes.subarray(48, 64),
    keysetVersion, manifestDigest: protectedBytes.subarray(72, 104),
    signerKeyId: protectedBytes.subarray(104, 136), observedMs, expiresMs, eventId, localSequence,
    peer, nonce, bodyCt: bytes.subarray(protectedEnd + 16, bodyEnd), wraps,
    signature: bytes.subarray(unsignedEnd),
  };
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
  return 0;
}
export function bodyAad(parsed: DraftEnvelope): Uint8Array {
  return concat(label("ZTSE/body/v1"), parsed.bytes.subarray(0, 10), parsed.protected);
}
export function signatureInput(parsed: DraftEnvelope): Uint8Array {
  return concat(label("ZTSE/sign/v1"), u32(parsed.unsigned.length), parsed.unsigned);
}
export async function keyId(algorithm: 0x0010 | 0x0101, point: Uint8Array): Promise<Uint8Array> {
  pointShape(point);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(concat(label("ZTSE/key/v1"),
    Uint8Array.of(algorithm >> 8, algorithm & 255), point))));
}
export async function wrapInfo(parsed: DraftEnvelope, wrap: DraftWrap): Promise<Uint8Array> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(parsed.protected)));
  return concat(label("ZTSE/wrap/v1"), hash, Uint8Array.of(wrap.role), wrap.keyId);
}
export function wrapAad(parsed: DraftEnvelope, wrap: DraftWrap): Uint8Array {
  return concat(label("ZTSE/wrap-aad/v1"), parsed.protected, Uint8Array.of(wrap.role), wrap.keyId);
}

export type DraftOpenContext = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array; peer: string;
  manifestDigest: Uint8Array; signerPublicPoint: Uint8Array;
  recipientRole: 1 | 2 | 3; recipientKeyId: Uint8Array; recipientPrivateKey: CryptoKey;
}>;

/** Caller supplies independently trusted IDs and keys. Does not validate manifest authorization or replay state. */
export async function openDraftEnvelope(input: Uint8Array, expected: DraftOpenContext): Promise<string> {
  const parsed = parseDraftEnvelope(input);
  if (!equal(parsed.accountId, expected.accountId) || !equal(parsed.deviceId, expected.deviceId) ||
      !equal(parsed.lineId, expected.lineId) || parsed.peer !== expected.peer ||
      !equal(parsed.manifestDigest, expected.manifestDigest)) fail("authenticated routing mismatch");
  pointShape(expected.signerPublicPoint);
  if (!equal(await keyId(0x0101, expected.signerPublicPoint), parsed.signerKeyId)) fail("signer key ID mismatch");
  const signer = await crypto.subtle.importKey("raw", buffer(expected.signerPublicPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signer, buffer(parsed.signature), buffer(signatureInput(parsed)))) {
    fail("origin signature");
  }
  for (const candidate of parsed.wraps) await suite.kem.deserializePublicKey(buffer(candidate.enc));
  const wrap = parsed.wraps.find((item) => item.role === expected.recipientRole && equal(item.keyId, expected.recipientKeyId));
  if (!wrap) fail("authorized recipient wrap missing");
  const recipient = await suite.createRecipientContext({ recipientKey: expected.recipientPrivateKey, enc: buffer(wrap.enc), info: buffer(await wrapInfo(parsed, wrap)) });
  const cek = new Uint8Array(await recipient.open(buffer(wrap.ct), buffer(wrapAad(parsed, wrap))));
  if (cek.length !== 32) fail("content key length");
  const bodyKey = await crypto.subtle.importKey("raw", buffer(cek), "AES-GCM", false, ["decrypt"]);
  const body = await crypto.subtle.decrypt({ name: "AES-GCM", iv: buffer(parsed.nonce), additionalData: buffer(bodyAad(parsed)), tagLength: 128 }, bodyKey, buffer(parsed.bodyCt));
  const textBytes = new Uint8Array(body);
  if (textBytes.length < 1 || textBytes.length > 32_768 || textBytes.includes(0) ||
      (textBytes.length >= 3 && equal(textBytes.subarray(0, 3), Uint8Array.of(0xef, 0xbb, 0xbf)))) fail("body text bounds");
  return decoder.decode(textBytes);
}
