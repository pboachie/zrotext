/**
 * Experimental test-only profile-02 envelope preparation. Not a production SDK
 * path: nothing here may be connected to a send, inbound, webhook, or radio
 * route. Composition is refused unless the exact `Manifest02` object returned by
 * `verifyManifest02` authorizes the request through `authorizeOutbound02` /
 * `authorizeInbound02` first; authorization is never re-implemented locally.
 */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { keyId } from "./draft01.js";
import {
  authorizeInbound02, authorizeOutbound02, canonicalSignature02, type Manifest02,
} from "./draft02-manifest.js";

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const maxSigned = (1n << 63n) - 1n;
const maxBodyText = 32_768;
const maxExpiryDelta = 900_000n;

function fail(why: string): never { throw new Error(`ZTSE draft-02 envelope prep: ${why}`); }
function label(value: string): Uint8Array { return encoder.encode(`${value}\0`); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function ab(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function compare(a: Uint8Array, b: Uint8Array): number {
  for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
}
function u16(value: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, value, false);
  return out;
}
function u32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}
function u64(value: bigint): Uint8Array {
  if (value < 0n || value > maxSigned) fail("u64 exceeds signed storage range");
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}
function fixed(bytes: Uint8Array, length: number, name: string): Uint8Array {
  if (bytes.length !== length) fail(`${name} width`);
  return bytes;
}

/** One authorized recipient wrap: the manifest `(role, keyId)` plus the exact KEM point it names. */
export type Draft02PrepRecipient = Readonly<{
  role: 1 | 2 | 3;
  /** Must equal SHA-256("ZTSE/key/v1\0" || 0x0010 || point) and appear in the verified manifest. */
  keyId: Uint8Array;
  /** 65-byte uncompressed P-256 KEM recipient point. */
  point: Uint8Array;
  /** 32-byte deterministic HPKE ephemeral IKM; test-only randomness stand-in. */
  ekm: Uint8Array;
}>;

/** The manifest-authorized origin signer (role 5 outbound, role 4 inbound). */
export type Draft02PrepSigner = Readonly<{
  privateKey: CryptoKey;
  /** 65-byte uncompressed P-256 point whose 0x0101 key ID the manifest must authorize. */
  publicPoint: Uint8Array;
}>;

type CommonPrepInput = Readonly<{
  /** The exact object returned by `verifyManifest02`; copies are rejected fail-closed. */
  manifest: Manifest02;
  nowMs: bigint;
  messageId: Uint8Array;
  deviceId: Uint8Array;
  lineId: Uint8Array;
  /** E.164 peer bytes: '+' then 1-9 then digits, 3-16 bytes total. */
  peer: Uint8Array;
  observedMs: bigint;
  /** Strict UTF-8 body text, 1-32768 bytes encoded, no BOM, no NUL. */
  content: string;
  /** 32-byte content key; deterministic test input, never derived here. */
  cek: Uint8Array;
  /** 12-byte body nonce; deterministic test input. */
  nonce: Uint8Array;
  signer: Draft02PrepSigner;
  recipients: readonly Draft02PrepRecipient[];
}>;

export type OutboundEnvelopePrepInput02 = CommonPrepInput & Readonly<{
  kind: 1;
  /** Must satisfy observedMs < expiresMs <= observedMs + 900000. */
  expiresMs: bigint;
}>;

export type InboundEnvelopePrepInput02 = CommonPrepInput & Readonly<{
  kind: 2;
  /** 16 bytes; must equal messageId (reader rule). */
  eventId: Uint8Array;
  /** 1..2^63-1, strictly increasing per device line. */
  localSequence: bigint;
}>;

export type PreparedWrap02 = Readonly<{
  role: number;
  keyId: Uint8Array;
  enc: Uint8Array;
  ct: Uint8Array;
  /** The exact RFC 9180 `info` bound into this wrap's key schedule. */
  info: Uint8Array;
}>;

export type PreparedEnvelope02 = Readonly<{
  envelope: Uint8Array;
  unsigned: Uint8Array;
  unsignedSha256: Uint8Array;
  header: Uint8Array;
  protected: Uint8Array;
  bodyAad: Uint8Array;
  signerKeyId: Uint8Array;
  signature: Uint8Array;
  wraps: readonly PreparedWrap02[];
}>;

function contentBytes(content: string): Uint8Array {
  const bytes = encoder.encode(content);
  if (strictDecoder.decode(bytes) !== content) fail("content is not strict UTF-8");
  if (bytes.length < 1 || bytes.length > maxBodyText) fail("content length");
  if (bytes.includes(0)) fail("content contains NUL");
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) fail("content starts with a BOM");
  return bytes;
}

function peerBytes(peer: Uint8Array): Uint8Array {
  if (peer.length < 3 || peer.length > 16 || peer[0] !== 0x2b || peer[1] < 49 || peer[1] > 57 ||
      !peer.subarray(2).every((byte) => byte >= 48 && byte <= 57)) fail("peer");
  return peer;
}

/** Wire order is strictly increasing (role, keyId); duplicates are rejected like the reader. */
function orderedRecipients(recipients: readonly Draft02PrepRecipient[]): Draft02PrepRecipient[] {
  const ordered = [...recipients].sort((a, b) => a.role - b.role || compare(a.keyId, b.keyId));
  for (let index = 1; index < ordered.length; index++) {
    if (ordered[index].role === ordered[index - 1].role && same(ordered[index].keyId, ordered[index - 1].keyId)) {
      fail("wrap order/duplicate");
    }
  }
  return ordered;
}

async function compose(kind: 1 | 2, input: CommonPrepInput, protectedTail: Uint8Array, signerKeyId: Uint8Array): Promise<PreparedEnvelope02> {
  const message = fixed(input.messageId, 16, "message id");
  const commonProtected = concat(input.manifest.accountId, message, fixed(input.deviceId, 16, "device id"),
    fixed(input.lineId, 16, "line id"), u64(input.manifest.version), input.manifest.digest, signerKeyId, u64(input.observedMs));
  const peer = peerBytes(input.peer);
  const protectedBytes = concat(commonProtected, protectedTail, Uint8Array.of(peer.length), peer);
  const header = concat(encoder.encode("ZTSE"), Uint8Array.of(2, kind, 0, 0), u16(protectedBytes.length));
  const bodyAad = concat(label("ZTSE/body/v2"), header, protectedBytes);
  const text = contentBytes(input.content);
  const cek = fixed(input.cek, 32, "content key");
  const nonce = fixed(input.nonce, 12, "body nonce");
  const bodyKey = await crypto.subtle.importKey("raw", ab(cek), "AES-GCM", false, ["encrypt"]);
  const bodyCt = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ab(nonce), additionalData: ab(bodyAad), tagLength: 128 }, bodyKey, ab(text)));
  const recipients = orderedRecipients(input.recipients);
  const count = recipients.length;
  if (count < (kind === 1 ? 2 : 1) || count > (kind === 1 ? 8 : 7)) fail("wrap count");
  const wraps: PreparedWrap02[] = [];
  const wrapParts: Uint8Array[] = [];
  for (const recipient of recipients) {
    if (!same(recipient.keyId, await keyId(0x0010, recipient.point))) fail("recipient key id");
    const info = concat(label("ZTSE/wrap/v2"), header, protectedBytes, Uint8Array.of(recipient.role), recipient.keyId);
    const sender = await suite.createSenderContext({
      recipientPublicKey: await suite.kem.deserializePublicKey(ab(fixed(recipient.point, 65, "recipient point"))),
      info, ekm: fixed(recipient.ekm, 32, "recipient ekm"),
    });
    const ct = new Uint8Array(await sender.seal(ab(cek), new ArrayBuffer(0)));
    const enc = new Uint8Array(sender.enc);
    if (enc.length !== 65 || ct.length !== 48) fail("wrap size");
    wraps.push({ role: recipient.role, keyId: recipient.keyId, enc, ct, info });
    wrapParts.push(concat(Uint8Array.of(recipient.role), recipient.keyId, enc, ct));
  }
  const unsigned = concat(header, protectedBytes, nonce, u32(bodyCt.length), bodyCt, Uint8Array.of(count), ...wrapParts);
  const transcript = concat(label("ZTSE/sign/v2"), u32(unsigned.length), unsigned);
  const signature = canonicalSignature02(new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, input.signer.privateKey, ab(transcript))));
  const envelope = concat(unsigned, signature);
  const kindMax = kind === 1 ? 34_213 : 34_082;
  if (envelope.length < 426 || envelope.length > 36_864 || envelope.length > kindMax) fail("envelope size");
  const unsignedSha256 = new Uint8Array(await crypto.subtle.digest("SHA-256", ab(unsigned)));
  return { envelope, unsigned, unsignedSha256, header, protected: protectedBytes, bodyAad, signerKeyId, signature, wraps };
}

/** Authorizes first, then composes a kind-1 outbound candidate-02 envelope; never emits unauthorized bytes. */
export async function prepareOutboundEnvelope02(input: OutboundEnvelopePrepInput02): Promise<PreparedEnvelope02> {
  const signerKeyId = await keyId(0x0101, input.signer.publicPoint);
  authorizeOutbound02(input.manifest, {
    accountId: input.manifest.accountId,
    deviceId: input.deviceId,
    lineId: input.lineId,
    manifestDigest: input.manifest.digest,
    keysetVersion: input.manifest.version,
    signerKeyId,
    wraps: input.recipients.map((recipient) => ({ role: recipient.role, keyId: recipient.keyId })),
  }, input.nowMs);
  if (input.observedMs >= input.expiresMs || input.expiresMs - input.observedMs > maxExpiryDelta) fail("intent/expiry");
  return compose(1, input, concat(u64(input.expiresMs), Uint8Array.of(1)), signerKeyId);
}

/** Authorizes first, then composes a kind-2 inbound candidate-02 envelope; never emits unauthorized bytes. */
export async function prepareInboundEnvelope02(input: InboundEnvelopePrepInput02): Promise<PreparedEnvelope02> {
  const signerKeyId = await keyId(0x0101, input.signer.publicPoint);
  authorizeInbound02(input.manifest, {
    kind: 2,
    accountId: input.manifest.accountId,
    deviceId: input.deviceId,
    lineId: input.lineId,
    messageId: input.messageId,
    eventId: input.eventId,
    localSequence: input.localSequence,
    manifestDigest: input.manifest.digest,
    keysetVersion: input.manifest.version,
    signerKeyId,
    wraps: input.recipients.map((recipient) => ({ role: recipient.role, keyId: recipient.keyId })),
  }, input.nowMs);
  if (input.localSequence < 1n || input.localSequence > maxSigned) fail("inbound identity/sequence");
  if (!same(input.messageId, fixed(input.eventId, 16, "event id"))) fail("inbound identity/sequence");
  return compose(2, input, concat(fixed(input.eventId, 16, "event id"), u64(input.localSequence)), signerKeyId);
}
