// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Production-shaped sealed outbound envelope composition (issue #537 slice A).
 *
 * `composeSealedOutboundEnvelope` composes one complete kind-01 profile-02
 * candidate envelope from explicit caller inputs and returns the exact bytes
 * together with the SHA-256 digest of the unsigned envelope — the Q6
 * idempotency identity a caller must reuse on retry. The wire layout, bounds
 * and rules mirror the dormant Rust parser (crates/server/src/sealed_envelope
 * and sealed_body) and the reviewed draft-02 helpers: composition is delegated
 * to `prepareOutboundEnvelope02` after this module's own fail-closed
 * validation, so the bytes are exactly the ones the cross-client lane feeds to
 * the Rust verifier. Authorization is never re-implemented: the exact manifest
 * object returned by `verifyManifest02` must authorize the request.
 *
 * The content key, body nonce and every HPKE ephemeral IKM are drawn fresh
 * from `crypto.getRandomValues` unless the caller explicitly supplies
 * `deterministicKeyMaterial`, which exists only to reproduce cross-client
 * vectors; production callers must omit it, because two compositions of the
 * same message under fresh material are two different Q6 identities by
 * design. Local key-material copies are zeroed on every exit path, but
 * JavaScript gives no erasure guarantee: the engine may have copied the
 * buffers, and the delegated helper holds its own snapshot until the
 * composition promise settles. The returned object carries only ciphertext
 * bytes and the digest — never body plaintext or key material.
 *
 * This module has no network client, no send path and no server dependency;
 * slice B adds the HTTP client. The server route stays disabled by default,
 * and composing an envelope is never carrier submission.
 */
import { keyId } from "./draft01.js";
import type { Manifest02 } from "./draft02-manifest.js";
import { prepareOutboundEnvelope02 } from "./draft02-envelope-prep.js";

export const SEALED_CONTENT_TYPE = "application/vnd.zrotext.sealed.v1";

/** Refusal codes mirroring the server parser's own failure strings. */
export type SealedEnvelopeErrorCode =
  | "identity"
  | "peer"
  | "time_range"
  | "intent_expiry"
  | "content"
  | "wrap_count"
  | "recipient"
  | "recipient_key_id"
  | "signer"
  | "key_material"
  | "envelope_size"
  | "authorization"
  | "composition";

export class SealedEnvelopeError extends Error {
  readonly code: SealedEnvelopeErrorCode;

  constructor(code: SealedEnvelopeErrorCode, detail: string, options?: Readonly<{ cause?: unknown }>) {
    super(`ZTSE sealed envelope: ${detail}`, options);
    this.name = "SealedEnvelopeError";
    this.code = code;
  }
}

export function isSealedEnvelopeError(value: unknown): value is SealedEnvelopeError {
  return value instanceof SealedEnvelopeError;
}

/** One manifest-authorized recipient wrap: the (role, keyId) plus the exact KEM point it names. */
export type SealedOutboundRecipient = Readonly<{
  role: 1 | 2 | 3;
  /** Must equal SHA-256("ZTSE/key/v1\0" || 0x0010 || point) and appear in the verified manifest. */
  keyId: Uint8Array;
  /** 65-byte uncompressed P-256 KEM recipient point. */
  point: Uint8Array;
}>;

/** The manifest-authorized origin signer (role 5). */
export type SealedOutboundSigner = Readonly<{
  privateKey: CryptoKey;
  /** 65-byte uncompressed P-256 point whose 0x0101 key ID the manifest must authorize. */
  publicPoint: Uint8Array;
}>;

/**
 * Reproducibility override for cross-client vectors only. `ekms[i]` is the
 * HPKE ephemeral IKM for `recipients[i]` as passed, in any order; the module
 * wire-sorts recipients itself. Production callers must omit this field.
 */
export type SealedDeterministicKeyMaterial = Readonly<{
  /** 32-byte content key. */
  cek: Uint8Array;
  /** 12-byte body nonce. */
  nonce: Uint8Array;
  /** One 32-byte IKM per recipient. */
  ekms: readonly Uint8Array[];
}>;

export type SealedOutboundCompositionInput = Readonly<{
  /** The exact object returned by `verifyManifest02`; copies are rejected fail-closed. */
  manifest: Manifest02;
  nowMs: bigint;
  messageId: Uint8Array;
  deviceId: Uint8Array;
  lineId: Uint8Array;
  /** E.164 peer bytes: '+' then 1-9 then digits, 3-16 bytes total. */
  peer: Uint8Array;
  observedMs: bigint;
  /** Must satisfy observedMs < expiresMs <= observedMs + 900000. */
  expiresMs: bigint;
  /** Strict UTF-8 body text, 1-32768 bytes encoded, no BOM, no NUL. */
  content: string;
  signer: SealedOutboundSigner;
  recipients: readonly SealedOutboundRecipient[];
  deterministicKeyMaterial?: SealedDeterministicKeyMaterial;
}>;

/** Only ciphertext bytes and the Q6 identity; no plaintext, no key material. */
export type SealedOutboundComposition = Readonly<{
  envelope: Uint8Array;
  unsignedDigest: Uint8Array;
}>;

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const maxSigned = (1n << 63n) - 1n;
const maxBodyText = 32_768;
const maxExpiryDelta = 900_000n;
const wrapWidth = 146;
const maxKindTotal = 34_213;

function fail(code: SealedEnvelopeErrorCode, why: string): never {
  throw new SealedEnvelopeError(code, why);
}
function copy(bytes: Uint8Array): Uint8Array { return Uint8Array.from(bytes); }
function draw(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function compare(a: Uint8Array, b: Uint8Array): number {
  for (let index = 0; index < Math.min(a.length, b.length); index++) if (a[index] !== b[index]) return a[index] - b[index];
  return a.length - b.length;
}

type OwnedRecipient = { role: 1 | 2 | 3; keyId: Uint8Array; point: Uint8Array; ekm: Uint8Array };
type OwnedInput = Readonly<{
  manifest: Manifest02; nowMs: bigint; messageId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  peer: Uint8Array; observedMs: bigint; expiresMs: bigint; content: string;
  signerPrivateKey: CryptoKey; signerPoint: Uint8Array; recipients: readonly OwnedRecipient[];
  cek: Uint8Array; nonce: Uint8Array;
}>;

/** Copies every caller-held value and draws or copies key material before any await. */
function snapshot(input: SealedOutboundCompositionInput): OwnedInput {
  const count = input.recipients.length;
  let cek: Uint8Array;
  let nonce: Uint8Array;
  const ekms: Uint8Array[] = [];
  const deterministic = input.deterministicKeyMaterial;
  if (deterministic) {
    cek = copy(deterministic.cek);
    nonce = copy(deterministic.nonce);
    if (cek.length !== 32 || nonce.length !== 12 || deterministic.ekms.length !== count ||
        deterministic.ekms.some((ekm) => ekm.length !== 32)) fail("key_material", "deterministic key material width");
    for (const ekm of deterministic.ekms) ekms.push(copy(ekm));
  } else {
    cek = draw(32);
    nonce = draw(12);
    for (let index = 0; index < count; index++) ekms.push(draw(32));
  }
  return {
    manifest: input.manifest, nowMs: input.nowMs,
    messageId: copy(input.messageId), deviceId: copy(input.deviceId), lineId: copy(input.lineId),
    peer: copy(input.peer), observedMs: input.observedMs, expiresMs: input.expiresMs, content: input.content,
    signerPrivateKey: input.signer.privateKey, signerPoint: copy(input.signer.publicPoint),
    recipients: input.recipients.map((recipient, index) => {
      if (recipient.role !== 1 && recipient.role !== 2 && recipient.role !== 3) fail("recipient", "wrap role");
      return { role: recipient.role, keyId: copy(recipient.keyId), point: copy(recipient.point), ekm: ekms[index] };
    }),
    cek, nonce,
  };
}

/** Synchronous fail-closed validation mirroring the server's parser rules. */
function validate(snap: OwnedInput, contentBytes: Uint8Array): OwnedRecipient[] {
  for (const [bytes, name] of [[snap.messageId, "message id"], [snap.deviceId, "device id"], [snap.lineId, "line id"]] as const) {
    if (bytes.length !== 16) fail("identity", `${name} width`);
  }
  const peer = snap.peer;
  if (peer.length < 3 || peer.length > 16 || peer[0] !== 0x2b || peer[1] < 49 || peer[1] > 57 ||
      !peer.subarray(2).every((byte) => byte >= 48 && byte <= 57)) fail("peer", "peer");
  for (const value of [snap.nowMs, snap.observedMs, snap.expiresMs]) {
    if (value < 0n || value > maxSigned) fail("time_range", "u64 exceeds signed storage range");
  }
  if (snap.observedMs >= snap.expiresMs || snap.expiresMs - snap.observedMs > maxExpiryDelta) fail("intent_expiry", "intent/expiry");
  if (contentBytes.length < 1 || contentBytes.length > maxBodyText) fail("content", "content length");
  if (strictDecoder.decode(contentBytes) !== snap.content) fail("content", "content is not strict UTF-8");
  if (contentBytes.includes(0)) fail("content", "content contains NUL");
  if (contentBytes.length >= 3 && contentBytes[0] === 0xef && contentBytes[1] === 0xbb && contentBytes[2] === 0xbf) {
    fail("content", "content starts with a BOM");
  }
  if (snap.signerPoint.length !== 65 || snap.signerPoint[0] !== 4) fail("signer", "signer point width");
  const count = snap.recipients.length;
  if (count < 2 || count > 8) fail("wrap_count", "wrap count");
  let deviceCount = 0;
  let archiveCount = 0;
  let integrationCount = 0;
  for (const recipient of snap.recipients) {
    if (recipient.point.length !== 65 || recipient.point[0] !== 4) fail("recipient", "recipient point width");
    if (recipient.role === 1) deviceCount++;
    else if (recipient.role === 2) archiveCount++;
    else integrationCount++;
  }
  if (deviceCount !== 1 || archiveCount !== 1 || integrationCount > 6) fail("recipient", "recipient roles");
  const ordered = [...snap.recipients].sort((a, b) => a.role - b.role || compare(a.keyId, b.keyId));
  for (let index = 1; index < ordered.length; index++) {
    if (ordered[index].role === ordered[index - 1].role && same(ordered[index].keyId, ordered[index - 1].keyId)) {
      fail("recipient", "wrap order/duplicate");
    }
  }
  // Parser parity: 426..=34213 bytes for kind 01. Unreachable given the checks
  // above (their maxima sum to exactly 34213) but kept so a future bound
  // change cannot silently admit an oversized envelope.
  const predicted = 10 + (154 + peer.length) + 16 + (contentBytes.length + 16) + 1 + count * wrapWidth + 64;
  if (predicted < 426 || predicted > maxKindTotal) fail("envelope_size", "kind envelope size");
  return ordered;
}

/**
 * Snapshots every caller-held value synchronously, validates fail-closed
 * against the server parser's rules with typed errors, authorizes against
 * the exact verified manifest through the delegated draft-02 helpers, and
 * returns the envelope bytes plus the unsigned SHA-256 digest. Nothing is
 * coerced and nothing partial is returned: the call either composes the
 * complete envelope or refuses.
 */
export async function composeSealedOutboundEnvelope(input: SealedOutboundCompositionInput): Promise<SealedOutboundComposition> {
  const snap = snapshot(input);
  const contentBytes = encoder.encode(snap.content);
  const ordered = validate(snap, contentBytes);
  for (const recipient of snap.recipients) {
    if (!same(recipient.keyId, await keyId(0x0010, recipient.point))) fail("recipient_key_id", "recipient key id");
  }
  try {
    const prepared = await prepareOutboundEnvelope02({
      kind: 1,
      manifest: snap.manifest,
      nowMs: snap.nowMs,
      messageId: snap.messageId,
      deviceId: snap.deviceId,
      lineId: snap.lineId,
      peer: snap.peer,
      observedMs: snap.observedMs,
      expiresMs: snap.expiresMs,
      content: snap.content,
      cek: snap.cek,
      nonce: snap.nonce,
      signer: { privateKey: snap.signerPrivateKey, publicPoint: snap.signerPoint },
      recipients: ordered.map((recipient) => ({ role: recipient.role, keyId: recipient.keyId, point: recipient.point, ekm: recipient.ekm })),
    });
    return { envelope: prepared.envelope, unsignedDigest: prepared.unsignedSha256 };
  } catch (error) {
    if (error instanceof SealedEnvelopeError) throw error;
    const why = error instanceof Error ? error.message : String(error);
    const code: SealedEnvelopeErrorCode =
      /authority|reader set|manifest|stale|just-verified|binding/.test(why) ? "authorization" : "composition";
    throw new SealedEnvelopeError(code, why, { cause: error });
  } finally {
    // Best-effort erasure of this module's key-material copies; see the header.
    snap.cek.fill(0);
    snap.nonce.fill(0);
    for (const recipient of snap.recipients) recipient.ekm.fill(0);
  }
}
