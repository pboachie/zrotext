/** Exported profile03 outbound crypto composer. No HTTP, durable adapter,
 * backend capability, recipient custody or radio authority is supplied here.
 * Retain exact returned ciphertext for retry; never recompose an unknown effect. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { canonicalP256Signature, isCanonicalP256Signature, keyId } from "./draft01.js";
import { authorizeOutbound03, type VerifiedManifest03 } from "./draft03-manifest.js";
import {
  captureElectionBytes03, captureCurrentElectionAuthority03, electionTime03, requireCurrentElection03,
  type CurrentElectionAuthority03, type VerifiedAcceptedElection03,
} from "./payload-profile-election03.js";

export type OutboundCompositionInput03 = Readonly<{
  manifest: VerifiedManifest03; acceptedElection: VerifiedAcceptedElection03;
  currentAuthority: CurrentElectionAuthority03; nowMs: bigint;
  messageId: Uint8Array; observedMs: bigint; expiresMs: bigint;
  peer: Uint8Array; content: string; signerPrivateKey: CryptoKey; signerPublicPoint: Uint8Array;
  recipients: readonly Readonly<{ role: 1 | 2 | 3; keyId: Uint8Array }>[];
}>;
export type OutboundComposition03 = Readonly<{ envelope: Uint8Array; unsignedDigest: Uint8Array; envelopeDigest: Uint8Array }>;
export type UnsignedOutboundInput03 = Omit<OutboundCompositionInput03, "signerPrivateKey">;
declare const preparedBrand: unique symbol;
/** Component identity, not a one-use signing authorization or durable journal. */
export type PreparedOutboundEnvelope03 = Readonly<{ [preparedBrand]: true }>;
type Prepared = Readonly<{
  unsigned: Uint8Array; transcript: Uint8Array; unsignedDigest: Uint8Array; signerPoint: Uint8Array;
  manifest: VerifiedManifest03; election: VerifiedAcceptedElection03; current: CurrentElectionAuthority03;
  now: bigint; observed: bigint; expires: bigint;
  recipients: readonly Readonly<{ role: 1 | 2 | 3; keyId: Uint8Array }>[];
}>;
const prepared = new WeakMap<PreparedOutboundEnvelope03, Prepared>();
const enc = new TextEncoder(), dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
function fail(why: string): never { throw new Error(`ZTSE composer03: ${why}`); }
function buffer(a: Uint8Array): ArrayBuffer { return Uint8Array.from(a).buffer; }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function integer(value: bigint, bytes: 2 | 4 | 8): Uint8Array {
  const out = new Uint8Array(bytes), view = new DataView(out.buffer);
  if (bytes === 8) { electionTime03(value); view.setBigUint64(0, value, false); }
  else if (bytes === 4) view.setUint32(0, Number(value), false);
  else view.setUint16(0, Number(value), false);
  return out;
}
function draw(length: number): Uint8Array {
  const out = new Uint8Array(length);
  if (typeof globalThis.crypto?.getRandomValues !== "function") fail("CSPRNG unavailable");
  globalThis.crypto.getRandomValues(out); return out;
}
async function sha(a: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(a))); }
const domain = (label: string) => enc.encode(label + "\0");
function closed(input: object, names: readonly string[]): void {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) fail("closed record type");
  const descriptors = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(descriptors);
  if (keys.length !== names.length || keys.some(k => typeof k !== "string" || !names.includes(k))) fail("closed record fields");
  for (const n of names) if (!descriptors[n] || !("value" in descriptors[n])) fail("record accessor");
}
function preparedState(handle: PreparedOutboundEnvelope03): Prepared {
  const p = prepared.get(handle); if (!p) fail("requires prepared unsigned envelope handle"); return p;
}

/** All caller arrays/scalars/key references captured before await; actual byte
 * brands are required. Private verifier snapshots remain the authority source.
 * Independently authenticated current adapter data is an explicit trust input,
 * not a locally minted permission. No deterministic key override is accepted. */
export async function prepareSealedOutboundEnvelope03(input: UnsignedOutboundInput03): Promise<PreparedOutboundEnvelope03> {
  closed(input, ["manifest", "acceptedElection", "currentAuthority", "nowMs", "messageId", "observedMs", "expiresMs", "peer", "content", "signerPublicPoint", "recipients"]);
  const manifest = input.manifest, election = input.acceptedElection;
  const current = captureCurrentElectionAuthority03(input.currentAuthority);
  const now = input.nowMs, observed = input.observedMs, expires = input.expiresMs;
  electionTime03(now); electionTime03(observed); electionTime03(expires);
  const message = captureElectionBytes03(input.messageId, 16), peer = captureElectionBytes03(input.peer, 3, 16);
  const signerPoint = captureElectionBytes03(input.signerPublicPoint, 65);
  const content = input.content;
  if (typeof content !== "string") fail("content type");
  const requested = input.recipients, count = requested?.length;
  if (!Array.isArray(requested) || typeof count !== "number" || !Number.isInteger(count) || count < 2 || count > 8) fail("recipient count");
  const recipients: { role: 1 | 2 | 3; keyId: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    const r = requested[i];
    recipients.push({ role: r.role, keyId: captureElectionBytes03(r.keyId, 32) });
  }
  if (!message.some(v => v !== 0)) fail("zero message id");
  if (peer[0] !== 43 || peer[1] < 49 || peer[1] > 57 || !peer.subarray(2).every(v => v >= 48 && v <= 57)) fail("peer");
  if (observed > now || observed >= expires || now >= expires || expires - observed > 900_000n) fail("intent/expiry");
  const text = enc.encode(content);
  if (text.length < 1 || text.length > 32_768 || dec.decode(text) !== content || text.includes(0)
      || text.length >= 3 && text[0] === 239 && text[1] === 187 && text[2] === 191) fail("strict body text");
  const bound = requireCurrentElection03(election, manifest, current, now);
  const signerId = await keyId(0x0101, signerPoint);
  const authorized = authorizeOutbound03(manifest, {
    accountId: bound.accountId, deviceId: bound.deviceId, lineId: bound.lineId, generation: bound.vaultGeneration,
    version: bound.manifestVersion, digest: bound.manifestDigest, signerKeyId: signerId, wraps: recipients,
  }, now);
  if (!same(signerPoint, authorized.signerPoint)) fail("signer point");
  if (!recipients.some(r => r.role === 1 && same(r.keyId, bound.selectedReaderKeyId))) fail("elected payload reader");
  if (observed < authorized.validFromMs) fail("authority lifetime start");
  if (expires > authorized.expiresMs || expires > bound.permissionExpiresAtMs) fail("authority deadline");
  const ordered = [...authorized.recipients].sort((a, b) => {
    if (a.role !== b.role) return a.role - b.role;
    for (let i = 0; i < 32; i++) if (a.keyId[i] !== b.keyId[i]) return a.keyId[i] - b.keyId[i];
    return 0;
  });
  // Component authorization is complete before randomness, encryption or wrapping.
  const secrets: Uint8Array[] = [];
  try {
    const cek = draw(32); secrets.push(cek);
    const nonce = draw(12); secrets.push(nonce);
    const protectedBytes = concat(bound.accountId, message, bound.deviceId, bound.lineId, integer(bound.manifestVersion, 8),
      bound.manifestDigest, signerId, integer(observed, 8), integer(expires, 8), Uint8Array.of(1, peer.length), peer);
    const header = concat(enc.encode("ZTSE"), Uint8Array.of(3, 1, 0, 0), integer(BigInt(protectedBytes.length), 2));
    const prefix = concat(header, protectedBytes);
    const bodyAad = concat(domain("ZTSE/body/v3"), prefix);
    const bodyKey = await crypto.subtle.importKey("raw", buffer(cek), "AES-GCM", false, ["encrypt"]);
    const body = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: buffer(nonce), additionalData: buffer(bodyAad), tagLength: 128 }, bodyKey, buffer(text)));
    const wraps: Uint8Array[] = [];
    for (const recipient of ordered) {
      const suffix = concat(prefix, Uint8Array.of(recipient.role), recipient.keyId);
      const info = concat(domain("ZTSE/wrap/v3"), suffix), aad = concat(domain("ZTSE/wrap-aad/v3"), suffix);
      const ekm = draw(32); secrets.push(ekm);
      const sender = await suite.createSenderContext({ recipientPublicKey: await suite.kem.deserializePublicKey(buffer(recipient.point)), info: buffer(info), ekm: buffer(ekm) });
      const ct = new Uint8Array(await sender.seal(buffer(cek), buffer(aad))), ephemeral = new Uint8Array(sender.enc);
      if (ephemeral.length !== 65 || ct.length !== 48) fail("wrap width");
      wraps.push(concat(Uint8Array.of(recipient.role), recipient.keyId, ephemeral, ct));
    }
    const unsigned = concat(prefix, nonce, integer(BigInt(body.length), 4), body, Uint8Array.of(wraps.length), ...wraps);
    const transcript = concat(domain("ZTSE/sign/v3"), integer(BigInt(unsigned.length), 4), unsigned);
    if (unsigned.length < 493 || unsigned.length > 34_149) fail("unsigned envelope size");
    const handle = Object.freeze({}) as PreparedOutboundEnvelope03;
    prepared.set(handle, { unsigned, transcript, unsignedDigest: await sha(unsigned), signerPoint,
      manifest, election, current, now, observed, expires, recipients });
    return handle;
  } finally {
    // Best effort only: WebCrypto/HPKE/engine may retain internal copies.
    for (const secret of secrets) secret.fill(0);
    text.fill(0);
  }
}

/** Owned public ciphertext only. Retaining this snapshot does not preserve the
 * private proof across a restart or authorize invoking the signing key. */
export function preparedOutboundEnvelopeSnapshot03(handle: PreparedOutboundEnvelope03): Readonly<{
  unsignedEnvelope: Uint8Array; transcript: Uint8Array; unsignedDigest: Uint8Array; signerPublicPoint: Uint8Array;
}> {
  const p = preparedState(handle);
  return { unsignedEnvelope: p.unsigned.slice(), transcript: p.transcript.slice(),
    unsignedDigest: p.unsignedDigest.slice(), signerPublicPoint: p.signerPoint.slice() };
}

/** Completes the SAME prepared ciphertext using an already produced signature.
 * No signing operation, CSPRNG draw, encryption or implicit retry occurs here.
 * The adapter must burn and durably retain the exact unsigned packet BEFORE
 * invoking the actual retained key; this local handle does not enforce that. */
export async function completeSealedOutboundEnvelope03(input: Readonly<{
  prepared: PreparedOutboundEnvelope03; signature: Uint8Array; nowMs: bigint;
}>): Promise<OutboundComposition03> {
  closed(input, ["prepared", "signature", "nowMs"]);
  const p = preparedState(input.prepared), signature = captureElectionBytes03(input.signature, 64), now = input.nowMs;
  electionTime03(now);
  if (now < p.now || now >= p.expires) fail("prepared comparison/deadline");
  const bound = requireCurrentElection03(p.election, p.manifest, p.current, now);
  const selected = authorizeOutbound03(p.manifest, {
    accountId: bound.accountId, deviceId: bound.deviceId, lineId: bound.lineId, generation: bound.vaultGeneration,
    version: bound.manifestVersion, digest: bound.manifestDigest, signerKeyId: await keyId(0x0101, p.signerPoint), wraps: p.recipients,
  }, now);
  if (p.observed < selected.validFromMs || p.expires > selected.expiresMs || p.expires > bound.permissionExpiresAtMs
      || !same(selected.signerPoint, p.signerPoint)) fail("prepared authority lifetime");
  if (!isCanonicalP256Signature(signature)) fail("canonical low-S raw64 signature");
  const key = await crypto.subtle.importKey("raw", buffer(p.signerPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buffer(signature), buffer(p.transcript))) fail("private/public signer mismatch");
  const envelope = concat(p.unsigned, signature);
  return { envelope, unsignedDigest: p.unsignedDigest.slice(), envelopeDigest: await sha(envelope) };
}

/** Original convenience API, preserving its envelope/profile/domain contract.
 * Maintained one-use adapters must use prepare/snapshot/complete instead so they
 * can journal the exact unsigned ciphertext before their signing invocation. */
export async function composeSealedOutboundEnvelope03(input: OutboundCompositionInput03): Promise<OutboundComposition03> {
  if (input === null || typeof input !== "object" || "deterministicKeyMaterial" in input) fail("production input/key material");
  const privateKey = input.signerPrivateKey, now = input.nowMs;
  if (privateKey?.type !== "private" || !privateKey.usages.includes("sign") || privateKey.algorithm.name !== "ECDSA"
      || (privateKey.algorithm as EcKeyAlgorithm).namedCurve !== "P-256") fail("signing key");
  const handle = await prepareSealedOutboundEnvelope03({ manifest: input.manifest, acceptedElection: input.acceptedElection,
    currentAuthority: input.currentAuthority, nowMs: now, messageId: input.messageId, observedMs: input.observedMs, expiresMs: input.expiresMs,
    peer: input.peer, content: input.content, signerPublicPoint: input.signerPublicPoint, recipients: input.recipients });
  const signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    privateKey, buffer(preparedState(handle).transcript))));
  return completeSealedOutboundEnvelope03({ prepared: handle, signature, nowMs: now });
}
