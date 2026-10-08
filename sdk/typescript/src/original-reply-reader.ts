// SPDX-License-Identifier: AGPL-3.0-only
/** Customer-local original phone event reader. This is not an archive-key delegation. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { decodeBodyText, keyId } from "./draft01.js";
import { parseConversationInbound02 } from "./conversation-reader.js";
import { authorizeInbound02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02 } from "./draft02-manifest.js";
import { acceptedOriginalReplySelection, type OriginalReplySelection } from "./original-reply-selection.js";

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const encoder = new TextEncoder();
const copy = (bytes: Uint8Array): Uint8Array => Uint8Array.from(bytes);
const ab = (bytes: Uint8Array): ArrayBuffer => Uint8Array.from(bytes).buffer;
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);
function join(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0; for (const part of parts) { out.set(part, at); at += part.length; } return out;
}
const label = (value: string): Uint8Array => encoder.encode(`${value}\0`);
function refuse(): never { throw Error("Original reply unavailable"); }

/** Exact independently selected capability identity; a response cannot select these fields. */
export type OriginalReplyScope = Readonly<{
  account: Uint8Array; device: Uint8Array; line: Uint8Array; interval: Uint8Array;
  connector: Uint8Array; readGrant: Uint8Array; reader: Uint8Array; peer: string;
}>;
/** Produced by the dedicated authenticated grant client, never from event metadata alone. */
export type OriginalReplyAuthority = OriginalReplyScope & Readonly<{
  revision: string; expiresMs: bigint; nowMs: bigint; manifest: Manifest02;
}>;
export type OriginalReplyRead = Readonly<{
  scope: OriginalReplyScope; event: Uint8Array; privateKey: CryptoKey;
  /** The exact locally accepted verifier object, not a server-asserted historical snapshot. */
  historical: Manifest02;
  /** Exact verifier result for the phone-approved and installed selected reader set. */
  selection: OriginalReplySelection;
  readCurrent: () => Promise<OriginalReplyAuthority>;
}>;
function snapshot(scope: OriginalReplyScope): OriginalReplyScope {
  return { ...scope, account: copy(scope.account), device: copy(scope.device), line: copy(scope.line),
    interval: copy(scope.interval), connector: copy(scope.connector), readGrant: copy(scope.readGrant), reader: copy(scope.reader) };
}
function matches(a: OriginalReplyScope, b: OriginalReplyScope): boolean {
  return a.peer === b.peer && ["account", "device", "line", "interval", "connector", "readGrant", "reader"].every(
    field => same(a[field as keyof Omit<OriginalReplyScope, "peer">], b[field as keyof Omit<OriginalReplyScope, "peer">]));
}
function validateScope(scope: OriginalReplyScope): void {
  for (const field of [scope.account, scope.device, scope.line, scope.interval, scope.connector, scope.readGrant]) {
    if (field.length !== 16 || !field.some(v => v !== 0)) refuse();
  }
  if (scope.reader.length !== 32 || !scope.reader.some(v => v !== 0) || !/^\+[1-9][0-9]{1,14}$/.test(scope.peer)) refuse();
}

/** Opens only an actual signed original profile-02 role-3 wrap under fresh independent authority.
 * The callback must validate its grant/interval/phone-approved selection on the service. It is not
 * a boolean supplied by an event producer. No plaintext is returned before the final current check.
 */
export async function openOriginalReply02(input: Uint8Array, options: OriginalReplyRead): Promise<string> {
  const scope = snapshot(options.scope), event = copy(options.event), privateKey = options.privateKey;
  const historicalInput = options.historical, readCurrent = options.readCurrent;
  const selection = acceptedOriginalReplySelection(options.selection);
  validateScope(scope);
  if (!same(selection.account, scope.account) || !same(selection.device, scope.device) || !same(selection.line, scope.line) ||
      !same(selection.interval, scope.interval) || selection.peer !== scope.peer ||
      !selection.readers.some(r => same(r.connector, scope.connector) && same(r.readGrant, scope.readGrant) && same(r.reader, scope.reader))) refuse();
  if (event.length !== 16 || !event.some(v => v !== 0) || privateKey.extractable || privateKey.type !== "private" || privateKey.algorithm.name !== "ECDH") refuse();
  const parsed = parseConversationInbound02(input);
  if (!same(parsed.accountId, scope.account) || !same(parsed.deviceId, scope.device) || !same(parsed.lineId, scope.line) ||
      !same(parsed.eventId!, event) || parsed.peer !== scope.peer || parsed.observedMs <= 0n) refuse();
  const initialResponse = await readCurrent();
  const initial = { ...initialResponse, ...snapshot(initialResponse) };
  if (!matches(scope, initial) || !initial.revision || initial.revision.length > 128 || initial.nowMs >= initial.expiresMs || parsed.observedMs > initial.nowMs) refuse();
  const identity = verifiedManifestIdentity02(initial.manifest, initial.nowMs);
  const current = await verifyManifest02(copy(initial.manifest.bytes), verifiedManifestTrust02(initial.manifest, initial.nowMs), initial.nowMs);
  const historical = await verifyManifest02(copy(historicalInput.bytes), verifiedManifestTrust02(historicalInput, parsed.observedMs), parsed.observedMs);
  const old = verifiedManifestIdentity02(historical, parsed.observedMs);
  if (!same(identity.accountId, scope.account) || !same(old.accountId, scope.account) || identity.generation !== old.generation ||
      !same(identity.rootPoint, old.rootPoint) || old.version > identity.version || old.version < selection.activationVersion || identity.generation !== selection.rootGeneration) refuse();
  const expected = [{ role: 2, keyId: selection.archiveReader }, ...selection.readers.map(r => ({ role: 3, keyId: r.reader }))];
  if (parsed.wraps.length !== expected.length || !expected.every(e => parsed.wraps.some(w => w.role === e.role && same(w.keyId, e.keyId)))) refuse();
  const reader = current.keys.find(k => k.role === 3 && same(k.keyId, scope.reader));
  if (!reader || reader.state !== 1 || !(reader.scope & 8) || reader.fromMs > initial.nowMs || initial.nowMs >= reader.untilMs) refuse();
  authorizeInbound02(historical, { kind: 2, accountId: parsed.accountId, deviceId: parsed.deviceId, lineId: parsed.lineId,
    messageId: parsed.messageId, eventId: parsed.eventId!, localSequence: parsed.localSequence!, manifestDigest: parsed.manifestDigest,
    keysetVersion: parsed.keysetVersion, signerKeyId: parsed.signerKeyId, wraps: parsed.wraps }, parsed.observedMs);
  const signer = historical.keys.find(k => k.role === 4 && same(k.keyId, parsed.signerKeyId));
  if (!signer || !same(await keyId(0x0101, signer.point), parsed.signerKeyId)) refuse();
  const signingKey = await crypto.subtle.importKey("raw", ab(signer.point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, parsed.unsigned.length);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, signingKey, ab(parsed.signature), ab(join(label("ZTSE/sign/v2"), length, parsed.unsigned)))) refuse();
  // ⚡ Bolt: Parallelize key deserialization for faster reply opening
  await Promise.all(parsed.wraps.map((wrap) => suite.kem.deserializePublicKey(ab(wrap.enc))));
  const wrap = parsed.wraps.find(w => w.role === 3 && same(w.keyId, scope.reader));
  if (!wrap) refuse();
  const publicKey = await crypto.subtle.importKey("raw", ab(reader.point), { name: "ECDH", namedCurve: "P-256" }, true, []);
  const recipient = await suite.createRecipientContext({ recipientKey: { privateKey, publicKey }, enc: ab(wrap.enc),
    info: ab(join(label("ZTSE/wrap/v2"), parsed.bytes.subarray(0, 10), parsed.protected, Uint8Array.of(3), wrap.keyId)) });
  let cek: Uint8Array | undefined, body: Uint8Array | undefined;
  try {
    cek = new Uint8Array(await recipient.open(ab(wrap.ct), new ArrayBuffer(0)));
    if (cek.length !== 32) refuse();
    const bodyKey = await crypto.subtle.importKey("raw", ab(cek), "AES-GCM", false, ["decrypt"]);
    body = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: ab(parsed.nonce), tagLength: 128,
      additionalData: ab(join(label("ZTSE/body/v2"), parsed.bytes.subarray(0, 10), parsed.protected)) }, bodyKey, ab(parsed.bodyCt)));
    const final = await readCurrent();
    if (!matches(scope, final) || final.revision !== initial.revision || final.nowMs < initial.nowMs || final.nowMs >= initial.expiresMs || final.nowMs >= final.expiresMs) refuse();
    const finalIdentity = verifiedManifestIdentity02(final.manifest, final.nowMs);
    if (finalIdentity.generation !== identity.generation || finalIdentity.version !== identity.version || !same(finalIdentity.digest, identity.digest)) refuse();
    if (final.nowMs >= reader.untilMs) refuse();
    return decodeBodyText(body);
  } finally { cek?.fill(0); body?.fill(0); }
}
