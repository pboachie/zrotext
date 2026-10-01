/** Candidate-only encrypted bundle verification. No networking, repinning,
 * decryption, persistence, private key import or dispatch permission. */
import { canonicalSignature02, enrollRootPin02, type ManifestTrust02 } from "./draft02-manifest.js";

type PublishedBundle = Readonly<{
  rootPin: Uint8Array; encryptedBackup: Uint8Array; publicCard: Uint8Array;
  unsignedEnrollment: Uint8Array; custodySignature: Uint8Array;
}>;
export type ComparedRootBundle = Readonly<{
  trust: ManifestTrust02; rootPin: Uint8Array; encryptedBackup: Uint8Array; publicCard: Uint8Array;
}>;
const enc = new TextEncoder();
function fail(): never { throw new Error("ZTSE root custody: invalid bundle or independent identity"); }
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function nonzero(a: Uint8Array): boolean { return a.some((x) => x !== 0); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}
function buffer(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
async function digest(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(bytes)));
}

/** intendedPin, comparedFingerprint and origin must originate independently of
 * the received directory/export. A valid result is public custody integrity,
 * not backup AEAD authentication, fresh authority or a historical key restore.
 * All mutable inputs are captured before the first asynchronous operation. */
export async function verifyPublishedRootBundle(
  intendedPin: Uint8Array, independentlyComparedFingerprint: Uint8Array,
  intendedOrigin: string, published: PublishedBundle,
): Promise<ComparedRootBundle> {
  if (intendedPin.length !== 94 || independentlyComparedFingerprint.length !== 32
      || published.rootPin.length !== 94 || published.encryptedBackup.length > 748
      || published.publicCard.length > 645 || published.unsignedEnrollment.length > 663
      || published.custodySignature.length !== 64) fail();
  const pin = Uint8Array.from(intendedPin), compared = Uint8Array.from(independentlyComparedFingerprint);
  const receivedPin = Uint8Array.from(published.rootPin), backup = Uint8Array.from(published.encryptedBackup);
  const card = Uint8Array.from(published.publicCard), u = Uint8Array.from(published.unsignedEnrollment);
  const signature = Uint8Array.from(published.custodySignature);
  const origin = intendedOrigin;
  if (!same(pin, receivedPin) || origin.length < 1 || origin.length > 512 || !/^[\x21-\x7e]+$/.test(origin)) fail();
  const url = new URL(origin);
  if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password
      || url.pathname !== "/" || url.search || url.hash) fail();
  const originBytes = enc.encode(origin);
  if (backup.length !== 236 + originBytes.length || card.length !== 133 + originBytes.length
      || u.length !== 151 + originBytes.length) fail();
  if (!same(backup.subarray(0, 6), Uint8Array.of(0x5a, 0x54, 0x52, 0x42, 1, 1))
      || !nonzero(backup.subarray(6, 22)) || !same(backup.subarray(22, 38), pin.subarray(5, 21))
      || new DataView(backup.buffer).getBigUint64(38, false) !== 1n
      || !same(backup.subarray(46, 78), compared)
      || new DataView(backup.buffer).getUint16(78, false) !== originBytes.length
      || !same(backup.subarray(80, 80 + originBytes.length), originBytes)
      || new DataView(backup.buffer).getUint32(184 + originBytes.length, false) !== 48) fail();
  if (!same(card.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x52, 0x43, 1))
      || new DataView(card.buffer).getUint16(5, false) !== originBytes.length
      || !same(card.subarray(7, 7 + originBytes.length), originBytes)
      || !same(card.subarray(7 + originBytes.length, 101 + originBytes.length), pin)) fail();
  if (!same(u.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x52, 0x45, 1))
      || !same(u.subarray(5, 21), pin.subarray(5, 21)) || !same(u.subarray(101, 133), compared)
      || new DataView(u.buffer).getUint16(149, false) !== originBytes.length
      || !same(u.subarray(151), originBytes)) fail();
  for (const offset of [5, 21, 37, 53]) if (!nonzero(u.subarray(offset, offset + 16))) fail();
  const issued = new DataView(u.buffer).getBigUint64(133, false);
  const expires = new DataView(u.buffer).getBigUint64(141, false);
  if (issued < 1n || expires > (1n << 63n) - 1n || expires <= issued || expires - issued > 300_000n) fail();
  if (!same(signature, canonicalSignature02(signature))) fail();
  const trust = await enrollRootPin02(pin, compared);
  const backupDigest = await digest(backup), cardDigest = await digest(card);
  if (!same(card.subarray(101 + originBytes.length), backupDigest)) fail();
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, u.length, false);
  const statement = concat(enc.encode("ZTSE/root-custody/v1\0"), length, u, backupDigest, cardDigest, compared);
  const key = await crypto.subtle.importKey("raw", buffer(trust.rootPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buffer(signature), buffer(statement))) fail();
  return { trust, rootPin: pin, encryptedBackup: backup, publicCard: card };
}
