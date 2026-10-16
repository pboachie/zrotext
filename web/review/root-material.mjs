// SPDX-License-Identifier: AGPL-3.0-only
// Public enrollment/ciphertext checks only. No recovery token or private root.
const encoder = new TextEncoder();
const maximum = (1n << 63n) - 1n;
const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
export const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
export function unhex(value, length) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) throw Error('Compare the complete public identity from your retained receipt.');
  return Uint8Array.from(value.match(/../g), (s) => parseInt(s, 16));
}
export function uuid(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) throw Error('Canonical identity required.');
  const bytes = unhex(value.replaceAll('-', ''), 16);
  if (!bytes.some((b) => b !== 0)) throw Error('Nonzero identity required.');
  return bytes;
}
export function decimal(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value)) throw Error('Bounded time or revision required.');
  const result = BigInt(value);
  if (result > maximum) throw Error('Bounded time or revision required.');
  return result;
}
export function closed(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) throw Error('Unexpected review response.');
  return value;
}
export function base64(bytes) {
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw);
}
export function decode(value, limit, exact = false) {
  if (typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw Error('Canonical public encoding required.');
  const raw = atob(value);
  const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
  if (bytes.length > limit || (exact && bytes.length !== limit) || btoa(raw) !== value) throw Error('Canonical public encoding required.');
  return bytes;
}
export function concat(...parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
const number = (bytes, offset) => new DataView(bytes.buffer, bytes.byteOffset + offset, 8).getBigUint64(0);
const hash = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const u32 = (n) => { const bytes = new Uint8Array(4); new DataView(bytes.buffer).setUint32(0, n); return bytes; };
const magic = (bytes, prefix) => same(bytes.subarray(0, prefix.length), Uint8Array.from(prefix));
async function readFile(file, min, max) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < min || file.size > max) throw Error('Retained kit file size refused.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length !== file.size) throw Error('Retained kit file changed while reading.');
  return bytes;
}
export async function readArtifacts(backupFile, cardFile, identity) {
  const origin = encoder.encode(identity.origin);
  const parsedOrigin = new URL(identity.origin);
  if (parsedOrigin.protocol !== 'https:' || parsedOrigin.origin !== identity.origin || origin.length > 512) throw Error('Exact HTTPS review origin required.');
  const account = uuid(identity.account), bundle = uuid(identity.bundle), fingerprint = unhex(identity.fingerprint, 32);
  const backup = await readFile(backupFile, 237, 748), card = await readFile(cardFile, 134, 645);
  if (!magic(backup, [90, 84, 82, 66, 1, 1]) || backup.length !== 236 + origin.length ||
      !same(backup.subarray(6, 22), bundle) || !same(backup.subarray(22, 38), account) || number(backup, 38) !== 1n ||
      !same(backup.subarray(46, 78), fingerprint) || new DataView(backup.buffer).getUint16(78) !== origin.length ||
      !same(backup.subarray(80, 80 + origin.length), origin) || new DataView(backup.buffer).getUint32(184 + origin.length) !== 48) throw Error('Encrypted backup differs from the independently retained identity.');
  if (!magic(card, [90, 84, 82, 67, 1]) || card.length !== 133 + origin.length ||
      new DataView(card.buffer).getUint16(5) !== origin.length || !same(card.subarray(7, 7 + origin.length), origin)) throw Error('Public card origin or framing differs.');
  const pin = card.slice(7 + origin.length, 101 + origin.length);
  if (!magic(pin, [90, 84, 82, 80, 2]) || !same(pin.subarray(5, 21), account) || number(pin, 21) !== 1n || pin[29] !== 4 ||
      !same(await hash(concat(encoder.encode('ZTSE/root-pin/v2\0'), pin)), fingerprint) ||
      !same(await hash(backup), card.subarray(101 + origin.length))) throw Error('Public pin, full fingerprint or encrypted-backup digest differs.');
  const publicKey = await crypto.subtle.importKey('raw', pin.subarray(29), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return { backup, card, pin, fingerprint, publicKey, identity: Object.freeze({ ...identity }) };
}
export function artifactRequest(kit) {
  return { root_pin_b64: base64(kit.pin), independently_compared_fingerprint_b64: base64(kit.fingerprint), encrypted_backup_b64: base64(kit.backup), public_card_b64: base64(kit.card) };
}
export async function inspectChallenge(view, prepared, context, kit) {
  closed(view, ['version', 'request_id', 'preparation_id', 'generation', 'root_challenge_id', 'reauth_challenge_id', 'reauth_nonce_b64', 'unsigned_enrollment_b64', 'custody_statement_b64', 'root_pin_b64', 'request_commitment_b64', 'expires_ms', 'server_now_ms']);
  if (view.version !== 1 || view.request_id !== prepared.request_id || view.preparation_id !== prepared.preparation_id || view.generation !== prepared.generation || !same(decode(view.root_pin_b64, 94, true), kit.pin)) throw Error('Root proposal identity changed.');
  uuid(view.root_challenge_id); uuid(view.reauth_challenge_id); decode(view.reauth_nonce_b64, 32, true); decode(view.request_commitment_b64, 32, true);
  const unsigned = decode(view.unsigned_enrollment_b64, 663);
  if (unsigned.length < 152 || !magic(unsigned, [90, 84, 82, 69, 1])) throw Error('Enrollment framing refused.');
  const origin = encoder.encode(context.origin);
  if (unsigned.length !== 151 + origin.length || new DataView(unsigned.buffer).getUint16(149) !== origin.length ||
      !same(unsigned.subarray(151), origin) || !same(unsigned.subarray(5, 21), uuid(context.account)) ||
      !same(unsigned.subarray(21, 37), uuid(context.owner_user)) || !same(unsigned.subarray(37, 53), uuid(context.review_owner_session)) ||
      !same(unsigned.subarray(53, 69), uuid(view.root_challenge_id)) || !unsigned.subarray(69, 101).some((b) => b !== 0) ||
      !same(unsigned.subarray(101, 133), kit.fingerprint)) throw Error('Enrollment differs from the current review workspace and retained kit.');
  const issued = number(unsigned, 133), expires = number(unsigned, 141), observed = decimal(view.server_now_ms);
  if (issued === 0n || expires > maximum || expires <= issued || expires - issued > 300000n || observed < issued || observed >= expires || expires !== decimal(view.expires_ms)) throw Error('Enrollment time bounds refused.');
  const statement = concat(encoder.encode('ZTSE/root-custody/v1\0'), u32(unsigned.length), unsigned, await hash(kit.backup), await hash(kit.card), kit.fingerprint);
  if (!same(decode(view.custody_statement_b64, 786), statement)) throw Error('Encrypted-custody publication differs from the retained files.');
  return { view: Object.freeze({ ...view }), unsigned, statement, issued, expires };
}
function signature(value) {
  const bytes = unhex(value, 64), r = BigInt('0x' + value.slice(0, 64)), s = BigInt('0x' + value.slice(64));
  if (r <= 0n || r >= order || s <= 0n || s > order / 2n) throw Error('Canonical public signature required.');
  return bytes;
}
export async function verifySignatures(text, challenge, kit) {
  if (typeof text !== 'string' || text.length > 320) throw Error('Paste only the two public signature lines.');
  const match = /^Enrollment signature: ([0-9a-f]{128})\r?\nCustody signature: ([0-9a-f]{128})\r?\n?$/.exec(text);
  if (!match) throw Error('Paste only the two public signature lines.');
  const enrollment = signature(match[1]), custody = signature(match[2]);
  const enrollmentStatement = concat(encoder.encode('ZTSE/root-enroll/v1\0'), u32(challenge.unsigned.length), challenge.unsigned);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kit.publicKey, enrollment, enrollmentStatement) ||
      !await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kit.publicKey, custody, challenge.statement)) throw Error('Public signatures do not approve this exact enrollment and encrypted custody.');
  return { enrollment_signature_b64: base64(enrollment), custody_signature_b64: base64(custody) };
}

export function inspectReceipt(receipt, request, context, kit, challenge) {
  closed(receipt, ['version', 'request_id', 'account', 'actor_owner_user', 'actor_review_owner_session', 'root_challenge_id', 'root_pin_b64', 'root_fingerprint_b64', 'completed_ms', 'server_now_ms']);
  for (const field of ['request_id', 'account', 'actor_owner_user', 'actor_review_owner_session', 'root_challenge_id']) uuid(receipt[field]);
  if (receipt.version !== 1 || receipt.request_id !== request.request_id || receipt.account !== context.account ||
      receipt.actor_owner_user !== context.owner_user || receipt.actor_review_owner_session !== context.review_owner_session ||
      receipt.root_challenge_id !== challenge.view.root_challenge_id || !same(decode(receipt.root_pin_b64, 94, true), kit.pin) ||
      !same(decode(receipt.root_fingerprint_b64, 32, true), kit.fingerprint) || decimal(receipt.completed_ms) < challenge.issued ||
      decimal(receipt.completed_ms) >= challenge.expires || decimal(receipt.completed_ms) > decimal(receipt.server_now_ms)) throw Error('Original root publication is still unconfirmed.');
  return receipt;
}
