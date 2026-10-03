/** Proposed ZTWC01 client-only ciphertext. No networking, key generation for
 * customers, persistence or dispatch authorization. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { authorizeWorkflowContext02, authorizeIntegrationWorkflowContext02, type Manifest02 } from "./draft02-manifest.js";
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const enc = new TextEncoder(), domain = enc.encode("ZT/workflow-context/hpke/v1\0");
const AAD_LENGTH = 222, HEADER_LENGTH = 291, MAX_CONTENT = 32768, MAX_SIGNED = (1n << 63n) - 1n;
export type WorkflowContextScope = Readonly<{
  kind: 1 | 2 | 3; accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  intervalId: Uint8Array; contextId: Uint8Array; bindingGeneration: bigint; revision: bigint;
  expiresMs: bigint; trustGeneration: bigint; manifestVersion: bigint;
  peerDigest: Uint8Array; readerId: Uint8Array; manifestDigest: Uint8Array;
}>;
function fail(): never { throw new Error("workflow context: invalid ciphertext or current scope"); }
function buffer(b: Uint8Array): ArrayBuffer { return Uint8Array.from(b).buffer; }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, b) => n + b.length, 0));
  let offset = 0; for (const b of parts) { out.set(b, offset); offset += b.length; } return out;
}
function fixed(b: Uint8Array, length: number): Uint8Array {
  if (b.length !== length || !b.some((v) => v !== 0)) fail(); return Uint8Array.from(b);
}
function number(n: bigint): Uint8Array {
  if (typeof n !== "bigint" || n < 1n || n > MAX_SIGNED) fail();
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, false); return b;
}
/** Captures all caller-held bytes before any asynchronous operation. */
export function workflowContextAad(scope: WorkflowContextScope): Uint8Array {
  if (![1, 2, 3].includes(scope.kind) || scope.revision > 128n) fail();
  return concat(enc.encode("ZTWC"), Uint8Array.of(1, scope.kind),
    ...[scope.accountId, scope.deviceId, scope.lineId, scope.intervalId, scope.contextId].map((b) => fixed(b, 16)),
    ...[scope.bindingGeneration, scope.revision, scope.expiresMs, scope.trustGeneration, scope.manifestVersion].map(number),
    ...[scope.peerDigest, scope.readerId, scope.manifestDigest].map((b) => fixed(b, 32)));
}
function authorize(manifest: Manifest02, aad: Uint8Array, nowMs: bigint, role: 2 | 3): Uint8Array {
  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
  const expiry = view.getBigUint64(102, false);
  if (nowMs < 1n || expiry <= nowMs || expiry - nowMs > 30n * 86400000n) fail();
  const verify = role === 2 ? authorizeWorkflowContext02 : authorizeIntegrationWorkflowContext02;
  return verify(manifest, {accountId: aad.slice(6, 22), deviceId: aad.slice(22, 38),
    lineId: aad.slice(38, 54), readerId: aad.slice(158, 190), generation: view.getBigUint64(110, false),
    version: view.getBigUint64(118, false), digest: aad.slice(190, 222)}, nowMs);
}
/** Uses a fresh library-generated HPKE encapsulation for each revision. */
export async function sealWorkflowContext(manifest: Manifest02, scope: WorkflowContextScope, nowMs: bigint, plaintext: Uint8Array): Promise<Uint8Array> {
  return sealContext(manifest, scope, nowMs, plaintext, 2);
}
/** Owner-declared separate representation for an explicitly selected role-3
 * reader. This cryptographic operation does not issue a runtime grant. */
export async function sealIntegrationWorkflowContext(manifest: Manifest02, scope: WorkflowContextScope, nowMs: bigint, plaintext: Uint8Array): Promise<Uint8Array> {
  return sealContext(manifest, scope, nowMs, plaintext, 3);
}
async function sealContext(manifest: Manifest02, scope: WorkflowContextScope, nowMs: bigint, plaintext: Uint8Array, role: 2 | 3): Promise<Uint8Array> {
  if (plaintext.length < 1 || plaintext.length > MAX_CONTENT) fail();
  const aad = workflowContextAad(scope), content = Uint8Array.from(plaintext);
  try {
  const point = authorize(manifest, aad, nowMs, role);
  const sender = await suite.createSenderContext({recipientPublicKey: await suite.kem.deserializePublicKey(buffer(point)), info: buffer(concat(domain, aad))});
  const ciphertext = new Uint8Array(await sender.seal(buffer(content), buffer(aad)));
  const encapsulation = new Uint8Array(sender.enc);
  if (encapsulation.length !== 65 || ciphertext.length !== content.length + 16) fail();
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, ciphertext.length, false);
  return concat(aad, encapsulation, length, ciphertext);
  } finally {
    // Best effort for this owned copy; JS/WebCrypto may retain internal copies.
    content.fill(0);
  }
}
/** The private key remains entirely in the selected customer client. */
export async function openWorkflowContext(manifest: Manifest02, expected: WorkflowContextScope, nowMs: bigint, privateKey: CryptoKey, envelope: Uint8Array): Promise<Uint8Array> {
  return openContext(manifest, expected, nowMs, privateKey, envelope, 2);
}
export async function openIntegrationWorkflowContext(manifest: Manifest02, expected: WorkflowContextScope, nowMs: bigint, privateKey: CryptoKey, envelope: Uint8Array): Promise<Uint8Array> {
  return openContext(manifest, expected, nowMs, privateKey, envelope, 3);
}
async function openContext(manifest: Manifest02, expected: WorkflowContextScope, nowMs: bigint, privateKey: CryptoKey, envelope: Uint8Array, role: 2 | 3): Promise<Uint8Array> {
  if (envelope.length < HEADER_LENGTH + 17 || envelope.length > HEADER_LENGTH + MAX_CONTENT + 16) fail();
  const bytes = Uint8Array.from(envelope), aad = workflowContextAad(expected);
  if (!aad.every((v, i) => bytes[i] === v)) fail();
  authorize(manifest, aad, nowMs, role);
  if (new DataView(bytes.buffer).getUint32(HEADER_LENGTH - 4, false) !== bytes.length - HEADER_LENGTH) fail();
  const recipient = await suite.createRecipientContext({recipientKey: privateKey, enc: buffer(bytes.slice(AAD_LENGTH, AAD_LENGTH + 65)), info: buffer(concat(domain, aad))});
  return new Uint8Array(await recipient.open(buffer(bytes.slice(HEADER_LENGTH)), buffer(aad)));
}
