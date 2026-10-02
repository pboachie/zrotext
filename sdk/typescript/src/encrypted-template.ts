// SPDX-License-Identifier: AGPL-3.0-only
/** Proposed ZTWT01 client-only ciphertext. Dedicated template-domain client encryption; no networking or dispatch authorization. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { authorizeWorkflowContext02, type Manifest02 } from "./draft02-manifest.js";
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const enc = new TextEncoder(), domain = enc.encode("ZT/workflow-template/hpke/v1\0");
const AAD_LENGTH = 222, HEADER_LENGTH = 291, MAX_CONTENT = 32768, MAX_SIGNED = (1n << 63n) - 1n;
export type EncryptedTemplateScope = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  intervalId: Uint8Array; templateId: Uint8Array; bindingGeneration: bigint; revision: bigint;
  expiresMs: bigint; trustGeneration: bigint; manifestVersion: bigint;
  peerDigest: Uint8Array; readerId: Uint8Array; manifestDigest: Uint8Array;
}>;
function fail(): never { throw new Error("encrypted template: invalid ciphertext or current scope"); }
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
export function encryptedTemplateAad(scope: EncryptedTemplateScope): Uint8Array {
  if (scope.revision > 128n) fail();
  return concat(enc.encode("ZTWT"), Uint8Array.of(1, 1),
    ...[scope.accountId, scope.deviceId, scope.lineId, scope.intervalId, scope.templateId].map((b) => fixed(b, 16)),
    ...[scope.bindingGeneration, scope.revision, scope.expiresMs, scope.trustGeneration, scope.manifestVersion].map(number),
    ...[scope.peerDigest, scope.readerId, scope.manifestDigest].map((b) => fixed(b, 32)));
}
function authorize(manifest: Manifest02, aad: Uint8Array, nowMs: bigint): Uint8Array {
  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
  const expiry = view.getBigUint64(102, false);
  if (nowMs < 1n || expiry <= nowMs || expiry - nowMs > 30n * 86400000n) fail();
  return authorizeWorkflowContext02(manifest, {accountId: aad.slice(6, 22), deviceId: aad.slice(22, 38),
    lineId: aad.slice(38, 54), readerId: aad.slice(158, 190), generation: view.getBigUint64(110, false),
    version: view.getBigUint64(118, false), digest: aad.slice(190, 222)}, nowMs);
}
/** Uses a fresh library-generated HPKE encapsulation for each revision. */
export async function sealEncryptedTemplateBytes(manifest: Manifest02, scope: EncryptedTemplateScope, nowMs: bigint, plaintext: Uint8Array): Promise<Uint8Array> {
  return sealContext(manifest, scope, nowMs, plaintext);
}
async function sealContext(manifest: Manifest02, scope: EncryptedTemplateScope, nowMs: bigint, plaintext: Uint8Array): Promise<Uint8Array> {
  if (plaintext.length < 1 || plaintext.length > MAX_CONTENT) fail();
  const aad = encryptedTemplateAad(scope), content = Uint8Array.from(plaintext);
  const point = authorize(manifest, aad, nowMs);
  const sender = await suite.createSenderContext({recipientPublicKey: await suite.kem.deserializePublicKey(buffer(point)), info: buffer(concat(domain, aad))});
  const ciphertext = new Uint8Array(await sender.seal(buffer(content), buffer(aad)));
  const encapsulation = new Uint8Array(sender.enc);
  if (encapsulation.length !== 65 || ciphertext.length !== content.length + 16) fail();
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, ciphertext.length, false);
  return concat(aad, encapsulation, length, ciphertext);
}
/** The private key remains entirely in the selected customer client. */
export async function openEncryptedTemplateBytes(manifest: Manifest02, expected: EncryptedTemplateScope, nowMs: bigint, privateKey: CryptoKey, envelope: Uint8Array): Promise<Uint8Array> {
  return openContext(manifest, expected, nowMs, privateKey, envelope);
}
async function openContext(manifest: Manifest02, expected: EncryptedTemplateScope, nowMs: bigint, privateKey: CryptoKey, envelope: Uint8Array): Promise<Uint8Array> {
  if (envelope.length < HEADER_LENGTH + 17 || envelope.length > HEADER_LENGTH + MAX_CONTENT + 16) fail();
  const bytes = Uint8Array.from(envelope), aad = encryptedTemplateAad(expected);
  if (!aad.every((v, i) => bytes[i] === v)) fail();
  authorize(manifest, aad, nowMs);
  if (new DataView(bytes.buffer).getUint32(HEADER_LENGTH - 4, false) !== bytes.length - HEADER_LENGTH) fail();
  const recipient = await suite.createRecipientContext({recipientKey: privateKey, enc: buffer(bytes.slice(AAD_LENGTH, AAD_LENGTH + 65)), info: buffer(concat(domain, aad))});
  return new Uint8Array(await recipient.open(buffer(bytes.slice(HEADER_LENGTH)), buffer(aad)));
}

import {canonicalTemplateBytes,validateTemplate,validateValues,templateLimits} from "./template-contract.js";
import {estimateSegments,type SegmentEstimate} from "./sms-segments.js";
export type TemplateContent = Readonly<{template:string;values:Readonly<Record<string,string>>}>;
/** This digest describes encrypted transport bytes only. Plaintext fingerprints
 * remain inside the selected customer client, never relay metadata. */
export async function encryptedTemplateDigest(envelope:Uint8Array):Promise<Uint8Array>{
    if(envelope.length<HEADER_LENGTH+17 || envelope.length>HEADER_LENGTH+MAX_CONTENT+16)fail();
    return new Uint8Array(await crypto.subtle.digest("SHA-256",buffer(envelope)));
}
/** Bounded canonical content is encrypted before any persistence adapter sees it. */
export async function sealEncryptedTemplate(manifest:Manifest02,scope:EncryptedTemplateScope,nowMs:bigint,content:TemplateContent):Promise<Uint8Array>{
    return sealEncryptedTemplateBytes(manifest,scope,nowMs,canonicalTemplateBytes(content.template,content.values));
}
export async function openEncryptedTemplate(manifest:Manifest02,scope:EncryptedTemplateScope,nowMs:bigint,privateKey:CryptoKey,envelope:Uint8Array):Promise<TemplateContent>{
    const plain=await openEncryptedTemplateBytes(manifest,scope,nowMs,privateKey,envelope);
    const value=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(plain));
    if(!value || Array.isArray(value) || Object.keys(value).sort().join()!=="template,v,values" || value.v!==1)fail();
    validateTemplate(value.template);validateValues(value.values);
    const template:string=value.template,values:Record<string,string>=value.values;
    const canonical=canonicalTemplateBytes(template,values);
    if(canonical.length!==plain.length || !canonical.every((v,i)=>v===plain[i]))fail();
    return Object.freeze({template,values:Object.freeze(values)});
}
/** Local preview has no save/send/approval effects. The actual selected Android
 * subscription must still divideMessage and check device bounds before dispatch. */
export function previewEncryptedTemplate(content:TemplateContent):Readonly<{text:string;estimate:SegmentEstimate}>{
    validateTemplate(content.template);validateValues(content.values);
    let text="",offset=0;
    for(const match of content.template.matchAll(/\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}/g)) {
        if(!Object.hasOwn(content.values,match[1]))throw new Error("A template variable has no value.");
        const piece=content.template.slice(offset,match.index)+content.values[match[1]];
        if(text.length+piece.length>templateLimits.output)throw new Error("Template output exceeds the allowed limit.");
        text+=piece;offset=match.index+match[0].length;
    }
    const tail=content.template.slice(offset);
    if(text.length+tail.length>templateLimits.output)throw new Error("Template output exceeds the allowed limit.");
    text+=tail;
    return Object.freeze({text,estimate:estimateSegments(text)});
}
