// SPDX-License-Identifier: AGPL-3.0-only
// Fresh synthetic fixture custody only. No production credential or radio adapter.
import { webcrypto, randomBytes, randomUUID, createHash } from "node:crypto";
import assert from "node:assert/strict";
import { enrollRootPin02, verifyManifest02, advanceManifestTrust02, authorizeOutbound02, canonicalSignature02 } from "../dist/draft02-manifest.js";
import { prepareOutboundEnvelope02 } from "../dist/draft02-envelope-prep.js";
import { openFixtureWrap } from "./conversation-simulator-wrap.mjs";
globalThis.crypto ??= webcrypto;
const b = (s) => Buffer.from(s, "base64"), encoded = (v) => Buffer.from(v).toString("base64");
const id = (s) => { assert.match(s, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/); return Buffer.from(s.replaceAll("-", ""), "hex"); };
const hash = (v) => createHash("sha256").update(v).digest();
const u64 = (n) => { const v = Buffer.alloc(8); v.writeBigUInt64BE(BigInt(n)); return v; };
const sized = (v) => { const n = Buffer.alloc(4); n.writeUInt32BE(v.length); return Buffer.concat([n, v]); };
const transcript = (proof) => Buffer.concat([Buffer.from("zrotext/conversation/confirm-send/v1\0"), sized(proof)]);
export function encodeFixtureConfirmation(c) {
  const peer=Buffer.from(c.peer,"ascii");
  assert.ok(peer.length>=3 && peer.length<=16 && /^\+[1-9][0-9]{1,14}$/.test(c.peer));
  return Buffer.concat([Buffer.from("ZTCS\x01"),...[c.account,c.device,c.line,c.interval,c.session,c.message].map(id),
    ...[c.generation,c.trustGeneration,c.version,c.expiresMs].map(u64),Buffer.from([peer.length]),peer,
    ...[c.signer,c.reader,c.manifest,c.envelopeDigest,c.bodyDigest].map((v)=>{const bytes=b(v);assert.equal(bytes.length,32);return bytes;})]);
}
const jwk = (point, scalar) => ({ kty: "EC", crv: "P-256", x: point.subarray(1,33).toString("base64url"), y: point.subarray(33).toString("base64url"), d: b(scalar).toString("base64url"), ext: false });
export async function signFixtureConfirmation(ready, confirmation) {
  const privateKey=await crypto.subtle.importKey("jwk",jwk(b(ready.browserPoint),ready.browserScalar),{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  return encoded(canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},privateKey,transcript(b(confirmation))))));
}
async function manifestFor(ready, current) {
  let trust = await enrollRootPin02(b(ready.pin), b(ready.fingerprint));
  let manifest = await verifyManifest02(b(ready.predecessor), trust, BigInt(Date.now()));
  trust = advanceManifestTrust02(trust, manifest);
  manifest = await verifyManifest02(b(ready.manifest), trust, BigInt(Date.now()));
  if (current !== ready.manifest) {
    trust = advanceManifestTrust02(trust, manifest);
    manifest = await verifyManifest02(b(current), trust, BigInt(Date.now()));
  }
  return manifest;
}
function authorityClaims(m, s, message, signer, recipients) {
  assert.deepEqual(Buffer.from(m.accountId), id(s.account)); assert.deepEqual(Buffer.from(m.digest), b(s.manifest));
  return { accountId:m.accountId, deviceId:id(s.device), lineId:id(s.line), manifestDigest:m.digest, keysetVersion:m.version, signerKeyId:signer.keyId, wraps:recipients };
}
export async function prepareConfirmedFixture(input) {
  const { ready, scope, body, current, lifetimeMs = 30000 } = structuredClone(input);
  assert.ok(Number.isInteger(lifetimeMs) && lifetimeMs>0 && lifetimeMs<=30000);
  const m = await manifestFor(ready, current), now = BigInt(Date.now()), message = randomUUID(), expires = now + BigInt(lifetimeMs);
  const signer = m.keys.find((k) => k.role === 5), phone = m.keys.find((k) => k.role === 1), archive = m.keys.find((k) => k.role === 2);
  assert.ok(signer && phone && archive); assert.deepEqual(Buffer.from(archive.keyId), b(scope.reader));
  const recipients = [phone, archive].map((k) => ({role:k.role, keyId:k.keyId}));
  authorizeOutbound02(m, authorityClaims(m,scope,message,signer,recipients), now);
  const point = b(ready.browserPoint);
  const privateKey = await crypto.subtle.importKey("jwk", jwk(point,ready.browserScalar), { name:"ECDSA", namedCurve:"P-256" }, false,["sign"]);
  const prepared = await prepareOutboundEnvelope02({ kind:1, manifest:m, nowMs:now, messageId:id(message),deviceId:id(scope.device),lineId:id(scope.line),peer:Buffer.from(scope.peer),observedMs:now,expiresMs:expires,
    content:body,cek:randomBytes(32),nonce:randomBytes(12),signer:{privateKey,publicPoint:point},recipients:[phone,archive].map((k)=>({role:k.role,keyId:k.keyId,point:k.point,ekm:randomBytes(32)})) });
  const confirmation=encodeFixtureConfirmation({...scope,message,trustGeneration:ready.trustGeneration,version:m.version,expiresMs:expires,
    signer:encoded(signer.keyId),reader:encoded(archive.keyId),manifest:encoded(m.digest),envelopeDigest:encoded(hash(prepared.envelope)),bodyDigest:encoded(hash(Buffer.from(body,"utf8")))});
  // Merely preparing the review does not sign the separate confirmation.
  return Object.freeze({ envelope:encoded(prepared.envelope), confirmation:encoded(confirmation), message, expiresMs:expires.toString(),
    sign: async () => encoded(canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},privateKey,transcript(confirmation))))) });
}
export async function openConfirmedFixture(input) {
  const { ready, scope, current, packet } = structuredClone(input);
  const m = await manifestFor(ready,current), bytes = b(packet.envelope), proof = b(packet.confirmation), sig = b(packet.signature);
  assert.ok(bytes.length >= 426 && bytes.length <= 34213); assert.ok(bytes.subarray(0,8).equals(Buffer.from([90,84,83,69,2,1,0,0])));
  const size = bytes.readUInt16BE(8); assert.ok(size>=157 && size<=170);
  const p = bytes.subarray(10,10+size); assert.equal(size,154+p[153]);
  assert.deepEqual(p.subarray(0,16),id(scope.account)); assert.deepEqual(p.subarray(32,48),id(scope.device)); assert.deepEqual(p.subarray(48,64),id(scope.line));
  assert.deepEqual(p.subarray(154),Buffer.from(scope.peer)); assert.deepEqual(p.subarray(72,104),b(scope.manifest));
  assert.equal(p[152],1);assert.deepEqual(p.subarray(16,32),id(packet.message));
  const observed=p.readBigUInt64BE(136),expiry=p.readBigUInt64BE(144),now=BigInt(Date.now());
  assert.ok(observed>0n && observed<=now && now<expiry && expiry>observed && expiry-observed<=30000n);
  const bodyAt=10+size, length=bytes.readUInt32BE(bodyAt+12); assert.ok(length>=17 && length<=32784);
  const wrapAt=bodyAt+16+length; assert.equal(bytes[wrapAt],2); assert.equal(bytes.length,wrapAt+1+292+64);
  const phone=m.keys.find((k)=>k.role===1),archive=m.keys.find((k)=>k.role===2),signer=m.keys.find((k)=>k.role===5);
  const wraps=[bytes.subarray(wrapAt+1,wrapAt+147),bytes.subarray(wrapAt+147,wrapAt+293)];
  const claims=authorityClaims(m,scope,packet.message,signer,[phone,archive].map((k)=>({role:k.role,keyId:k.keyId})));
  authorizeOutbound02(m,claims,BigInt(Date.now())); assert.deepEqual(p.subarray(64,72),u64(m.version)); assert.deepEqual(p.subarray(104,136),Buffer.from(signer.keyId));
  for (let i=0;i<2;i++) {assert.equal(wraps[i][0],[1,2][i]);assert.deepEqual(wraps[i].subarray(1,33),Buffer.from([phone,archive][i].keyId));}
  const signerKey=await crypto.subtle.importKey("raw",signer.point,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  assert.deepEqual(Buffer.from(canonicalSignature02(sig)),sig);
  assert.ok(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},signerKey,sig,transcript(proof)));
  const envelopeSignature=bytes.subarray(-64); assert.deepEqual(Buffer.from(canonicalSignature02(envelopeSignature)),envelopeSignature);
  assert.ok(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},signerKey,envelopeSignature,Buffer.concat([Buffer.from("ZTSE/sign/v2\0"),sized(bytes.subarray(0,-64))])));
  const peer=Buffer.from(scope.peer);
  const prefix=Buffer.concat([Buffer.from("ZTCS\x01"),id(scope.account),id(scope.device),id(scope.line),id(scope.interval),id(scope.session),p.subarray(16,32),u64(scope.generation),u64(ready.trustGeneration),u64(m.version),u64(expiry),Buffer.from([peer.length]),peer,Buffer.from(signer.keyId),Buffer.from(archive.keyId),Buffer.from(m.digest),hash(bytes)]);
  assert.equal(proof.length,prefix.length+32); assert.deepEqual(proof.subarray(0,-32),prefix);
  const wrap=wraps[0], point=b(ready.phonePoint);
  const privateKey=await crypto.subtle.importKey("jwk",jwk(point,ready.phoneScalar),{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
  const cek=await openFixtureWrap(privateKey,point,wrap.subarray(33,98),Buffer.concat([Buffer.from("ZTSE/wrap/v2\0"),bytes.subarray(0,10),p,wrap.subarray(0,33)]),wrap.subarray(98));
  const key=await crypto.subtle.importKey("raw",cek,"AES-GCM",false,["decrypt"]);
  const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:bytes.subarray(bodyAt,bodyAt+12),tagLength:128,additionalData:Buffer.concat([Buffer.from("ZTSE/body/v2\0"),bytes.subarray(0,10),p])},key,bytes.subarray(bodyAt+16,wrapAt));
  assert.deepEqual(hash(Buffer.from(plain)),proof.subarray(-32));
  const text=new TextDecoder("utf-8",{fatal:true,ignoreBOM:true}).decode(plain);assert.ok(text && !text.includes("\0") && !text.startsWith("\uFEFF"));
  assert.ok(BigInt(Date.now())<expiry);return text;
}
