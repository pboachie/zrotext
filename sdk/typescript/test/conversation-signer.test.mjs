// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {prepareConversationSignerSetup02} from "../dist/conversation-signer.js";
import {canonicalSignature02,verifyManifest02,advanceManifestTrust02,browserSignerKeyId02,verifiedManifestIdentity02} from "../dist/draft02-manifest.js";
import {openConfirmedFixture,encodeFixtureConfirmation} from "./conversation-simulator-send.mjs";
globalThis.crypto ??= webcrypto;
const encoder = new TextEncoder();
const now = BigInt(Date.now());
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const zero32 = new Uint8Array(32);
const account = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
const device = Uint8Array.from({ length: 16 }, (_, i) => i + 17);
const line = Uint8Array.from({ length: 16 }, (_, i) => i + 33);
const zero16 = new Uint8Array(16);

function join(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function u16(n) { return Uint8Array.of(n >> 8, n & 255); }
function u32(n) { return Uint8Array.of(n >>> 24, n >>> 16 & 255, n >>> 8 & 255, n & 255); }
function u64(n) { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, n, false); return out; }
function bytes32(n) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
function val(bytes) { return bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n); }
async function sha(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function key() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return { privateKey: pair.privateKey, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function id(role, point) {
  return sha(join(encoder.encode("ZTSE/key/v1\0"), role <= 3 ? u16(0x10) : u16(0x101), point));
}
async function sign(k, label, unsigned) {
  const input = join(encoder.encode(`${label}\0`), u32(unsigned.length), unsigned);
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k.privateKey, input)));
}
function highS(low) {
  const out = Uint8Array.from(low);
  out.set(bytes32(order - val(out.subarray(32))), 32);
  return out;
}
async function fixture() {
  const root = await key();
  const payload = await key();
  const archive = await key();
  const signer = await key();
  const records = [
    { role: 1, key: payload, device, line, scope: 4, state: 1 },
    { role: 2, key: archive, device: zero16, line: zero16, scope: 12, state: 1 },
    { role: 5, key: signer, device: zero16, line, scope: 1, state: 1 },
    { role: 6, key: root, device: zero16, line: zero16, scope: 0, state: 1 },
  ];
  for (const record of records) record.keyId = await id(record.role, record.key.point);
  return { root, payload, archive, signer, records };
}
async function manifest(f, options = {}) {
  const records = options.records ?? f.records;
  const issued = options.issued ?? now - 1_000n;
  const expires = options.expires ?? now + 3_600_000n;
  const version = options.version ?? 1n;
  const previous = options.previous ?? zero32;
  const sorted = [...records].sort((a, b) => a.role - b.role || Buffer.compare(a.keyId, b.keyId));
  const recordBytes = sorted.map((r) => join(
    Uint8Array.of(r.role), r.keyId, r.key.point, r.device, r.line,
    u16(r.scope), u64(r.from ?? issued), u64(r.until ?? expires), Uint8Array.of(r.state),
  ));
  const unsigned = join(encoder.encode("ZTMA"), Uint8Array.of(2), account,
    u64(options.generation ?? 1n), u64(version), u64(issued), u64(expires), previous,
    f.root.point, Uint8Array.of(sorted.length), ...recordBytes);
  return join(unsigned, await sign(options.signer ?? f.root, "ZTSE/manifest/v2", unsigned));
}
function pin(root) {
  return { accountId: Uint8Array.from(account), generation: 1n, rootPoint: Uint8Array.from(root.point),
    version: 0n, digest: Uint8Array.from(zero32), anchorDigest: Uint8Array.from(zero32) };
}
async function rootPinBytes(root, accountId = account) {
  const bytes = join(encoder.encode("ZTRP"), Uint8Array.of(2), accountId, u64(1n), root.point);
  const fingerprint = await sha(join(encoder.encode("ZTSE/root-pin/v2\0"), bytes));
  return { bytes, fingerprint };
}

const bindingFor=f=>({account,device,line,interval:Uint8Array.from({length:16},(_,i)=>i+49),session:Uint8Array.from({length:16},(_,i)=>i+65),generation:1n,peer:"+12",phoneReader:f.records[0].keyId,archiveReader:f.records[1].keyId});
const b64=v=>Buffer.from(v).toString("base64");
const uuid=v=>Buffer.from(v).toString("hex").replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/,"$1-$2-$3-$4-$5");
async function candidate(){
 const f=await fixture(),binding=bindingFor(f);let trust=pin(f.root),authority=await verifyManifest02(await manifest(f),trust,now);const predecessor=Uint8Array.from(authority.bytes);trust=advanceManifestTrust02(trust,authority);
 let alive=true,consent=true,time=now,selection=binding,reads=0,readHook=()=>{};
 const signer=await prepareConversationSignerSetup02(binding,async()=>{},async()=>{reads++;readHook();return {binding:selection,manifest:authority,nowMs:time,ownerSessionLive:alive,consentLive:consent};});
 f.records[2]={...f.records[2],key:{point:signer.publicPoint},keyId:signer.keyId};
 authority=await verifyManifest02(await manifest(f,{version:2n,previous:authority.digest}),trust,now);trust=advanceManifestTrust02(trust,authority);
 const envelope=new Uint8Array(426).fill(7),text="Synthetic exact reply \u03a9\nTrailing spaces  ";
 async function packet(){const p={account:uuid(account),device:uuid(device),line:uuid(line),interval:uuid(binding.interval),session:uuid(binding.session),message:uuid(Uint8Array.from({length:16},(_,i)=>i+81)),generation:1,trustGeneration:authority.generation,version:authority.version,expiresMs:now+30000n,peer:binding.peer,signer:b64(signer.keyId),reader:b64(binding.archiveReader),manifest:b64(authority.digest),envelopeDigest:b64(await sha(envelope)),bodyDigest:b64(await sha(encoder.encode(text)))};return encodeFixtureConfirmation(p);}
 return {f,binding,signer,envelope,text,packet,setAlive:v=>alive=v,setConsent:v=>consent=v,setTime:v=>time=v,setSelection:v=>selection=v,setHook:v=>readHook=v,get reads(){return reads;},identity:()=>verifiedManifestIdentity02(authority,time),phoneFixture:async()=>{const root=await rootPinBytes(f.root),jwk=await crypto.subtle.exportKey("jwk",f.payload.privateKey);return {pin:b64(root.bytes),fingerprint:b64(root.fingerprint),predecessor:b64(predecessor),manifest:b64(authority.bytes),phonePoint:b64(f.payload.point),phoneScalar:Buffer.from(jwk.d,"base64url").toString("base64"),trustGeneration:1};},changeRoot:async()=>{f.root=await key();const rootId=await id(6,f.root.point);f.records=f.records.map(r=>r.role===6?{...r,key:f.root,keyId:rootId}:r);trust={...pin(f.root),generation:2n};authority=await verifyManifest02(await manifest(f,{generation:2n}),trust,now);},renew:async()=>{authority=await verifyManifest02(await manifest(f,{version:authority.version+1n,previous:authority.digest}),trust,now);trust=advanceManifestTrust02(trust,authority);},revoke:async()=>{authority=await verifyManifest02(await manifest(f,{version:authority.version+1n,previous:authority.digest,records:f.records.map(r=>r.role===5?{...r,state:2}:r)}),trust,now);trust=advanceManifestTrust02(trust,authority);}};
}
test("explicit setup refusal generates no usable signer",async()=>{const f=await fixture();let reads=0;await assert.rejects(prepareConversationSignerSetup02(bindingFor(f),async()=>{throw Error("declined");},async()=>{reads++;return null;}));assert.equal(reads,0);});
test("unverified manifest cannot authorize setup",async()=>{const f=await fixture();await assert.rejects(prepareConversationSignerSetup02(bindingFor(f),async()=>{},async()=>({binding:bindingFor(f),manifest:{accountId:account},nowMs:now,ownerSessionLive:true,consentLive:true})),/just-verified/);});
test("actual owner-enrolled candidate signs exact domain once",async()=>{const c=await candidate(),proof=await c.packet();let confirmed=0;const signature=await c.signer.signReviewed(proof,c.envelope,c.text,async(digest,body)=>{confirmed++;assert.deepEqual(digest,await sha(proof));assert.deepEqual(body,await sha(encoder.encode(c.text)));});const publicKey=await crypto.subtle.importKey("raw",c.signer.publicPoint,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);const transcript=join(encoder.encode("zrotext/conversation/confirm-send/v1\0"),u32(proof.length),proof);assert.equal(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},publicKey,signature,transcript),true);assert.deepEqual(signature,canonicalSignature02(signature));await assert.rejects(c.signer.signReviewed(proof,c.envelope,c.text,async()=>{}),/consumed/);assert.equal(confirmed,1);assert.deepEqual(c.signer.keyId,await browserSignerKeyId02(c.signer.publicPoint));assert.equal("privateKey" in c.signer,false);});
for(const [name,change] of [["logout",c=>c.setAlive(false)],["withdrawn consent",c=>c.setConsent(false)],["expiry",c=>c.setTime(now+30000n)],["changed peer",c=>c.setSelection({...c.binding,peer:"+13"})],["changed session",c=>c.setSelection({...c.binding,session:device})],["revoked owner manifest",async c=>c.revoke()]])test(name+" refuses confirmed signing",async()=>{const c=await candidate(),proof=await c.packet();await change(c);await assert.rejects(c.signer.signReviewed(proof,c.envelope,c.text,async()=>{}));});
test("changed actual body cannot sign",async()=>{const c=await candidate();await assert.rejects(c.signer.signReviewed(await c.packet(),c.envelope,c.text+"changed",async()=>{}),/content/);});
test("changed encrypted bytes cannot sign",async()=>{const c=await candidate(),p=await c.packet();c.envelope[0]^=1;await assert.rejects(c.signer.signReviewed(p,c.envelope,c.text,async()=>{}),/content/);});
test("cancelled confirmation cannot silently retry",async()=>{const c=await candidate(),p=await c.packet();await assert.rejects(c.signer.signReviewed(p,c.envelope,c.text,async()=>{throw Error("cancelled");}));await assert.rejects(c.signer.signReviewed(p,c.envelope,c.text,async()=>{}),/unavailable/);});
test("authority change after signing withholds signature",async()=>{const c=await candidate(),p=await c.packet();let calls=0;c.setHook(()=>{if(++calls===2)c.setAlive(false);});await assert.rejects(c.signer.signReviewed(p,c.envelope,c.text,async()=>{}),/authority/);});
test("clock rollback refuses",async()=>{const c=await candidate();c.setTime(now-1n);await assert.rejects(c.signer.signReviewed(await c.packet(),c.envelope,c.text,async()=>{}));});
test("closed signer cannot resume without explicit new setup",async()=>{const c=await candidate();c.signer.close();await assert.rejects(c.signer.signReviewed(await c.packet(),c.envelope,c.text,async()=>{}));});
test("strict UTF8 rejects unpaired surrogates",async()=>{const c=await candidate();await assert.rejects(c.signer.signReviewed(await c.packet(),c.envelope,"bad\ud800",async()=>{}),/UTF-8/);});

test("owned signer prepares a real profile02 envelope before separate confirmation",async()=>{const c=await candidate();let confirmations=0;const review=await c.signer.prepareReview(c.text);assert.ok(review.envelope.length>=557);assert.deepEqual(Buffer.from(review.envelope.subarray(0,8)),Buffer.from([90,84,83,69,2,1,0,0]));assert.equal(review.body,c.text);const signature=await c.signer.signReviewed(review.proof,review.envelope,review.body,async()=>{confirmations++;});assert.equal(signature.length,64);assert.equal(confirmations,1);});
test("preparing review cannot confirm or persist credentials",async()=>{const c=await candidate();const first=await c.signer.prepareReview(c.text),second=await c.signer.prepareReview(c.text);assert.notDeepEqual(first.envelope,second.envelope);assert.notDeepEqual(first.messageId,second.messageId);assert.equal("privateKey" in c.signer,false);});

test("valid new root generation cannot reuse old setup signer",async()=>{const c=await candidate();await c.changeRoot();await assert.rejects(c.signer.prepareReview(c.text),/root changed/);});
test("same root benign enrollment renewal remains usable",async()=>{const c=await candidate();await c.renew();const review=await c.signer.prepareReview(c.text);assert.equal((await c.signer.signReviewed(review.proof,review.envelope,review.body,async()=>{})).length,64);});

test("new signer review decrypts as exact confirmed content at distinct phone fixture",async()=>{
 const c=await candidate(),review=await c.signer.prepareReview(c.text),signature=await c.signer.signReviewed(review.proof,review.envelope,review.body,async()=>{}),ready=await c.phoneFixture();
 const scope={account:uuid(c.binding.account),device:uuid(c.binding.device),line:uuid(c.binding.line),interval:uuid(c.binding.interval),session:uuid(c.binding.session),generation:"1",peer:c.binding.peer,reader:b64(c.binding.archiveReader),manifest:b64(c.identity().digest)};
 const packet={message:uuid(review.messageId),envelope:b64(review.envelope),confirmation:b64(review.proof),signature:b64(signature)};
 assert.equal(await openConfirmedFixture({ready,scope,current:ready.manifest,packet}),c.text);
});
