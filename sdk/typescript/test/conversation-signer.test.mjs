// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {prepareConversationSignerSetup02} from "../dist/conversation-signer.js";
import {createConversationEnrollment02} from "../dist/conversation-enrollment.js";
import {prepareConversationCustody02,existingConversationRootCustodian02} from "../dist/conversation-custody.js";
import {prepareInboundEnvelope02} from "../dist/draft02-envelope-prep.js";
import {Draft02TrustStore} from "../dist/draft02-trust-store.js";
import {indexedDB} from "fake-indexeddb";
import {canonicalSignature02,verifyManifest02,advanceManifestTrust02,browserSignerKeyId02,verifiedManifestIdentity02} from "../dist/draft02-manifest.js";
import {openConfirmedFixture,encodeFixtureConfirmation} from "./conversation-simulator-send.mjs";
globalThis.crypto ??= webcrypto;
globalThis.indexedDB ??= indexedDB;
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

async function enrollmentCandidate(changeBinding=b=>b){
 const f=await fixture(),binding=changeBinding(bindingFor(f));let trust=pin(f.root),authority=await verifyManifest02(await manifest(f),trust,now);
 trust=advanceManifestTrust02(trust,authority);const before=authority;const browser=await key();
 let alive=true,consent=true,selection=binding,time=now,decisions=0,signs=0,installs=0;
 let decide=async()=>{},custodian=async r=>sign(f.root,"ZTSE/manifest/v2",r.unsigned),beforeInstall=async()=>{};
 const read=async()=>({binding:selection,manifest:authority,nowMs:time,ownerSessionLive:alive,consentLive:consent});
 const adapter=createConversationEnrollment02(binding,browser.point,read,async r=>{decisions++;await decide(r);},async r=>{signs++;return custodian(r);},async(expected,accepted,highWater,selected)=>{
  await beforeInstall();assert.deepEqual(selected,binding);
  if(!alive||!consent||selection!==binding||!Buffer.from(authority.digest).equals(Buffer.from(expected)))throw Error("Fixture CAS authority lost");
  authority=accepted;trust=highWater;installs++;
 });
 return {f,binding,browser,adapter,before,read,stats:()=>({decisions,signs,installs}),setAlive:v=>alive=v,setConsent:v=>consent=v,setSelection:v=>selection=v,setTime:v=>time=v,setDecision:v=>decide=v,setSigner:v=>custodian=v,setInstall:v=>beforeInstall=v,
 rotateRoot:async()=>{f.root=await key();const rootId=await id(6,f.root.point);f.records=f.records.map(r=>r.role===6?{...r,key:f.root,keyId:rootId}:r);trust={...pin(f.root),generation:2n};authority=await verifyManifest02(await manifest(f,{generation:2n}),trust,now);},
 renew:async()=>{authority=await verifyManifest02(await manifest(f,{version:authority.version+1n,previous:authority.digest}),trust,now);trust=advanceManifestTrust02(trust,authority);}};
}
test("existing root enrollment adds only bounded exact line signer and verifies install",async()=>{
 const c=await enrollmentCandidate(),accepted=await c.adapter.enroll();assert.equal(accepted.version,2n);assert.deepEqual(accepted.previousDigest,c.before.digest);
 const keyId=await browserSignerKeyId02(c.browser.point),record=accepted.keys.find(k=>Buffer.from(k.keyId).equals(Buffer.from(keyId)));
 assert.equal(record.role,5);assert.equal(record.scope,1);assert.deepEqual(record.lineId,c.binding.line);assert.equal(record.untilMs,now+1800000n);
 for(const original of c.before.keys)assert.deepEqual(accepted.keys.find(k=>Buffer.from(k.keyId).equals(Buffer.from(original.keyId))),original);
 assert.deepEqual(c.stats(),{decisions:1,signs:1,installs:1});await assert.rejects(c.adapter.enroll(),/consumed/);
});
test("root enrollment refusal consumes action without signing",async()=>{const c=await enrollmentCandidate();c.setDecision(async()=>{throw Error("declined");});await assert.rejects(c.adapter.enroll());assert.deepEqual(c.stats(),{decisions:1,signs:0,installs:0});await assert.rejects(c.adapter.enroll(),/consumed/);});
test("root enrollment tampered successor signature never installs",async()=>{const c=await enrollmentCandidate();c.setSigner(async r=>{const signature=await sign(c.f.root,"ZTSE/manifest/v2",r.unsigned);signature[2]^=1;return signature;});await assert.rejects(c.adapter.enroll());assert.equal(c.stats().installs,0);});
test("root enrollment wrong signing root never installs",async()=>{const c=await enrollmentCandidate(),wrong=await key();c.setSigner(r=>sign(wrong,"ZTSE/manifest/v2",r.unsigned));await assert.rejects(c.adapter.enroll(),/verification/);assert.equal(c.stats().installs,0);});
for(const [name,change] of [["logout",c=>c.setAlive(false)],["consent withdrawal",c=>c.setConsent(false)],["account switch",c=>c.setSelection({...c.binding,account:device})],["session switch",c=>c.setSelection({...c.binding,session:device})],["reader switch",c=>c.setSelection({...c.binding,archiveReader:new Uint8Array(32).fill(8)})],["expiry",c=>c.setTime(now+1800000n)],["manifest renewal",c=>c.renew()]])test("root enrollment rejects "+name+" during owner decision",async()=>{const c=await enrollmentCandidate();c.setDecision(async()=>{await change(c);});await assert.rejects(c.adapter.enroll());assert.equal(c.stats().signs,0);assert.equal(c.stats().installs,0);});
test("root enrollment revocation during signature withholds installation",async()=>{const c=await enrollmentCandidate();c.setSigner(async r=>{const signature=await sign(c.f.root,"ZTSE/manifest/v2",r.unsigned);c.setConsent(false);return signature;});await assert.rejects(c.adapter.enroll());assert.equal(c.stats().installs,0);});
test("root enrollment final install CAS rejects late logout",async()=>{const c=await enrollmentCandidate();c.setInstall(async()=>{c.setAlive(false);});await assert.rejects(c.adapter.enroll(),/CAS/);assert.equal(c.stats().installs,0);});
for(const [name,change] of [["foreign device",b=>({...b,device:line})],["foreign line",b=>({...b,line:device})],["wrong phone reader",b=>({...b,phoneReader:new Uint8Array(32).fill(8)})],["wrong archive reader",b=>({...b,archiveReader:new Uint8Array(32).fill(8)})]])test("root enrollment preflight rejects "+name+" before root approval",async()=>{const c=await enrollmentCandidate(change);await assert.rejects(c.adapter.enroll(),/reader authority/);assert.deepEqual(c.stats(),{decisions:0,signs:0,installs:0});});
test("root enrollment callback mutation cannot alter owned signed successor",async()=>{const c=await enrollmentCandidate();c.setDecision(async r=>{r.unsigned.fill(0);r.binding.line.fill(0);r.publicPoint.fill(0);});const accepted=await c.adapter.enroll();assert.equal(accepted.version,2n);assert.deepEqual(accepted.accountId,account);});
test("root enrollment valid root rotation cannot reuse old review",async()=>{const c=await enrollmentCandidate();c.setDecision(()=>c.rotateRoot());await assert.rejects(c.adapter.enroll(),/predecessor changed/);assert.equal(c.stats().signs,0);});

async function custodyCandidate(options={}) {
 const f=await fixture(),inbound=await key();
 f.records.push({role:4,key:inbound,keyId:await id(4,inbound.point),device,line,scope:2,state:1});
 const binding=bindingFor(f),store=await Draft02TrustStore.open("synthetic-custody-"+crypto.randomUUID()),rootPin=await rootPinBytes(f.root);
 await store.enroll(rootPin.bytes,rootPin.fingerprint,now);
 let authority=await store.acceptManifest(await manifest(f),now),alive=true,consent=true,time=now,confirmations=0,decisions=0;
 const genesis=authority;
 const archiveJwk=await crypto.subtle.exportKey("jwk",f.archive.privateKey);archiveJwk.key_ops=["deriveBits"];
 const archive=await crypto.subtle.importKey("jwk",archiveJwk,{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);
 const root=await crypto.subtle.importKey("jwk",await crypto.subtle.exportKey("jwk",f.root.privateKey),{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
 const read=async()=>({binding,manifest:authority,nowMs:time,ownerSessionLive:alive,consentLive:consent});
 const acceptedChain=[genesis.bytes];
 const config={binding,archivePrivateKey:archive,readCurrent:read,
  consumeSetupDecision:async reviewed=>assert.deepEqual(reviewed,binding),consumeOwnerDecision:async review=>{decisions++;assert.deepEqual(review.binding,binding);assert.equal(review.successorVersion,authority.version+1n);},
  signWithExistingRoot:existingConversationRootCustodian02(root),installVerified:async(expected,accepted,highWater,selection)=>{
   assert.deepEqual(expected,authority.digest);assert.deepEqual(selection,binding);
   if(options.skipInstall)return;
   authority=await store.acceptManifest(accepted.bytes,time);acceptedChain.push(authority.bytes);assert.deepEqual((await store.read()).trust,highWater);
  },consumeConfirmation:async()=>{confirmations++;},...options};
 const custody=await prepareConversationCustody02(config);
 async function inboundEnvelope(historic=genesis){return (await prepareInboundEnvelope02({kind:2,manifest:historic,nowMs:now,messageId:binding.interval,eventId:binding.interval,deviceId:device,lineId:line,peer:encoder.encode(binding.peer),observedMs:now,localSequence:1n,content:"Synthetic inbound \u03a9\nTrailing spaces  ",cek:crypto.getRandomValues(new Uint8Array(32)),nonce:crypto.getRandomValues(new Uint8Array(12)),signer:{privateKey:inbound.privateKey,publicPoint:inbound.point},recipients:[{role:2,keyId:binding.archiveReader,point:f.archive.point,ekm:crypto.getRandomValues(new Uint8Array(32))}]})).envelope;}
 return {custody,store,genesis,inboundEnvelope,binding,get authority(){return authority;},stats:()=>({confirmations,decisions}),setAlive:v=>alive=v,setConsent:v=>consent=v,setTime:v=>time=v,
  renew:async(revoked=false)=>{const currentRecords=authority.keys.map(k=>({role:k.role,key:{point:k.point},keyId:k.keyId,device:k.deviceId,line:k.lineId,scope:k.scope,state:revoked&&k.role===2?2:k.state,from:k.fromMs,until:k.untilMs}));if(revoked){const replacement=await key();currentRecords.push({role:2,key:replacement,keyId:await id(2,replacement.point),device:zero16,line:zero16,scope:12,state:1,from:now-1000n,until:now+3600000n});}authority=await store.acceptManifest(await manifest(f,{records:currentRecords,version:authority.version+1n,previous:authority.digest}),time);},
  reopen:async()=>{custody.close();return prepareConversationCustody02({...config,history:{trustStore:store,loadChain:async digest=>{const at=acceptedChain.findIndex(bytes=>Buffer.from(bytes.subarray(0,-64)).equals(Buffer.from(genesis.bytes.subarray(0,-64)))&&Buffer.from(digest).equals(Buffer.from(genesis.digest)));if(at<0)throw Error("Synthetic chain not found");return acceptedChain.slice(at);}}});},
  close:()=>{custody.close();store.close();}};
}
test("session custody composes exact existing root enrollment and one confirmed packet",async()=>{const c=await custodyCandidate();try{const {scope}=await c.custody.authority(),review=await c.custody.prepare(scope,"Synthetic exact reply");assert.deepEqual(c.stats(),{confirmations:0,decisions:1});const packet=await c.custody.signReviewed(review,scope,"Synthetic exact reply");assert.deepEqual(Object.keys(packet),["envelope","confirmation","signature"]);assert.equal(Buffer.from(packet.signature,"base64").length,64);assert.equal(c.stats().confirmations,1);await assert.rejects(c.custody.signReviewed(review,scope,"Synthetic exact reply"));}finally{c.close();}});
test("transport success without authoritative enrollment never opens custody",async()=>{await assert.rejects(custodyCandidate({skipInstall:true}),/authoritatively installed/);});
test("session custody verifies signed profile02 inbound and preserves exact body",async()=>{const c=await custodyCandidate();try{const {scope}=await c.custody.authority();assert.equal(await c.custody.openSealed(await c.inboundEnvelope(),scope),"Synthetic inbound \u03a9\nTrailing spaces  ");}finally{c.close();}});
test("same root renewal retains historical inbound without changing ciphertext",async()=>{const c=await custodyCandidate();try{const bytes=await c.inboundEnvelope();await c.renew();const {scope}=await c.custody.authority();assert.equal(await c.custody.openSealed(bytes,scope),"Synthetic inbound \u03a9\nTrailing spaces  ");}finally{c.close();}});
for(const [name,change] of [["current archive revocation",c=>c.renew(true)],["logout",c=>c.setAlive(false)],["consent loss",c=>c.setConsent(false)],["signer expiry",c=>c.setTime(now+1800000n)]])test("custody closes on "+name,async()=>{const c=await custodyCandidate();try{const {scope}=await c.custody.authority(),bytes=await c.inboundEnvelope();await change(c);await assert.rejects(c.custody.openSealed(bytes,scope));await assert.rejects(c.custody.authority());}finally{c.close();}});
test("inbound signature tampering never releases plaintext",async()=>{const c=await custodyCandidate();try{const {scope}=await c.custody.authority(),bytes=await c.inboundEnvelope();bytes[bytes.length-1]^=1;await assert.rejects(c.custody.openSealed(bytes,scope));}finally{c.close();}});
test("persistent high-water proves accepted historical chain without rollback",async()=>{const c=await custodyCandidate();try{const chain=[c.genesis.bytes,c.authority.bytes],before=await c.store.read();assert.deepEqual((await c.store.verifyHistory(chain,now)).digest,c.genesis.digest);assert.deepEqual(await c.store.read(),before);await assert.rejects(c.store.verifyHistory([c.genesis.bytes],now),/high-water/);await assert.rejects(c.store.verifyHistory([c.genesis.bytes,c.genesis.bytes,c.authority.bytes],now),/duplicate/);const broken=Uint8Array.from(c.authority.bytes);broken[60]^=1;await assert.rejects(c.store.verifyHistory([c.genesis.bytes,broken],now));await c.renew();await assert.rejects(c.store.verifyHistory(chain,now),/high-water/);}finally{c.close();}});
test("fresh explicitly approved custody restores history through persisted high-water",async()=>{const c=await custodyCandidate();let fresh;try{const bytes=await c.inboundEnvelope();fresh=await c.reopen();const {scope}=await fresh.authority();assert.equal(await fresh.openSealed(bytes,scope),"Synthetic inbound \u03a9\nTrailing spaces  ");assert.equal(c.stats().decisions,2);}finally{fresh?.close();c.close();}});
