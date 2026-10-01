// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant adapter to an EXISTING owner-root custodian, never a root generator or private-key store. */
import {authorizeOutbound02,browserSignerKeyId02,canonicalSignature02,verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02,advanceManifestTrust02,type Manifest02,type ManifestTrust02} from "./draft02-manifest.js";
import type {ConversationSignerBinding02,ConversationSignerCurrent02} from "./conversation-signer.js";
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const join=(...p:Uint8Array[])=>{const out=new Uint8Array(p.reduce((n,v)=>n+v.length,0));let at=0;for(const v of p){out.set(v,at);at+=v.length;}return out;};
const u64=(v:bigint)=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,v);return b;};
const copyBinding=(b:ConversationSignerBinding02)=>({...b,account:Uint8Array.from(b.account),device:Uint8Array.from(b.device),line:Uint8Array.from(b.line),interval:Uint8Array.from(b.interval),session:Uint8Array.from(b.session),phoneReader:Uint8Array.from(b.phoneReader),archiveReader:Uint8Array.from(b.archiveReader)});
const bindingEqual=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&(["account","device","line","interval","session","phoneReader","archiveReader"] as const).every(k=>same(a[k],b[k]));
export type ConversationEnrollmentReview02=Readonly<{binding:ConversationSignerBinding02;publicPoint:Uint8Array;keyId:Uint8Array;predecessorDigest:Uint8Array;successorVersion:bigint;untilMs:bigint;unsigned:Uint8Array}>;
/** Single-use enrollment operation. installVerified must atomically CAS the predecessor high-water
 * with verified successor and live session/consent; it must not publish an unchecked callback result.
 * Custodian signs the exact ZTSE/manifest/v2 transcript and independently consumes owner approval.
 */
export function createConversationEnrollment02(input:ConversationSignerBinding02,publicPoint:Uint8Array,
 readCurrent:()=>Promise<ConversationSignerCurrent02|null>,
 consumeOwnerDecision:(review:ConversationEnrollmentReview02)=>Promise<void>,
 signWithExistingRoot:(review:ConversationEnrollmentReview02)=>Promise<Uint8Array>,
 installVerified:(expectedDigest:Uint8Array,accepted:Manifest02,highWater:ManifestTrust02,binding:ConversationSignerBinding02)=>Promise<void>) {
 const binding=copyBinding(input),point=Uint8Array.from(publicPoint);let consumed=false;
 if((["account","device","line","interval","session","phoneReader","archiveReader"] as const).some(k=>binding[k].length!==(k.endsWith("Reader")?32:16)||binding[k].every(v=>v===0))||binding.generation<=0n||binding.generation>=(1n<<63n)||!/^\+[1-9][0-9]{1,14}$/.test(binding.peer))throw Error("Enrollment binding");
 return Object.freeze({enroll:async()=>{
  if(consumed)throw Error("Enrollment already consumed");consumed=true;
  const current=await readCurrent();if(!current||!current.ownerSessionLive||!current.consentLive||!bindingEqual(binding,current.binding))throw Error("Enrollment authority unavailable");
  const base=verifiedManifestIdentity02(current.manifest,current.nowMs),keyId=await browserSignerKeyId02(point);
  if(!same(base.accountId,binding.account)||base.version>=(1n<<63n)-1n||current.nowMs<=0n)throw Error("Enrollment identity");
  const pin=verifiedManifestTrust02(current.manifest,current.nowMs);
  const original=await verifyManifest02(Uint8Array.from(current.manifest.bytes),pin,current.nowMs);
  function readers(nowMs:bigint) {
   const phone=original.keys.find(k=>k.role===1&&same(k.keyId,binding.phoneReader));
   const archive=original.keys.find(k=>k.role===2&&same(k.keyId,binding.archiveReader));
   if(!phone||!archive||!same(phone.deviceId,binding.device)||!same(phone.lineId,binding.line)||
      [phone,archive].some(k=>k.state!==1||!(k.scope&4)||k.fromMs>nowMs||nowMs>=k.untilMs))throw Error("Enrollment reader authority");
  }
  readers(current.nowMs);
  const until=original.expiresMs<current.nowMs+1800000n?original.expiresMs:current.nowMs+1800000n;
  if(until<=current.nowMs||original.keys.length>=64||original.keys.some(k=>same(k.keyId,keyId)||same(k.point,point)))throw Error("Enrollment key unavailable");
  const keys=[...original.keys.map(k=>({...k,keyId:Uint8Array.from(k.keyId),point:Uint8Array.from(k.point),deviceId:Uint8Array.from(k.deviceId),lineId:Uint8Array.from(k.lineId)})),
   {role:5,keyId,point,deviceId:new Uint8Array(16),lineId:Uint8Array.from(binding.line),scope:1,fromMs:current.nowMs,untilMs:until,state:1}];
  keys.sort((a,b)=>a.role-b.role||compare(a.keyId,b.keyId));
  const records=keys.map(k=>join(Uint8Array.of(k.role),k.keyId,k.point,k.deviceId,k.lineId,Uint8Array.of(k.scope>>8,k.scope&255),u64(k.fromMs),u64(k.untilMs),Uint8Array.of(k.state)));
  const unsigned=join(Uint8Array.of(90,84,77,65,2),base.accountId,u64(base.generation),u64(base.version+1n),u64(current.nowMs),u64(original.expiresMs),base.digest,base.rootPoint,Uint8Array.of(keys.length),...records);
  const review=():ConversationEnrollmentReview02=>Object.freeze({binding:copyBinding(binding),publicPoint:Uint8Array.from(point),keyId:Uint8Array.from(keyId),predecessorDigest:Uint8Array.from(base.digest),successorVersion:base.version+1n,untilMs:until,unsigned:Uint8Array.from(unsigned)});
  let lastNow=current.nowMs;
  async function live(){const value=await readCurrent();if(!value||!value.ownerSessionLive||!value.consentLive||!bindingEqual(binding,value.binding)||value.nowMs<lastNow||value.nowMs>=until)throw Error("Enrollment authority changed");
   const identity=verifiedManifestIdentity02(value.manifest,value.nowMs);if(identity.generation!==base.generation||identity.version!==base.version||!same(identity.rootPoint,base.rootPoint)||!same(identity.digest,base.digest))throw Error("Enrollment predecessor changed");readers(value.nowMs);lastNow=value.nowMs;return value;}
  await consumeOwnerDecision(review());await live();
  const signature=canonicalSignature02(Uint8Array.from(await signWithExistingRoot(review())));
  const final=await live();
  const accepted=await verifyManifest02(join(unsigned,signature),pin,final.nowMs);
  const latest=await live();
  authorizeOutbound02(accepted,{accountId:binding.account,deviceId:binding.device,lineId:binding.line,manifestDigest:accepted.digest,keysetVersion:accepted.version,signerKeyId:keyId,wraps:[{role:1,keyId:binding.phoneReader},{role:2,keyId:binding.archiveReader}]},latest.nowMs);
  await installVerified(Uint8Array.from(base.digest),accepted,advanceManifestTrust02(pin,accepted),copyBinding(binding));
  // The authoritative install adapter owns session/consent CAS; returned success alone cannot unlock signer.
  return accepted;
 }});
}
function compare(a:Uint8Array,b:Uint8Array){for(let i=0;i<Math.min(a.length,b.length);i++)if(a[i]!==b[i])return a[i]-b[i];return a.length-b.length;}
