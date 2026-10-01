// SPDX-License-Identifier: AGPL-3.0-only
/** Existing archive only. No generation, replacement, root recovery or persistent private storage.
 * Unlock transiently imports an extractable scalar-only key to derive actual full X/Y.
 * JWK private strings/engine copies cannot be reliably zeroized. Only the retained key is nonextractable.
 */
import {DhkemP256HkdfSha256} from "@hpke/core";
import {verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02} from "./draft02-manifest.js";
import {keyId} from "./draft01.js";
import type {ConversationSignerBinding02,ConversationSignerCurrent02} from "./conversation-signer.js";
const enc=new TextEncoder(),ab=(b:Uint8Array)=>Uint8Array.from(b).buffer;
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const join=(...p:Uint8Array[])=>{const b=new Uint8Array(p.reduce((n,v)=>n+v.length,0));let at=0;for(const v of p){b.set(v,at);at+=v.length;}return b;};
const u64=(n:bigint)=>{if(n<=0n||n>=(1n<<63n))throw Error("Archive identity refused");const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
const label=(s:string)=>enc.encode(s+"\0");
const fields=["account","session","interval","device","line","phoneReader","archiveReader"] as const;
const own=(b:ConversationSignerBinding02)=>{if(fields.some(k=>!(b[k] instanceof Uint8Array)||b[k].length!==(k.endsWith("Reader")?32:16)))throw Error("Archive selection refused");const c={...b};for(const k of fields)c[k]=Uint8Array.from(b[k]);if(fields.some(k=>c[k].length!==(k.endsWith("Reader")?32:16)||c[k].every(v=>v===0))||!/^\+[1-9][0-9]{1,14}$/.test(c.peer))throw Error("Archive selection refused");u64(c.generation);return c;};
const equal=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&fields.every(k=>same(a[k],b[k]));
export type ArchiveReaderLease02=Readonly<{withKey<T>(binding:ConversationSignerBinding02,run:(key:CryptoKey)=>Promise<T>):Promise<T>;close():void;onClose(listener:()=>void):()=>void}>;
export type ArchiveUnlockReview02=Readonly<{binding:ConversationSignerBinding02;origin:string;rootFingerprint:Uint8Array;archivePoint:Uint8Array;untilMs:bigint;capability:"account-wide archive decryption"}>;
export async function unlockExistingArchive02(input:Readonly<{encrypted:Uint8Array;recovery:Uint8Array;binding:ConversationSignerBinding02;origin:string;comparedRootFingerprint:Uint8Array;untilMs:bigint;readCurrent:()=>Promise<ConversationSignerCurrent02|null>;consumeUnlockDecision:(review:ArchiveUnlockReview02)=>Promise<void>;signal:AbortSignal}>):Promise<ArchiveReaderLease02>{
 if(!(input.encrypted instanceof Uint8Array)||input.encrypted.length<334||input.encrypted.length>845||!(input.recovery instanceof Uint8Array)||input.recovery.length!==32||!(input.comparedRootFingerprint instanceof Uint8Array)||input.comparedRootFingerprint.length!==32||typeof input.origin!=="string"||input.origin.length>512)throw Error("Archive input bound refused");
 const {readCurrent,consumeUnlockDecision}=input;
 const binding=own(input.binding),encrypted=Uint8Array.from(input.encrypted),recovery=Uint8Array.from(input.recovery),fingerprint=Uint8Array.from(input.comparedRootFingerprint),origin=input.origin,until=input.untilMs,signal=input.signal;
 let key:CryptoKey|null=null,closed=false,busy=false,timer:ReturnType<typeof setTimeout>|null=null,lastNow=0n,deadline=until,monotonicDeadline=Infinity,lastVersion=0n,lastDigest:Uint8Array|null=null,root:Uint8Array|null=null,generation:bigint|null=null,archivePoint:Uint8Array|null=null;
 const listeners=new Set<()=>void>();
 const close=()=>{if(closed)return;closed=true;key=null;recovery.fill(0);if(timer!==null)clearTimeout(timer);timer=null;try{signal?.removeEventListener("abort",close);}finally{for(const listener of listeners)try{listener();}catch{}listeners.clear();}};
 if(!signal||signal.aborted){close();throw Error("Archive unlock closed");}signal.addEventListener("abort",close,{once:true});
 let vault:Uint8Array|null=null,scalar:Uint8Array|null=null,pkcs8:Uint8Array|null=null,temporary:CryptoKey|null=null,jwk:JsonWebKey|null=null;
 try {
  const url=new URL(origin);if(url.protocol!=="https:"||url.origin!==origin||url.username||url.password||url.pathname!=="/"||url.search||url.hash||!/^https:\/\/[\x21-\x7e]{1,512}$/.test(origin)||origin.length>512||fingerprint.length!==32||fingerprint.every(v=>v===0)||recovery.length!==32)throw Error("Archive identity refused");
  const arm=()=>{if(timer!==null)clearTimeout(timer);const remaining=monotonicDeadline-performance.now();if(remaining<=0){close();throw Error("Archive signed authority expired");}timer=setTimeout(close,remaining);};
  async function current(){
   if(closed||performance.now()>=monotonicDeadline)throw Error("Archive custody closed");const started=performance.now(),sampled=await readCurrent();if(closed||!sampled||!sampled.ownerSessionLive||!sampled.consentLive||!equal(binding,own(sampled.binding))||sampled.nowMs<=0n||sampled.nowMs<lastNow||sampled.nowMs>=deadline)throw Error("Archive authority lost");
   const now=sampled.nowMs,id=verifiedManifestIdentity02(sampled.manifest,now),manifest=await verifyManifest02(Uint8Array.from(sampled.manifest.bytes),verifiedManifestTrust02(sampled.manifest,now),now);
   if(closed||!same(id.accountId,binding.account)||generation!==null&&(generation!==id.generation||!same(root!,id.rootPoint))||id.version<lastVersion||id.version===lastVersion&&lastDigest&&!same(lastDigest,id.digest))throw Error("Archive trust changed");
   const pin=join(enc.encode("ZTRP"),Uint8Array.of(2),id.accountId,u64(id.generation),id.rootPoint),actual=new Uint8Array(await crypto.subtle.digest("SHA-256",ab(join(label("ZTSE/root-pin/v2"),pin))));if(closed||!same(actual,fingerprint))throw Error("Archive compared root refused");
   const reader=manifest.keys.find(k=>k.role===2&&same(k.keyId,binding.archiveReader));if(!reader||reader.state!==1||!(reader.scope&8)||reader.fromMs>now||reader.untilMs<=now||archivePoint&&!same(archivePoint,reader.point)||!same(await keyId(0x10,reader.point),binding.archiveReader))throw Error("Archive reader unavailable");
   if(closed)throw Error("Archive custody closed");root=id.rootPoint;generation=id.generation;archivePoint=Uint8Array.from(reader.point);lastNow=now;deadline=[deadline,reader.untilMs,manifest.expiresMs].reduce((a,b)=>a<b?a:b);monotonicDeadline=Math.min(monotonicDeadline,started+Number(deadline-now));lastVersion=id.version;lastDigest=id.digest;if(key)arm();return {now,identity:id,point:archivePoint};
  }
  const initial=await current();if(until-initial.now>1800000n)throw Error("Archive session lifetime refused");u64(until);
  const h=177+enc.encode(origin).length;if(encrypted.length!==h+156||encrypted.length>845||!same(encrypted.subarray(0,6),Uint8Array.of(90,84,65,66,1,1))||encrypted.subarray(6,22).every(v=>v===0)||!same(encrypted.subarray(22,38),binding.account)||!same(encrypted.subarray(38,46),u64(initial.identity.generation))||!same(encrypted.subarray(46,78),fingerprint)||!same(encrypted.subarray(78,110),binding.archiveReader)||!same(encrypted.subarray(110,175),initial.point)||new DataView(encrypted.buffer).getUint16(175)!==h-177||!same(encrypted.subarray(177,h),enc.encode(origin))||!same(encrypted.subarray(h+104,h+108),Uint8Array.of(0,0,0,48)))throw Error("Archive backup identity refused");
  await consumeUnlockDecision(Object.freeze({binding:own(binding),origin,rootFingerprint:Uint8Array.from(fingerprint),archivePoint:Uint8Array.from(initial.point),untilMs:until,capability:"account-wide archive decryption"}));await current();
  const material=await crypto.subtle.importKey("raw",ab(recovery),"HKDF",false,["deriveKey"]),wrapping=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:ab(encrypted.subarray(h,h+32)),info:ab(join(label("ZTSE/archive-vault-wrap/v1"),binding.account,u64(initial.identity.generation),binding.archiveReader))},material,{name:"AES-GCM",length:256},false,["decrypt"]);
  await current();vault=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:ab(encrypted.subarray(h+32,h+44)),additionalData:ab(join(label("ZTSE/archive-vault-key-wrap/v1"),encrypted.subarray(0,h+44))),tagLength:128},wrapping,ab(encrypted.subarray(h+44,h+92))));if(vault.length!==32)throw Error("Archive backup refused");await current();
  const bodyKey=await crypto.subtle.importKey("raw",ab(vault),"AES-GCM",false,["decrypt"]);scalar=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:ab(encrypted.subarray(h+92,h+104)),additionalData:ab(join(label("ZTSE/archive-backup/v1"),encrypted.subarray(0,h+108))),tagLength:128},bodyKey,ab(encrypted.subarray(h+108))));if(scalar.length!==32)throw Error("Archive scalar refused");await current();
  // This public API imports scalar-only PKCS8, so exported X/Y cannot echo untrusted header coordinates.
  temporary=await new DhkemP256HkdfSha256().deserializePrivateKey(ab(scalar));jwk=await crypto.subtle.exportKey("jwk",temporary);
  const decode=(s:string|undefined)=>{if(!s||!/^[A-Za-z0-9_-]{43}$/.test(s))throw Error("Archive actual point unavailable");return Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"="),c=>c.charCodeAt(0));};
  const point=join(Uint8Array.of(4),decode(jwk.x),decode(jwk.y));if(!same(point,initial.point)||!same(await keyId(0x10,point),binding.archiveReader))throw Error("Archive actual point differs");
  pkcs8=join(Uint8Array.of(48,65,2,1,0,48,19,6,7,42,134,72,206,61,2,1,6,8,42,134,72,206,61,3,1,7,4,39,48,37,2,1,1,4,32),scalar);
  key=await crypto.subtle.importKey("pkcs8",ab(pkcs8),{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]);if(key.extractable||key.type!=="private")throw Error("Archive key custody refused");await current();
  arm();
  return Object.freeze({close,onClose(listener:()=>void){if(closed)listener();else listeners.add(listener);return()=>{listeners.delete(listener);};},async withKey<T>(selected:ConversationSignerBinding02,run:(key:CryptoKey)=>Promise<T>):Promise<T>{if(closed||busy||!key)throw Error("Archive custody unavailable");busy=true;try{if(!equal(binding,own(selected)))throw Error("Archive selection changed");await current();const result=await run(key!);await current();return result;}catch(error){close();throw error;}finally{busy=false;}}});
 }catch(error){close();throw error;}finally{recovery.fill(0);vault?.fill(0);scalar?.fill(0);pkcs8?.fill(0);temporary=null;if(jwk)delete jwk.d;jwk=null;}
}
