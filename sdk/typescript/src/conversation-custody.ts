// SPDX-License-Identifier: AGPL-3.0-only
/** Explicit session custody composition. No root generation, storage, endpoints or default activation. */
import { prepareConversationSignerSetup02, type ConversationSignerBinding02, type ConversationSignerCurrent02 } from "./conversation-signer.js";
import { createConversationEnrollment02 } from "./conversation-enrollment.js";
import { canonicalSignature02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02 } from "./draft02-manifest.js";
import { openConversationInbound02, parseConversationInbound02 } from "./conversation-reader.js";
import { type Draft02TrustStore } from "./draft02-trust-store.js";
import type {ArchiveReaderLease02} from "./conversation-archive-custody.js";
type Enrollment=Parameters<typeof createConversationEnrollment02>;
export type ConversationOwnerScope02=Readonly<{account:string;session:string;interval:string;device:string;line:string;generation:string;peer:string;reader:string;manifest:string}>;
export type ConversationCustodyOptions02=Readonly<{
 binding:ConversationSignerBinding02;archivePrivateKey?:CryptoKey;archiveLease?:ArchiveReaderLease02;
 signal?:AbortSignal;
 readCurrent:()=>Promise<ConversationSignerCurrent02|null>;
 consumeSetupDecision:Parameters<typeof prepareConversationSignerSetup02>[1];
 consumeOwnerDecision:Enrollment[3];signWithExistingRoot:Enrollment[4];installVerified:Enrollment[5];
 consumeConfirmation:(proofDigest:Uint8Array,bodyDigest:Uint8Array)=>Promise<void>;
 history?:Readonly<{trustStore:Draft02TrustStore;loadChain?:(manifestDigest:Uint8Array,currentDigest:Uint8Array)=>Promise<readonly Uint8Array[]>}>;
}>;
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const b64=(v:Uint8Array)=>btoa(Array.from(v,b=>String.fromCharCode(b)).join(""));
const uuid=(v:Uint8Array)=>Array.from(v,b=>b.toString(16).padStart(2,"0")).join("").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,"$1-$2-$3-$4-$5");
const copy=(b:ConversationSignerBinding02):ConversationSignerBinding02=>({...b,account:Uint8Array.from(b.account),session:Uint8Array.from(b.session),interval:Uint8Array.from(b.interval),device:Uint8Array.from(b.device),line:Uint8Array.from(b.line),phoneReader:Uint8Array.from(b.phoneReader),archiveReader:Uint8Array.from(b.archiveReader)});
const equal=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&(["account","session","interval","device","line","phoneReader","archiveReader"] as const).every(k=>same(a[k],b[k]));
/** Adapter for an existing owner-controlled CryptoKey. No import, generation or persistence occurs.
 * Exact owner approval is consumed separately by enrollment before this function is called.
 */
export function existingConversationRootCustodian02(privateKey:CryptoKey):Enrollment[4]{
 if(privateKey.type!=="private"||privateKey.extractable||privateKey.algorithm.name!=="ECDSA"||(privateKey.algorithm as EcKeyAlgorithm).namedCurve!=="P-256"||!privateKey.usages.includes("sign"))throw Error("Existing nonextractable owner root required");
 return async review=>{const unsigned=Uint8Array.from(review.unsigned),label=new TextEncoder().encode("ZTSE/manifest/v2\0"),input=new Uint8Array(label.length+4+unsigned.length);input.set(label);new DataView(input.buffer).setUint32(label.length,unsigned.length);input.set(unsigned,label.length+4);return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},privateKey,input.buffer)));};
}
/** Caller invokes only after an explicit setup action. The existing custodian consumes exact root approval;
 * installation must CAS independently verified predecessor/session/consent through the existing trust store.
 * Its transport result is re-read and checked before this closure can prepare or sign.
 */
export async function prepareConversationCustody02(options:ConversationCustodyOptions02){
 options={...options,history:options.history?{...options.history}:undefined};
 const binding=copy(options.binding);let archive=options.archivePrivateKey??null,lease=options.archiveLease??null;
 options={...options,archivePrivateKey:undefined,archiveLease:undefined};
 if(Boolean(archive)===Boolean(lease)){const held=lease;lease=null;archive=null;held?.close();throw Error("Exactly one existing archive custodian required");}
 if(archive&&(archive.type!=="private"||archive.extractable||archive.algorithm.name!=="ECDH"||(archive.algorithm as EcKeyAlgorithm).namedCurve!=="P-256"||!archive.usages.includes("deriveBits")))throw Error("Existing nonextractable archive reader required");
 let closed=false,busy=false,enrolled=false,lastNow=0n,lastVersion=0n,lastDigest:Uint8Array|null=null,root:Uint8Array|null=null,generation:bigint|null=null;
 let signer:Awaited<ReturnType<typeof prepareConversationSignerSetup02>>|null=null;
 type Signer=Awaited<ReturnType<typeof prepareConversationSignerSetup02>>;
 const history=new Map<string,Manifest02>();let reviews=new WeakMap<object,Awaited<ReturnType<Signer["prepareReview"]>>>(),expiryTimer:ReturnType<typeof setTimeout>|null=null;
 const closeListeners=new Set<()=>void>();let releaseLease:(()=>void)|null=null;
 const close=()=>{if(closed)return;closed=true;const held=lease;lease=null;archive=null;try{signer?.close();}finally{signer=null;try{held?.close();}finally{history.clear();reviews=new WeakMap();if(expiryTimer!==null)clearTimeout(expiryTimer);for(const cleanup of [()=>options.signal?.removeEventListener("abort",close),()=>releaseLease?.()])try{cleanup();}catch{}releaseLease=null;for(const listener of closeListeners)try{listener();}catch{}closeListeners.clear();}}};
 releaseLease=lease?.onClose(close)??null;
 if(options.signal?.aborted){close();throw Error("Custody setup closed");}options.signal?.addEventListener("abort",close,{once:true});
 async function current():Promise<ConversationSignerCurrent02>{
  if(closed)throw Error("Custody closed");
  const sampled=await options.readCurrent();
  if(closed||!sampled)throw Error("Custody authority lost");
  const value={...sampled,binding:copy(sampled.binding)};
  if(!value.ownerSessionLive||!value.consentLive||!equal(binding,value.binding)||value.nowMs<=0n||value.nowMs<lastNow)throw Error("Custody authority lost");
  const identity=verifiedManifestIdentity02(value.manifest,value.nowMs);
  if(!same(identity.accountId,binding.account)||(root&&(!same(root,identity.rootPoint)||generation!==identity.generation))||identity.version<lastVersion||(identity.version===lastVersion&&lastDigest&&!same(lastDigest,identity.digest)))throw Error("Custody trust changed");
  // Clone/reverify against the actual verifier high-water, insulating record readers from caller mutation.
  const manifest=await verifyManifest02(Uint8Array.from(value.manifest.bytes),verifiedManifestTrust02(value.manifest,value.nowMs),value.nowMs);
  if(closed)throw Error("Custody closed");
  if(options.history){const snapshot=await options.history.trustStore.read();if(closed||!snapshot||snapshot.trust.version!==identity.version||snapshot.trust.generation!==identity.generation||!same(snapshot.trust.accountId,identity.accountId)||!same(snapshot.trust.rootPoint,identity.rootPoint)||!same(snapshot.trust.digest,identity.digest))throw Error("Custody persisted authority changed");}
  const reader=manifest.keys.find(k=>k.role===2&&same(k.keyId,binding.archiveReader));
  if(!reader||reader.state!==1||!(reader.scope&8)||reader.fromMs>value.nowMs||value.nowMs>=reader.untilMs)throw Error("Custody reader revoked");
  if(enrolled){const key=manifest.keys.find(k=>k.role===5&&same(k.keyId,signer!.keyId));if(!key||key.state!==1||key.fromMs>value.nowMs||value.nowMs>=key.untilMs)throw Error("Custody signer expired or revoked");}
  if(lease)await lease.withKey(binding,async()=>{});if(closed)throw Error("Custody closed");root=identity.rootPoint;generation=identity.generation;lastNow=value.nowMs;lastVersion=identity.version;lastDigest=identity.digest;
  const digest=b64(identity.digest);if(!history.has(digest)&&history.size>=64)throw Error("Custody history full");history.set(digest,manifest);
  return {...value,binding:copy(binding),manifest};
 }
 const scopeFor=(value:ConversationSignerCurrent02):ConversationOwnerScope02=>Object.freeze({account:uuid(binding.account),session:uuid(binding.session),interval:uuid(binding.interval),device:uuid(binding.device),line:uuid(binding.line),generation:binding.generation.toString(),peer:binding.peer,reader:b64(binding.archiveReader),manifest:b64(verifiedManifestIdentity02(value.manifest,value.nowMs).digest)});
 async function selected(scope:ConversationOwnerScope02){const value=await current(),expected=scopeFor(value);if((Object.keys(expected) as (keyof ConversationOwnerScope02)[]).some(k=>scope[k]!==expected[k]))throw Error("Custody selection changed");return value;}
 async function operation<T>(run:()=>Promise<T>):Promise<T>{if(closed||busy)throw Error("Custody unavailable");busy=true;try{return await run();}catch(e){close();throw e;}finally{busy=false;}}
 try {
  signer=await prepareConversationSignerSetup02(binding,options.consumeSetupDecision,current);
  if(closed){signer.close();signer=null;throw Error("Custody setup closed");}
  const accepted=await createConversationEnrollment02(binding,signer.publicPoint,current,options.consumeOwnerDecision,options.signWithExistingRoot,options.installVerified).enroll();
  const installed=await current();
  if(!same(verifiedManifestIdentity02(installed.manifest,installed.nowMs).digest,accepted.digest))throw Error("Enrollment not authoritatively installed");
  const key=installed.manifest.keys.find(k=>k.role===5&&same(k.keyId,signer!.keyId));if(!key)throw Error("Enrolled signer unavailable");
  enrolled=true;
  const remaining=key.untilMs-installed.nowMs;if(remaining<=0n||remaining>1800000n)throw Error("Custody lifetime invalid");
  expiryTimer=setTimeout(close,Number(remaining));
  return Object.freeze({close,onClose:(listener:()=>void)=>{if(closed)listener();else closeListeners.add(listener);return()=>{closeListeners.delete(listener);};},
   authority:()=>operation(async()=>{const value=await current(),key=value.manifest.keys.find(k=>k.role===5&&same(k.keyId,signer!.keyId));if(!key||key.state!==1||value.nowMs>=key.untilMs)throw Error("Custody signer expired");return Object.freeze({phase:"active",scope:scopeFor(value),validForMs:Number(key.untilMs-value.nowMs>60000n?60000n:key.untilMs-value.nowMs)});}),
   prepare:(scope:ConversationOwnerScope02,body:string)=>operation(async()=>{await selected(scope);const review=await signer!.prepareReview(body);await selected(scope);const ticket=Object.freeze({});reviews.set(ticket,review);return ticket;}),
   signReviewed:(ticket:object,scope:ConversationOwnerScope02,body:string)=>operation(async()=>{const review=reviews.get(ticket);reviews.delete(ticket);if(!review||review.body!==body)throw Error("Custody review unavailable");await selected(scope);const signature=await signer!.signReviewed(review.proof,review.envelope,body,options.consumeConfirmation);await selected(scope);return Object.freeze({envelope:b64(review.envelope),confirmation:b64(review.proof),signature:b64(signature)});}),
   openSealed:(bytes:Uint8Array,scope:ConversationOwnerScope02)=>{const owned=Uint8Array.from(bytes);return operation(async()=>{const value=await selected(scope),parsed=parseConversationInbound02(owned);let historic=history.get(b64(parsed.manifestDigest));if(!historic&&options.history){if(options.history.loadChain){const chain=await options.history.loadChain(Uint8Array.from(parsed.manifestDigest),Uint8Array.from(value.manifest.digest));historic=await options.history.trustStore.verifyHistory(chain,parsed.observedMs);}else historic=await options.history.trustStore.verifyStoredHistory(parsed.manifestDigest,parsed.observedMs);await selected(scope);}if(!historic||!same(historic.digest,parsed.manifestDigest))throw Error("Accepted history provenance unavailable");const open=(key:CryptoKey)=>openConversationInbound02(owned,{...binding,archivePrivateKey:key,historical:historic!,current:value.manifest,nowMs:value.nowMs});const text=lease?await lease.withKey(binding,open):await open(archive!);await selected(scope);return text;});}
  });
 }catch(e){close();throw e;}
}
