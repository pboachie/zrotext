// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant session-lifetime role-5 signer. No endpoint, persistence or automatic enrollment. */
import {prepareOutboundEnvelope02} from "./draft02-envelope-prep.js";
import {authorizeOutbound02,browserSignerKeyId02,canonicalSignature02,verifiedManifestIdentity02,type Manifest02} from "./draft02-manifest.js";
export type ConversationSignerBinding02=Readonly<{account:Uint8Array;device:Uint8Array;line:Uint8Array;interval:Uint8Array;session:Uint8Array;generation:bigint;peer:string;phoneReader:Uint8Array;archiveReader:Uint8Array}>;
/** Mandatory current source supplies authenticated UTC advanced monotonically; wall time alone is invalid. */
export type ConversationSignerCurrent02=Readonly<{binding:ConversationSignerBinding02;manifest:Manifest02;nowMs:bigint;ownerSessionLive:boolean;consentLive:boolean}>;
const enc=new TextEncoder(),max=(1n<<63n)-1n;
const ab=(v:Uint8Array):ArrayBuffer=>Uint8Array.from(v).buffer;
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const join=(...parts:Uint8Array[])=>{const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;};
const hash=async(v:Uint8Array)=>new Uint8Array(await crypto.subtle.digest("SHA-256",ab(v)));
const byteFields=["account","device","line","interval","session","phoneReader","archiveReader"] as const;
function own(b:ConversationSignerBinding02):ConversationSignerBinding02 {
 const value={...b,account:Uint8Array.from(b.account),device:Uint8Array.from(b.device),line:Uint8Array.from(b.line),interval:Uint8Array.from(b.interval),session:Uint8Array.from(b.session),phoneReader:Uint8Array.from(b.phoneReader),archiveReader:Uint8Array.from(b.archiveReader)};
 if(byteFields.some(k=>value[k].length!==(k.endsWith("Reader")?32:16)||value[k].every(n=>n===0))||b.generation<=0n||b.generation>max||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))throw Error("Signer binding");
 return value;
}
const equal=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&byteFields.every(k=>same(a[k],b[k]));
function bodyBytes(text:string){
 for(let i=0;i<text.length;i++){const c=text.charCodeAt(i);if(c>=0xd800&&c<=0xdbff){const n=text.charCodeAt(++i);if(!(n>=0xdc00&&n<=0xdfff))throw Error("Invalid UTF-8 body");}else if(c>=0xdc00&&c<=0xdfff)throw Error("Invalid UTF-8 body");}
 const bytes=enc.encode(text);if(bytes.length<1||bytes.length>32768||text.startsWith("\uFEFF")||text.includes("\0"))throw Error("Invalid body");return bytes;
}
/** Mandatory UI decision consumers bind exact setup selection and exact reviewed content. */
export async function prepareConversationSignerSetup02(input:ConversationSignerBinding02,
 consumeSetupDecision:(binding:ConversationSignerBinding02)=>Promise<void>,
 readCurrent:()=>Promise<ConversationSignerCurrent02|null>) {
 const binding=own(input);let closed=false,busy=false,lastNow=0n;
 let setupGeneration:bigint|null=null,setupRoot:Uint8Array|null=null,lastVersion=0n,lastManifest:Uint8Array|null=null;
 const used=new Set<string>();let pair:CryptoKeyPair|null=null;
 async function live(){
  if(closed)throw Error("Signer closed");const value=await readCurrent();
  if(closed||!value||!value.ownerSessionLive||!value.consentLive||!equal(binding,own(value.binding)))throw Error("Signer authority unavailable");
  const identity=verifiedManifestIdentity02(value.manifest,value.nowMs);
  if(!same(identity.accountId,binding.account)||value.nowMs<=0n||value.nowMs<lastNow)throw Error("Signer authority changed");
  if(setupGeneration!==null&&(setupGeneration!==identity.generation||!same(setupRoot!,identity.rootPoint)))throw Error("Signer root changed");
  if(identity.version<lastVersion||(identity.version===lastVersion&&lastManifest!==null&&!same(lastManifest,identity.digest)))throw Error("Signer manifest regressed");
  setupGeneration=identity.generation;setupRoot=Uint8Array.from(identity.rootPoint);lastVersion=identity.version;lastManifest=Uint8Array.from(identity.digest);
  lastNow=value.nowMs;return {...value,identity};
 }
 try {
  await consumeSetupDecision(own(binding));await live();
  pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]);await live();
  if(pair.privateKey.extractable)throw Error("Exportable signer");
  const point=new Uint8Array(await crypto.subtle.exportKey("raw",pair.publicKey)),keyId=await browserSignerKeyId02(point);
  async function prepareReview(text:string) {
   if(closed||busy)throw Error("Signer unavailable");busy=true;
   let bytes:Uint8Array|null=null,cek:Uint8Array|null=null,nonce:Uint8Array|null=null;
   try {
    bytes=bodyBytes(text);cek=crypto.getRandomValues(new Uint8Array(32));nonce=crypto.getRandomValues(new Uint8Array(12));
    const current=await live(),message=crypto.getRandomValues(new Uint8Array(16));message[6]=(message[6]&15)|64;message[8]=(message[8]&63)|128;
    const expiry=current.nowMs+30000n;if(expiry>max)throw Error("Time overflow");
    const selected=[{role:1 as const,keyId:binding.phoneReader},{role:2 as const,keyId:binding.archiveReader}];
    authorizeOutbound02(current.manifest,{accountId:binding.account,deviceId:binding.device,lineId:binding.line,manifestDigest:current.identity.digest,keysetVersion:current.identity.version,signerKeyId:keyId,wraps:selected},current.nowMs);
    const recipients=selected.map(selection=>{const record=current.manifest.keys.find(k=>k.role===selection.role&&same(k.keyId,selection.keyId));if(!record)throw Error("Reader unavailable");return {...selection,point:Uint8Array.from(record.point),ekm:crypto.getRandomValues(new Uint8Array(32))};});
    const key=pair?.privateKey;if(!key)throw Error("Signer closed");
    let envelope:Uint8Array;
    try {const prepared=await prepareOutboundEnvelope02({kind:1,manifest:current.manifest,nowMs:current.nowMs,messageId:message,deviceId:binding.device,lineId:binding.line,peer:enc.encode(binding.peer),observedMs:current.nowMs,expiresMs:expiry,content:text,cek,nonce,signer:{privateKey:key,publicPoint:point},recipients});envelope=prepared.envelope;}
    finally {for(const recipient of recipients)recipient.ekm.fill(0);}
    const final=await live();if(final.identity.generation!==current.identity.generation||final.identity.version!==current.identity.version||!same(final.identity.digest,current.identity.digest)||final.nowMs>=expiry)throw Error("Review authority changed");
    const u64=(n:bigint)=>{const out=new Uint8Array(8);new DataView(out.buffer).setBigUint64(0,n);return out;};
    const peer=enc.encode(binding.peer);
    const proof=join(Uint8Array.of(90,84,67,83,1),binding.account,binding.device,binding.line,binding.interval,binding.session,message,u64(binding.generation),u64(current.identity.generation),u64(current.identity.version),u64(expiry),Uint8Array.of(peer.length),peer,keyId,binding.archiveReader,current.identity.digest,await hash(envelope),await hash(bytes));
    const latest=await live();if(latest.identity.generation!==current.identity.generation||latest.identity.version!==current.identity.version||!same(latest.identity.digest,current.identity.digest)||latest.nowMs>=expiry)throw Error("Review authority changed");
    return Object.freeze({proof:Uint8Array.from(proof),envelope:Uint8Array.from(envelope),body:text,messageId:Uint8Array.from(message)});
   } catch(error){closed=true;pair=null;throw error;} finally {bytes?.fill(0);cek?.fill(0);nonce?.fill(0);busy=false;}
  }
  return Object.freeze({prepareReview,publicPoint:Uint8Array.from(point),keyId:Uint8Array.from(keyId),close:()=>{closed=true;pair=null;},
   signReviewed:async(proofInput:Uint8Array,envelopeInput:Uint8Array,text:string,consumeConfirmation:(proofDigest:Uint8Array,bodyDigest:Uint8Array)=>Promise<void>)=>{
    if(closed||busy)throw Error("Signer unavailable");busy=true;
    const proof=Uint8Array.from(proofInput),envelope=Uint8Array.from(envelopeInput);
    let body:Uint8Array|null=null;
    try {
     body=bodyBytes(text);
     if(proof.length<297||proof.length>310||!same(proof.subarray(0,5),Uint8Array.of(90,84,67,83,1)))throw Error("Confirmation shape");
     const ids=[binding.account,binding.device,binding.line,binding.interval,binding.session];for(let i=0;i<ids.length;i++)if(!same(proof.subarray(5+i*16,21+i*16),ids[i]))throw Error("Confirmation scope");
     if(proof.subarray(85,101).every(v=>v===0))throw Error("Confirmation message");
     const view=new DataView(proof.buffer,proof.byteOffset,proof.byteLength),generation=view.getBigUint64(101),trust=view.getBigUint64(109),version=view.getBigUint64(117),expiry=view.getBigUint64(125),length=proof[133];
     if(generation!==binding.generation||[trust,version,expiry].some(v=>v<=0n||v>max)||length<3||length>16||proof.length!==294+length||!same(proof.subarray(134,134+length),enc.encode(binding.peer)))throw Error("Confirmation selection");
     let at=134+length;const signer=proof.subarray(at,at+=32),reader=proof.subarray(at,at+=32),manifest=proof.subarray(at,at+=32),envelopeDigest=proof.subarray(at,at+=32),bodyDigest=proof.subarray(at,at+32);
     if(!same(signer,keyId)||!same(reader,binding.archiveReader)||envelope.length<426||envelope.length>34213||!same(await hash(envelope),envelopeDigest)||!same(await hash(body),bodyDigest))throw Error("Confirmation content");
     const digest=await hash(proof),identity=Array.from(digest).join(",");if(used.has(identity)||used.size>=1024)throw Error("Confirmation already consumed or full");
     used.add(identity);await consumeConfirmation(Uint8Array.from(digest),Uint8Array.from(bodyDigest));
     function authorize(value:Awaited<ReturnType<typeof live>>){
      if(value.identity.generation!==trust||value.identity.version!==version||!same(value.identity.digest,manifest)||value.nowMs>=expiry||expiry-value.nowMs>30000n)throw Error("Confirmation expired or authority changed");
      authorizeOutbound02(value.manifest,{accountId:binding.account,deviceId:binding.device,lineId:binding.line,manifestDigest:manifest,keysetVersion:version,signerKeyId:keyId,wraps:[{role:1,keyId:binding.phoneReader},{role:2,keyId:binding.archiveReader}]},value.nowMs);
     }
     authorize(await live());const size=new Uint8Array(4);new DataView(size.buffer).setUint32(0,proof.length);
     const key=pair?.privateKey;if(!key)throw Error("Signer closed");
     const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,ab(join(enc.encode("zrotext/conversation/confirm-send/v1\0"),size,proof)))));
     authorize(await live());return signature;
    } catch(error){closed=true;pair=null;throw error;} finally {body?.fill(0);busy=false;}
   }});
 } catch(error){closed=true;pair=null;throw error;}
}
