// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant opaque template persistence. No login, keys, plaintext or sending. */
import {authorizeWorkflowContext02,verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02,type Manifest02} from './draft02-manifest.js';
import type {ConversationSignerBinding02,ConversationSignerCurrent02} from './conversation-signer.js';
import {encryptedTemplateAad,encryptedTemplateDigest,type EncryptedTemplateScope} from './encrypted-template.js';
import {templateSaveRequest,templateSaveReceipt,type TemplateSaveRequest} from './template-store-contract.js';

export type TemplateOwnerCurrent = ConversationSignerCurrent02 & Readonly<{phase:'active';validForMs:number}>;
export type TemplateSaveInput = Readonly<{requestId:string;expectedRevision:number;scope:EncryptedTemplateScope;envelope:Uint8Array}>;
export type TemplateCiphertextReview = Readonly<{requestId:string;expectedRevision:number;scope:EncryptedTemplateScope;encryptedDigest:string}>;
export type TemplatePending = Readonly<{requestId:string;templateId:string;revision:number;encryptedDigest:string}>;
export type TemplateTicket = object;
export type TemplateSaveAcknowledgement = TemplatePending & Readonly<{state:'acknowledged_saved_revision'}>;
export type TemplateSnapshot = Readonly<{state:'verified_current_snapshot';requestAcknowledged:false;scope:EncryptedTemplateScope;envelope:Uint8Array;encryptedDigest:string;matchesPending:boolean}>;
export interface OwnerEncryptedTemplateOptions {
 enabled?:boolean;origin:string;binding:ConversationSignerBinding02;templateId:Uint8Array;
 readCurrent:()=>Promise<TemplateOwnerCurrent|null>;currentCsrf:()=>string|Promise<string>;
 consumeCiphertextReview:(review:TemplateCiphertextReview)=>Promise<void>;
 signal:AbortSignal;timeoutMs?:number;fetchImpl?:typeof fetch;
}
export class OwnerTemplateError extends Error {
 constructor(readonly code:string,readonly state:'refused'|'unknown') {super(`Owner template ${code}`);this.name='OwnerTemplateError';}
}
const maximum=(1n<<63n)-1n,maxEnvelope=33075,contentType='application/vnd.zrotext.workflow-template.v1';
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hex=(b:Uint8Array)=>Array.from(b,n=>n.toString(16).padStart(2,'0')).join('');
const uuid=(b:Uint8Array)=>{const s=hex(b);return `${s.slice(0,8)}-${s.slice(8,12)}-${s.slice(12,16)}-${s.slice(16,20)}-${s.slice(20)}`;};
function refuse():never {throw new OwnerTemplateError('invalid_request','refused');}
function record(input:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,any>{
 if(!input||Object.getPrototypeOf(input)!==Object.prototype)refuse();
 const result:Record<string,any>={},allowed=new Set([...required,...optional]);
 for(const key of Reflect.ownKeys(input)){if(typeof key!=='string'||!allowed.has(key))refuse();const d=Object.getOwnPropertyDescriptor(input,key)!;if(!Object.hasOwn(d,'value'))refuse();result[key]=d.value;}
 if(required.some(k=>!Object.hasOwn(result,k)))refuse();return result;
}
function bytes(input:unknown,size:number):Uint8Array {if(!(input instanceof Uint8Array)||input.length!==size||!input.some(v=>v!==0))refuse();return Uint8Array.from(input);}
const bindingFields=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'] as const;
function binding(input:unknown):ConversationSignerBinding02{
 const b=record(input,bindingFields);for(const n of ['account','device','line','interval','session'])b[n]=bytes(b[n],16);for(const n of ['phoneReader','archiveReader'])b[n]=bytes(b[n],32);
 if(typeof b.generation!=='bigint'||b.generation<1n||b.generation>maximum||typeof b.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))refuse();return b as ConversationSignerBinding02;
}
function sameBinding(a:ConversationSignerBinding02,b:ConversationSignerBinding02):boolean{return a.generation===b.generation&&a.peer===b.peer&&['account','device','line','interval','session','phoneReader','archiveReader'].every(k=>equal(a[k as 'account'],b[k as 'account']));}
const scopeFields=['accountId','deviceId','lineId','intervalId','templateId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'] as const;
function scope(input:unknown):EncryptedTemplateScope{
 const s=record(input,scopeFields);for(const n of ['accountId','deviceId','lineId','intervalId','templateId'])s[n]=bytes(s[n],16);for(const n of ['peerDigest','readerId','manifestDigest'])s[n]=bytes(s[n],32);
 for(const n of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])if(typeof s[n]!=='bigint'||s[n]<1n||s[n]>maximum)refuse();encryptedTemplateAad(s as EncryptedTemplateScope);return s as EncryptedTemplateScope;
}
function parse(envelope:Uint8Array):EncryptedTemplateScope{
 if(envelope.length<308||envelope.length>maxEnvelope||!equal(envelope.slice(0,6),Uint8Array.of(90,84,87,84,1,1))||envelope[222]!==4)refuse();
 const v=new DataView(envelope.buffer,envelope.byteOffset,envelope.byteLength);if(v.getUint32(287)!==envelope.length-291)refuse();
 return scope({accountId:envelope.slice(6,22),deviceId:envelope.slice(22,38),lineId:envelope.slice(38,54),intervalId:envelope.slice(54,70),templateId:envelope.slice(70,86),bindingGeneration:v.getBigUint64(86),revision:v.getBigUint64(94),expiresMs:v.getBigUint64(102),trustGeneration:v.getBigUint64(110),manifestVersion:v.getBigUint64(118),peerDigest:envelope.slice(126,158),readerId:envelope.slice(158,190),manifestDigest:envelope.slice(190,222)});
}
interface Saved {ticket:object;requestId:string;scope:EncryptedTemplateScope;request:TemplateSaveRequest;csrf:string;deadline:number;attempts:number;verifies:number;unknown:boolean;timer?:ReturnType<typeof setTimeout>}

/** Explicit trusted owner host; the relay remains the authority for persistence. */
export class OwnerEncryptedTemplateClient {
 #options:OwnerEncryptedTemplateOptions;#binding:ConversationSignerBinding02;#template:Uint8Array;#fetch:typeof fetch;#timeout:number;
 #closed=false;#busy=false;#controller=new AbortController();#saved:Saved|null=null;#pending:TemplatePending|null=null;
 #root:Uint8Array|null=null;#generation=0n;#version=0n;#digest:Uint8Array|null=null;#now=0n;#head=0n;#headDigest:string|null=null;
 constructor(input:OwnerEncryptedTemplateOptions){
  const o=record(input,['origin','binding','templateId','readCurrent','currentCsrf','consumeCiphertextReview','signal'],['enabled','timeoutMs','fetchImpl']);
  let url:URL;try{url=new URL(o.origin);}catch{refuse();}
  if(url.protocol!=='https:'||url.origin!==o.origin||url.username||url.password||url.search||url.hash||!['readCurrent','currentCsrf','consumeCiphertextReview'].every(k=>typeof o[k]==='function')||!(o.signal instanceof AbortSignal)||o.fetchImpl!==undefined&&typeof o.fetchImpl!=='function'||o.enabled!==undefined&&typeof o.enabled!=='boolean')refuse();
  this.#timeout=o.timeoutMs??10000;if(!Number.isSafeInteger(this.#timeout)||this.#timeout<1||this.#timeout>10000)refuse();
  this.#options={...o} as OwnerEncryptedTemplateOptions;this.#binding=binding(o.binding);this.#template=bytes(o.templateId,16);this.#fetch=o.fetchImpl??globalThis.fetch.bind(globalThis);
  o.signal.addEventListener('abort',this.#abort,{once:true});if(o.enabled!==true||o.signal.aborted)this.close();
 }
 #abort=()=>this.close();
 close():void {this.#closed=true;this.#controller.abort();this.#options.signal.removeEventListener('abort',this.#abort);if(this.#saved){clearTimeout(this.#saved.timer);this.#saved.request.body.fill(0);this.#saved=null;}}
 pending():TemplatePending|null{return this.#pending?Object.freeze({...this.#pending}):null;}
 #live(deadline:number):void {if(this.#closed||this.#options.signal.aborted)throw new OwnerTemplateError('closed',this.#pending?'unknown':'refused');if(performance.now()>=deadline){this.close();throw new OwnerTemplateError('deadline',this.#pending?'unknown':'refused');}}
 async #wait<T>(value:Promise<T>|T,deadline:number):Promise<T>{
  const observed=Promise.resolve(value);let timer:ReturnType<typeof setTimeout>|undefined,abort=()=>{};
  try{this.#live(deadline);}catch(error){void observed.catch(()=>{});throw error;}
  try{return await Promise.race([observed,new Promise<never>((_,reject)=>{abort=()=>reject(new OwnerTemplateError('closed',this.#pending?'unknown':'refused'));this.#controller.signal.addEventListener('abort',abort,{once:true});timer=setTimeout(()=>{reject(new OwnerTemplateError('deadline',this.#pending?'unknown':'refused'));this.close();},Math.max(0,deadline-performance.now()));})]);}
  finally{if(timer!==undefined)clearTimeout(timer);this.#controller.signal.removeEventListener('abort',abort);}
 }
 async #csrf(deadline:number):Promise<string>{const value=await this.#wait(this.#options.currentCsrf(),deadline);this.#live(deadline);if(typeof value!=='string'||value.length<1||value.length>256||/[^\x21-\x7e]/.test(value))refuse();return value;}
 async #current(s:EncryptedTemplateScope|null,deadline:number,csrf:string):Promise<number>{
  this.#live(deadline);const started=performance.now();
  try{
   const c=record(await this.#wait(this.#options.readCurrent(),deadline),['binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs']);this.#live(deadline);
   const selected=binding(c.binding);if(!sameBinding(selected,this.#binding)||c.ownerSessionLive!==true||c.consentLive!==true||c.phase!=='active'||typeof c.nowMs!=='bigint'||c.nowMs<1n||c.nowMs<this.#now||!Number.isFinite(c.validForMs)||c.validForMs<=0||c.validForMs>60000)refuse();
   // Identity and trust are obtained from opaque SDK verification, not public fields.
   const identity=verifiedManifestIdentity02(c.manifest,c.nowMs),trust=verifiedManifestTrust02(c.manifest,c.nowMs);
   const manifest:Manifest02=await this.#wait(verifyManifest02(Uint8Array.from(c.manifest.bytes),trust,c.nowMs),deadline);this.#live(deadline);
   const id=verifiedManifestIdentity02(manifest,c.nowMs);
   if(!equal(identity.digest,id.digest)||!equal(id.accountId,this.#binding.account)||this.#root&&(!equal(this.#root,id.rootPoint)||id.generation!==this.#generation)||id.version<this.#version||id.version===this.#version&&this.#digest&&!equal(id.digest,this.#digest))refuse();
   const reader=this.#binding.archiveReader;
   authorizeWorkflowContext02(manifest,{accountId:Uint8Array.from(this.#binding.account),deviceId:Uint8Array.from(this.#binding.device),lineId:Uint8Array.from(this.#binding.line),readerId:Uint8Array.from(reader),generation:id.generation,version:id.version,digest:Uint8Array.from(id.digest)},c.nowMs);
   if(s){
    const b=this.#binding;for(const [n,k] of [['accountId','account'],['deviceId','device'],['lineId','line'],['intervalId','interval'],['readerId','archiveReader']] as const)if(!equal(s[n],b[k]))refuse();
    if(!equal(s.templateId,this.#template)||s.bindingGeneration!==b.generation||s.trustGeneration!==id.generation||s.manifestVersion!==id.version||!equal(s.manifestDigest,id.digest)||s.expiresMs<=c.nowMs||s.expiresMs-c.nowMs>30n*86400000n)refuse();
    const peer=new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer)),deadline));if(!equal(peer,s.peerDigest))refuse();
   }
   const role2=manifest.keys.find(k=>k.role===2&&equal(k.keyId,reader))!,phone=manifest.keys.find(k=>k.role===4&&k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs&&equal(k.deviceId,this.#binding.device)&&equal(k.lineId,this.#binding.line))!;
   const expiry=[manifest.expiresMs,role2.untilMs,phone.untilMs,...(s?[s.expiresMs]:[])].reduce((a,b)=>a<b?a:b);
   const shortened=Math.min(deadline,started+c.validForMs,started+Number(expiry-c.nowMs));this.#live(shortened);
   if(await this.#csrf(shortened)!==csrf)refuse();this.#live(shortened);
   this.#root=Uint8Array.from(id.rootPoint);this.#generation=id.generation;this.#version=id.version;this.#digest=Uint8Array.from(id.digest);this.#now=c.nowMs;return shortened;
  }catch{this.close();throw new OwnerTemplateError('owner_changed',this.#pending?'unknown':'refused');}
 }
 #identity(r:Saved):TemplatePending{return Object.freeze({requestId:r.requestId,templateId:uuid(r.scope.templateId),revision:Number(r.scope.revision),encryptedDigest:r.request.encryptedDigest});}
 #deadline(r:Saved,deadline:number):void{this.#live(deadline);if(deadline>r.deadline)refuse();clearTimeout(r.timer);r.deadline=deadline;r.timer=setTimeout(()=>this.close(),Math.max(0,deadline-performance.now()));}
 #forget(r:Saved):void{clearTimeout(r.timer);r.request.body.fill(0);if(this.#saved===r)this.#saved=null;this.#pending=null;}
 #ticket(ticket:object):Saved{if(this.#busy)throw new OwnerTemplateError('busy','refused');this.#live(this.#saved?.deadline??0);const r=this.#saved;if(!r||r.ticket!==ticket)refuse();return r;}
 async prepareSave(input:TemplateSaveInput):Promise<TemplateTicket>{
  if(this.#busy||this.#saved||this.#pending)throw new OwnerTemplateError('pending_write','refused');const deadline=performance.now()+this.#timeout;this.#live(deadline);
  this.#busy=true;let r:Saved|undefined,envelope:Uint8Array|undefined;
  try{
   const d=record(input,['requestId','expectedRevision','scope','envelope']),s=scope(d.scope);if(!(d.envelope instanceof Uint8Array)||d.envelope.length<308||d.envelope.length>maxEnvelope)refuse();envelope=Uint8Array.from(d.envelope);parse(envelope);if(!equal(encryptedTemplateAad(s),envelope.slice(0,222)))refuse();
   const request=await this.#wait(templateSaveRequest(s,d.requestId,d.expectedRevision,envelope),deadline);this.#live(deadline);const csrf=await this.#csrf(deadline);
   r={ticket:Object.freeze({}),requestId:d.requestId,scope:s,request,csrf,deadline,attempts:0,verifies:0,unknown:false};this.#saved=r;this.#deadline(r,await this.#current(s,deadline,csrf));
   await this.#wait(crypto.subtle.importKey('raw',Uint8Array.from(envelope.slice(222,287)).buffer,{name:'ECDH',namedCurve:'P-256'},false,[]),r.deadline);
   await this.#wait(this.#options.consumeCiphertextReview(Object.freeze({requestId:r.requestId,expectedRevision:d.expectedRevision,scope:scope(s),encryptedDigest:request.encryptedDigest})),r.deadline);
   this.#deadline(r,await this.#current(s,r.deadline,csrf));return r.ticket;
  }catch(error){if(r)this.#forget(r);if(error instanceof OwnerTemplateError)throw error;throw new OwnerTemplateError('invalid_request','refused');}finally{envelope?.fill(0);this.#busy=false;}
 }
 async #body(response:Response,limit:number,deadline:number):Promise<Uint8Array>{
  const reader=response.body?.getReader();if(!reader)throw new OwnerTemplateError('response_unknown','unknown');let size=0;const chunks:Uint8Array[]=[];
  try{for(;;){const next=await this.#wait(reader.read(),deadline);this.#live(deadline);if(next.done)break;if(!(next.value instanceof Uint8Array)||size+next.value.length>limit)throw new OwnerTemplateError('response_unknown','unknown');size+=next.value.length;chunks.push(Uint8Array.from(next.value));}const out=new Uint8Array(size);let at=0;for(const b of chunks){out.set(b,at);at+=b.length;}return out;}
  finally{void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{/* Late stream results cannot publish. */}}
 }
 async #response(post:boolean,deadline:number,csrf:string,r?:Saved):Promise<Response>{
  this.#live(deadline);if(await this.#csrf(deadline)!==csrf){this.close();throw new OwnerTemplateError('owner_changed',this.#pending?'unknown':'refused');}this.#live(deadline);
  const url=this.#options.origin+'/v1/owner/workflow/templates'+(post?'':'/'+uuid(this.#template));
  const response=await this.#wait(this.#fetch(url,{method:post?'POST':'GET',credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:this.#controller.signal,headers:{Accept:post?'application/json':contentType,'x-zrotext-csrf':csrf,...(post?r!.request.headers:{})},...(post?{body:Uint8Array.from(r!.request.body).buffer}:{})}),deadline);this.#live(deadline);
  if(response.redirected||response.url&&response.url!==url){void response.body?.cancel().catch(()=>{});throw new OwnerTemplateError('response_unknown','unknown');}return response;
 }
 async #post(ticket:TemplateTicket,retry:boolean):Promise<TemplateSaveAcknowledgement>{
  const r=this.#ticket(ticket);if(retry?!r.unknown:r.attempts!==0)refuse();if(r.attempts>=3)throw new OwnerTemplateError('attempts_exhausted',r.unknown?'unknown':'refused');this.#busy=true;const wasUnknown=r.unknown;let attempted=false;
  try{
   this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));this.#live(r.deadline);r.attempts++;r.unknown=true;attempted=true;this.#pending=this.#identity(r);
   const response=await this.#response(true,r.deadline,r.csrf,r);
   if([400,401,403,404,409,413,429].includes(response.status)){void response.body?.cancel().catch(()=>{});
    // A browser may invisibly retry a committed request before this refusal.
    // Retain unknown metadata even on the first explicit fetch. Auth refusals
    // also destroy the live retry capability and invalidate this host lifetime.
    if(response.status===401||response.status===403)this.close();throw new OwnerTemplateError('response_unknown','unknown');}
   if(response.status!==200||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')){void response.body?.cancel().catch(()=>{});throw new OwnerTemplateError('response_unknown','unknown');}
   const body=await this.#body(response,256,r.deadline);templateSaveReceipt(r.request,body);if(new TextDecoder('utf-8',{fatal:true}).decode(body)!==JSON.stringify({revision:r.request.revision}))throw new OwnerTemplateError('response_unknown','unknown');
   this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));
   // The existing backend has immutable revisions. Contradictory observations
   // cannot acknowledge this request or overwrite an already observed digest.
   if(r.scope.revision===this.#head&&this.#headDigest!==null&&r.request.encryptedDigest!==this.#headDigest)throw new OwnerTemplateError('response_unknown','unknown');
   const acknowledgement=Object.freeze({...this.#identity(r),state:'acknowledged_saved_revision' as const});
   if(r.scope.revision>=this.#head){this.#head=r.scope.revision;this.#headDigest=r.request.encryptedDigest;}this.#forget(r);return acknowledgement;
  }catch(error){if(error instanceof OwnerTemplateError&&error.state==='refused'&&!this.#pending&&this.#saved!==r)throw error;if(attempted||wasUnknown)throw new OwnerTemplateError('response_unknown','unknown');if(error instanceof OwnerTemplateError)throw error;throw new OwnerTemplateError('save_refused','refused');}finally{this.#busy=false;}
 }
 commit(ticket:TemplateTicket):Promise<TemplateSaveAcknowledgement>{return this.#post(ticket,false);}
 retryUnknown(ticket:TemplateTicket):Promise<TemplateSaveAcknowledgement>{return this.#post(ticket,true);}
 async #latest(r?:Saved):Promise<TemplateSnapshot>{
  let deadline=r?.deadline??performance.now()+this.#timeout;this.#live(deadline);const csrf=r?.csrf??await this.#csrf(deadline);deadline=await this.#current(null,deadline,csrf);if(r)this.#deadline(r,deadline);
  const response=await this.#response(false,deadline,csrf);
  if(response.status!==200||response.headers.get('content-type')!==contentType){void response.body?.cancel().catch(()=>{});if(response.status===401||response.status===403)this.close();throw new OwnerTemplateError('read_refused',this.#pending?'unknown':'refused');}
  const envelope=await this.#body(response,maxEnvelope,deadline);this.#live(deadline);const s=parse(envelope);if(s.revision<this.#head)throw new OwnerTemplateError('head_regressed',this.#pending?'unknown':'refused');
  deadline=await this.#current(s,deadline,csrf);if(r)this.#deadline(r,deadline);
  await this.#wait(crypto.subtle.importKey('raw',Uint8Array.from(envelope.slice(222,287)).buffer,{name:'ECDH',namedCurve:'P-256'},false,[]),deadline);
  const digest=hex(await this.#wait(encryptedTemplateDigest(envelope),deadline));deadline=await this.#current(s,deadline,csrf);if(r)this.#deadline(r,deadline);this.#live(deadline);
  if(s.revision===this.#head&&this.#headDigest!==null&&digest!==this.#headDigest)throw new OwnerTemplateError('head_changed',this.#pending?'unknown':'refused');
  this.#head=s.revision;this.#headDigest=digest;return Object.freeze({state:'verified_current_snapshot',requestAcknowledged:false,scope:scope(s),envelope:Uint8Array.from(envelope),encryptedDigest:digest,matchesPending:!!r&&equal(envelope,r.request.body)});
 }
 async readLatest():Promise<TemplateSnapshot>{if(this.#busy)throw new OwnerTemplateError('busy','refused');if(this.#saved?.unknown)return this.verifyUnknown(this.#saved.ticket);this.#busy=true;try{return await this.#latest(this.#saved??undefined);}catch(error){if(error instanceof OwnerTemplateError)throw error;throw new OwnerTemplateError('read_refused',this.#pending?'unknown':'refused');}finally{this.#busy=false;}}
 async verifyUnknown(ticket:TemplateTicket):Promise<TemplateSnapshot>{const r=this.#ticket(ticket);if(!r.unknown)refuse();if(r.verifies>=3)throw new OwnerTemplateError('attempts_exhausted','unknown');this.#busy=true;r.verifies++;try{return await this.#latest(r);}catch{throw new OwnerTemplateError('response_unknown','unknown');}finally{this.#busy=false;}}
}
