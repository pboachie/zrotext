// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant, exclusive local draft review and encryption. Never commits or sends. */
import {authorizeWorkflowContext02,verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02,type Manifest02} from './draft02-manifest.js';
import {encryptedTemplateAad,previewEncryptedTemplate,sealEncryptedTemplate,type EncryptedTemplateScope,type TemplateContent} from './encrypted-template.js';
import {canonicalTemplateBytes,validateValues} from './template-contract.js';
import {OwnerEncryptedTemplateClient,type OwnerEncryptedTemplateOptions,type TemplateTicket} from './owner-encrypted-template-client.js';
import type {ConversationSignerBinding02} from './conversation-signer.js';
const prepareSave=OwnerEncryptedTemplateClient.prototype.prepareSave;
const closePersistence=OwnerEncryptedTemplateClient.prototype.close;
const pendingPersistence=OwnerEncryptedTemplateClient.prototype.pending;

export type TemplateDraftState=Readonly<{epoch:bigint;revision:bigint;custodyLive:boolean}>;
export type TemplateAuthoringInput=TemplateContent & Readonly<{requestId:string;expectedRevision:number;scope:EncryptedTemplateScope;epoch:bigint;draftRevision:bigint}>;
export type TemplateDraftReview=TemplateAuthoringInput & Readonly<{preview:ReturnType<typeof previewEncryptedTemplate>}>;
export type TemplateAuthoringOptions=OwnerEncryptedTemplateOptions & Readonly<{
 readDraftState:()=>Promise<TemplateDraftState|null>;
 /** Consume a local owner decision for this exact copied draft. Only true accepts. */
 consumeDraftReview:(review:TemplateDraftReview)=>Promise<boolean>;
}>;
export class TemplateAuthoringError extends Error {
 constructor(readonly code:string){super(`Template authoring ${code}`);this.name='TemplateAuthoringError';}
}
function refuse(code='invalid_draft'):never {throw new TemplateAuthoringError(code);}
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
function record(input:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,any>{
 if(!input||Object.getPrototypeOf(input)!==Object.prototype)refuse();
 const out:Record<string,any>={},allowed=new Set([...required,...optional]);
 for(const key of Reflect.ownKeys(input)){if(typeof key!=='string'||!allowed.has(key))refuse();const d=Object.getOwnPropertyDescriptor(input,key)!;if(!Object.hasOwn(d,'value'))refuse();out[key]=d.value;}
 if(required.some(k=>!Object.hasOwn(out,k)))refuse();return out;
}
function bytes(value:unknown,length:number):Uint8Array {if(!(value instanceof Uint8Array)||value.length!==length||!value.some(v=>v!==0))refuse();return Uint8Array.from(value);}
const bindingFields=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'];
function ownBinding(input:unknown):ConversationSignerBinding02 {
 const b=record(input,bindingFields);for(const k of ['account','device','line','interval','session'])b[k]=bytes(b[k],16);for(const k of ['phoneReader','archiveReader'])b[k]=bytes(b[k],32);
 if(typeof b.generation!=='bigint'||b.generation<1n||b.generation>((1n<<63n)-1n)||typeof b.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))refuse();return b as ConversationSignerBinding02;
}
const sameBinding=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&['account','device','line','interval','session','phoneReader','archiveReader'].every(k=>equal(a[k as 'account'],b[k as 'account']));
const scopeFields=['accountId','deviceId','lineId','intervalId','templateId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'];
function ownScope(input:unknown):EncryptedTemplateScope {
 const s=record(input,scopeFields);for(const k of ['accountId','deviceId','lineId','intervalId','templateId'])s[k]=bytes(s[k],16);for(const k of ['peerDigest','readerId','manifestDigest'])s[k]=bytes(s[k],32);encryptedTemplateAad(s as EncryptedTemplateScope);return s as EncryptedTemplateScope;
}

/** Owns its persistence client and one draft lifetime. close/invalidate fences both. */
export class OwnerTemplateAuthoring {
 readonly client:OwnerEncryptedTemplateClient;
 #options:TemplateAuthoringOptions;#binding:ConversationSignerBinding02;#template:Uint8Array;
 #closed=false;#expired=false;#busy=false;#used=false;#controller=new AbortController();#deadline=0;#timer?:ReturnType<typeof setTimeout>;
 #root:Uint8Array|null=null;#generation=0n;#version=0n;#digest:Uint8Array|null=null;#now=0n;
 constructor(input:TemplateAuthoringOptions){
  const o=record(input,['origin','binding','templateId','readCurrent','currentCsrf','consumeCiphertextReview','signal','readDraftState','consumeDraftReview'],['enabled','timeoutMs','fetchImpl']);
  if(typeof o.readDraftState!=='function'||typeof o.consumeDraftReview!=='function')refuse();
  this.#binding=ownBinding(o.binding);this.#template=bytes(o.templateId,16);this.#options={...o,binding:this.#binding,templateId:this.#template} as TemplateAuthoringOptions;
  const {readDraftState:_,consumeDraftReview:__,...persistence}=this.#options;
  this.client=new OwnerEncryptedTemplateClient(persistence);
  o.signal.addEventListener('abort',this.#abort,{once:true});if(o.enabled!==true||o.signal.aborted)this.close();
  Object.freeze(this);
 }
 #abort=()=>this.close();
 close():void {this.#closed=true;clearTimeout(this.#timer);this.#controller.abort();closePersistence.call(this.client);this.#options.signal.removeEventListener('abort',this.#abort);}
 /** Host calls this on draft input, navigation, owner epoch or custody change. */
 invalidate():void {this.close();}
 #arm():void {clearTimeout(this.#timer);this.#timer=setTimeout(()=>{this.#expired=true;this.close();},Math.max(0,this.#deadline-performance.now()));}
 #live():void {if(this.#closed)refuse(this.#expired?'deadline':'closed');if(performance.now()>=this.#deadline){this.#expired=true;this.close();refuse('deadline');}}
 async #wait<T>(input:Promise<T>|T):Promise<T>{
  const observed=Promise.resolve(input);let timer:ReturnType<typeof setTimeout>|undefined,abort=()=>{};
  try{this.#live();}catch(error){void observed.catch(()=>{});throw error;}
  try{return await Promise.race([observed,new Promise<never>((_,reject)=>{abort=()=>reject(new TemplateAuthoringError(this.#expired?'deadline':'closed'));this.#controller.signal.addEventListener('abort',abort,{once:true});timer=setTimeout(()=>{this.#expired=true;reject(new TemplateAuthoringError('deadline'));this.close();},Math.max(0,this.#deadline-performance.now()));})]);}
  finally{if(timer!==undefined)clearTimeout(timer);this.#controller.signal.removeEventListener('abort',abort);}
 }
 async #csrf():Promise<string>{const value=await this.#wait(this.#options.currentCsrf());this.#live();if(typeof value!=='string'||!value.length||value.length>256||/[^\x21-\x7e]/.test(value))refuse('owner_changed');return value;}
 async #draft(input:TemplateAuthoringInput):Promise<void>{const d=record(await this.#wait(this.#options.readDraftState()),['epoch','revision','custodyLive']);this.#live();if(d.epoch!==input.epoch||d.revision!==input.draftRevision||d.custodyLive!==true)refuse('draft_changed');}
 async #current(input:TemplateAuthoringInput,csrf:string):Promise<{manifest:Manifest02;nowMs:bigint}>{
  this.#live();await this.#draft(input);const started=performance.now();
  const c=record(await this.#wait(this.#options.readCurrent()),['binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs']);this.#live();
  if(!sameBinding(this.#binding,ownBinding(c.binding))||c.ownerSessionLive!==true||c.consentLive!==true||c.phase!=='active'||typeof c.nowMs!=='bigint'||c.nowMs<1n||c.nowMs<this.#now||!Number.isFinite(c.validForMs)||c.validForMs<=0||c.validForMs>60000)refuse('owner_changed');
  const identity=verifiedManifestIdentity02(c.manifest,c.nowMs),trust=verifiedManifestTrust02(c.manifest,c.nowMs);
  const manifest=await this.#wait(verifyManifest02(Uint8Array.from(c.manifest.bytes),trust,c.nowMs));this.#live();const id=verifiedManifestIdentity02(manifest,c.nowMs);
  const s=input.scope,b=this.#binding;
  if(!equal(id.digest,identity.digest)||!equal(id.accountId,b.account)||this.#root&&(!equal(this.#root,id.rootPoint)||this.#generation!==id.generation)||id.version<this.#version||id.version===this.#version&&this.#digest&&!equal(this.#digest,id.digest))refuse('owner_changed');
  for(const [name,field] of [['accountId','account'],['deviceId','device'],['lineId','line'],['intervalId','interval'],['readerId','archiveReader']] as const)if(!equal(s[name],b[field]))refuse('scope_changed');
  if(!equal(s.templateId,this.#template)||s.bindingGeneration!==b.generation||s.trustGeneration!==id.generation||s.manifestVersion!==id.version||!equal(s.manifestDigest,id.digest)||s.expiresMs<=c.nowMs||s.expiresMs-c.nowMs>30n*86400000n)refuse('scope_changed');
  const peer=new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer))));this.#live();if(!equal(peer,s.peerDigest))refuse('scope_changed');
  authorizeWorkflowContext02(manifest,{accountId:s.accountId,deviceId:s.deviceId,lineId:s.lineId,readerId:s.readerId,generation:id.generation,version:id.version,digest:id.digest},c.nowMs);
  const reader=manifest.keys.find(k=>k.role===2&&equal(k.keyId,s.readerId))!,phone=manifest.keys.find(k=>k.role===4&&k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs&&equal(k.deviceId,b.device)&&equal(k.lineId,b.line))!;
  const expiry=[manifest.expiresMs,reader.untilMs,phone.untilMs,s.expiresMs].reduce((a,b)=>a<b?a:b);
  this.#deadline=Math.min(this.#deadline,started+c.validForMs,started+Number(expiry-c.nowMs));this.#live();this.#arm();
  await this.#draft(input);if(await this.#csrf()!==csrf)refuse('owner_changed');this.#live();
  this.#root=Uint8Array.from(id.rootPoint);this.#generation=id.generation;this.#version=id.version;this.#digest=Uint8Array.from(id.digest);this.#now=c.nowMs;
  return {manifest,nowMs:c.nowMs};
 }
 async prepare(input:TemplateAuthoringInput):Promise<TemplateTicket>{
  // Acquire before any caller-controlled Proxy/accessor inspection.
  if(this.#busy)refuse('busy');if(this.#used||pendingPersistence.call(this.client))refuse('pending_draft');this.#busy=true;
  this.#deadline=performance.now()+(this.#options.timeoutMs??10000);this.#arm();let envelope:Uint8Array|undefined;
  try{
   this.#live();const d=record(input,['requestId','expectedRevision','scope','template','values','epoch','draftRevision']);
   if(typeof d.epoch!=='bigint'||d.epoch<1n||typeof d.draftRevision!=='bigint'||d.draftRevision<1n||typeof d.requestId!=='string'||!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(d.requestId)||!Number.isSafeInteger(d.expectedRevision)||d.expectedRevision<0||d.expectedRevision>=128)refuse();
   const s=ownScope(d.scope);if(s.revision!==BigInt(d.expectedRevision+1))refuse();
   if(!d.values||Object.getPrototypeOf(d.values)!==Object.prototype)refuse();const values:Record<string,string>={},keys=Reflect.ownKeys(d.values);if(keys.length>32)refuse();
   for(const k of keys){if(typeof k!=='string'||['__proto__','prototype','constructor'].includes(k))refuse();const descriptor=Object.getOwnPropertyDescriptor(d.values,k);if(!descriptor||!Object.hasOwn(descriptor,'value'))refuse();values[k]=descriptor.value;}
   validateValues(values);
   const captured={...d,scope:s,values:Object.freeze(values)} as TemplateAuthoringInput;const canonical=canonicalTemplateBytes(captured.template,captured.values);try{if(canonical.length>32768)refuse();}finally{canonical.fill(0);}
   const preview=previewEncryptedTemplate(captured),csrf=await this.#csrf();await this.#current(captured,csrf);
   const review=Object.freeze({...captured,scope:ownScope(s),values:Object.freeze({...values}),preview});
   if(await this.#wait(this.#options.consumeDraftReview(review))!==true)refuse('review_declined');this.#live();
   const current=await this.#current(captured,csrf);
   envelope=await this.#wait(sealEncryptedTemplate(current.manifest,s,current.nowMs,{template:captured.template,values}));this.#live();await this.#current(captured,csrf);
   const ticket=await this.#wait(prepareSave.call(this.client,{requestId:captured.requestId,expectedRevision:captured.expectedRevision,scope:s,envelope}));this.#live();await this.#current(captured,csrf);
   this.#used=true;return ticket;
  }catch(error){this.close();if(error instanceof TemplateAuthoringError)throw error;throw new TemplateAuthoringError('refused');}
  finally{envelope?.fill(0);this.#busy=false;}
 }
}
