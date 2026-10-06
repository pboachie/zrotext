// SPDX-License-Identifier: AGPL-3.0-only
/** Explicit customer-local opening. Owns the supplied opaque client's lifetime. */
import {OwnerEncryptedTemplateClient,type TemplateOwnerCurrent} from './owner-encrypted-template-client.js';
import {authorizeWorkflowContext02,verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02,type Manifest02} from './draft02-manifest.js';
import {encryptedTemplateAad,openEncryptedTemplate,previewEncryptedTemplate,type EncryptedTemplateScope} from './encrypted-template.js';
import type {ConversationSignerBinding02} from './conversation-signer.js';

export interface OwnerTemplateOpeningOptions {
 enabled?:boolean;client:OwnerEncryptedTemplateClient;binding:ConversationSignerBinding02;templateId:Uint8Array;
 readCurrent:()=>Promise<TemplateOwnerCurrent|null>;currentCsrf:()=>string|Promise<string>;
 signal:AbortSignal;timeoutMs?:number;
}
export interface TemplateOpeningInput {readonly privateKey:CryptoKey}
export type TemplateOpenedPreview=Readonly<{
 state:'opened_current_preview';requestAcknowledged:false;matchesPending:boolean;revision:bigint;
 encryptedDigest:string;preview:ReturnType<typeof previewEncryptedTemplate>;
}>;
export class OwnerTemplateOpeningError extends Error {
 constructor(readonly code:'closed'|'busy'|'deadline'|'refused'){super(`Template opening ${code}`);this.name='OwnerTemplateOpeningError';}
}
const readLatest=OwnerEncryptedTemplateClient.prototype.readLatest;
const closeClient=OwnerEncryptedTemplateClient.prototype.close;
const bindingFields=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'] as const;
const scopeFields=['accountId','deviceId','lineId','intervalId','templateId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'] as const;
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((n,i)=>n===b[i]);
function refused():never {throw new OwnerTemplateOpeningError('refused');}
function record(input:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,any>{
 if(!input||Object.getPrototypeOf(input)!==Object.prototype)refused();
 const result:Record<string,any>={},allowed=new Set([...required,...optional]);
 for(const key of Reflect.ownKeys(input)){
  if(typeof key!=='string'||!allowed.has(key))refused();
  const descriptor=Object.getOwnPropertyDescriptor(input,key)!;
  if(!Object.hasOwn(descriptor,'value'))refused();result[key]=descriptor.value;
 }
 if(required.some(key=>!Object.hasOwn(result,key)))refused();return result;
}
function bytes(input:unknown,size:number):Uint8Array {
 if(!(input instanceof Uint8Array)||input.length!==size||!input.some(n=>n!==0))refused();return Uint8Array.from(input);
}
function binding(input:unknown):ConversationSignerBinding02 {
 const value=record(input,bindingFields);
 for(const key of ['account','device','line','interval','session'])value[key]=bytes(value[key],16);
 for(const key of ['phoneReader','archiveReader'])value[key]=bytes(value[key],32);
 if(typeof value.generation!=='bigint'||value.generation<1n||value.generation>(1n<<63n)-1n||typeof value.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(value.peer))refused();
 return value as ConversationSignerBinding02;
}
function sameBinding(a:ConversationSignerBinding02,b:ConversationSignerBinding02):boolean {
 return a.generation===b.generation&&a.peer===b.peer&&['account','device','line','interval','session','phoneReader','archiveReader'].every(key=>equal(a[key as 'account'],b[key as 'account']));
}
function scope(input:unknown):EncryptedTemplateScope {
 const value=record(input,scopeFields);
 for(const key of ['accountId','deviceId','lineId','intervalId','templateId'])value[key]=bytes(value[key],16);
 for(const key of ['peerDigest','readerId','manifestDigest'])value[key]=bytes(value[key],32);
 encryptedTemplateAad(value as EncryptedTemplateScope);return value as EncryptedTemplateScope;
}
type Current=Readonly<{manifest:Manifest02;nowMs:bigint}>;

/** No automatic reads or UI attachment. Supply a dedicated client; close aborts it. */
export class OwnerTemplateOpening {
 #options:OwnerTemplateOpeningOptions;#binding:ConversationSignerBinding02;#template:Uint8Array;#timeout:number;
 #closed=false;#busy=false;#epoch=0;#abortController=new AbortController();
 #root:Uint8Array|null=null;#generation=0n;#version=0n;#digest:Uint8Array|null=null;#now=0n;
 constructor(input:OwnerTemplateOpeningOptions){
  const o=record(input,['client','binding','templateId','readCurrent','currentCsrf','signal'],['enabled','timeoutMs']);
  if(!(o.client instanceof OwnerEncryptedTemplateClient)||typeof o.readCurrent!=='function'||typeof o.currentCsrf!=='function'||!(o.signal instanceof AbortSignal)||o.enabled!==undefined&&typeof o.enabled!=='boolean')refused();
  this.#timeout=o.timeoutMs??10000;
  if(!Number.isSafeInteger(this.#timeout)||this.#timeout<1||this.#timeout>10000)refused();
  this.#binding=binding(o.binding);this.#template=bytes(o.templateId,16);this.#options={...o} as OwnerTemplateOpeningOptions;
  o.signal.addEventListener('abort',this.#abort,{once:true});if(o.enabled!==true||o.signal.aborted)this.close();
 }
 #abort=()=>this.close();
 /** Call on draft/review replacement, hiding, owner loss or custody replacement. */
 invalidate():void {this.close();}
 close():void {
  if(this.#closed)return;this.#closed=true;this.#epoch++;this.#abortController.abort();
  this.#options.signal.removeEventListener('abort',this.#abort);
  closeClient.call(this.#options.client);
 }
 #live(deadline:number,epoch:number):void {
  if(this.#closed||this.#options.signal.aborted||this.#epoch!==epoch)throw new OwnerTemplateOpeningError('closed');
  if(performance.now()>=deadline){this.close();throw new OwnerTemplateOpeningError('deadline');}
 }
 async #wait<T>(value:Promise<T>|T,deadline:number,epoch:number):Promise<T>{
  const observed=Promise.resolve(value);let timer:ReturnType<typeof setTimeout>|undefined,abort=()=>{};
  try{this.#live(deadline,epoch);}catch(error){void observed.catch(()=>{});throw error;}
  try{
   const result=await Promise.race([observed,new Promise<never>((_,reject)=>{
    abort=()=>reject(new OwnerTemplateOpeningError('closed'));this.#abortController.signal.addEventListener('abort',abort,{once:true});
    timer=setTimeout(()=>{reject(new OwnerTemplateOpeningError('deadline'));this.close();},Math.max(0,deadline-performance.now()));
   })]);this.#live(deadline,epoch);return result;
  }finally{if(timer!==undefined)clearTimeout(timer);this.#abortController.signal.removeEventListener('abort',abort);}
 }
 async #csrf(deadline:number,epoch:number):Promise<string>{
  const value=await this.#wait(this.#options.currentCsrf(),deadline,epoch);
  if(typeof value!=='string'||value.length<1||value.length>256||/[^\x21-\x7e]/.test(value))refused();return value;
 }
 async #current(s:EncryptedTemplateScope|null,budget:{deadline:number},epoch:number,csrf:string):Promise<Current>{
  this.#live(budget.deadline,epoch);const started=performance.now();
  const c=record(await this.#wait(this.#options.readCurrent(),budget.deadline,epoch),['binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs']);
  if(!sameBinding(binding(c.binding),this.#binding)||c.ownerSessionLive!==true||c.consentLive!==true||c.phase!=='active'||typeof c.nowMs!=='bigint'||c.nowMs<1n||c.nowMs<this.#now||!Number.isFinite(c.validForMs)||c.validForMs<=0||c.validForMs>60000)refused();
  const identity=verifiedManifestIdentity02(c.manifest,c.nowMs),trust=verifiedManifestTrust02(c.manifest,c.nowMs);
  const manifest=await this.#wait(verifyManifest02(Uint8Array.from(c.manifest.bytes),trust,c.nowMs),budget.deadline,epoch);
  const id=verifiedManifestIdentity02(manifest,c.nowMs),b=this.#binding;
  if(!equal(identity.digest,id.digest)||!equal(id.accountId,b.account)||this.#root&&(!equal(this.#root,id.rootPoint)||id.generation!==this.#generation)||id.version<this.#version||id.version===this.#version&&this.#digest&&!equal(id.digest,this.#digest))refused();
  authorizeWorkflowContext02(manifest,{accountId:b.account,deviceId:b.device,lineId:b.line,readerId:b.archiveReader,generation:id.generation,version:id.version,digest:id.digest},c.nowMs);
  if(s){
   for(const [field,key] of [['accountId','account'],['deviceId','device'],['lineId','line'],['intervalId','interval'],['readerId','archiveReader']] as const)if(!equal(s[field],b[key]))refused();
   if(!equal(s.templateId,this.#template)||s.bindingGeneration!==b.generation||s.trustGeneration!==id.generation||s.manifestVersion!==id.version||!equal(s.manifestDigest,id.digest)||s.expiresMs<=c.nowMs||s.expiresMs-c.nowMs>30n*86400000n)refused();
   const peer=new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer)),budget.deadline,epoch));
   if(!equal(peer,s.peerDigest))refused();
  }
  const reader=manifest.keys.find(k=>k.role===2&&equal(k.keyId,b.archiveReader))!;
  const phone=manifest.keys.find(k=>k.role===4&&k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs&&equal(k.deviceId,b.device)&&equal(k.lineId,b.line))!;
  const expiry=[manifest.expiresMs,reader.untilMs,phone.untilMs,...(s?[s.expiresMs]:[])].reduce((a,b)=>a<b?a:b);
  budget.deadline=Math.min(budget.deadline,started+c.validForMs,started+Number(expiry-c.nowMs));this.#live(budget.deadline,epoch);
  if(await this.#csrf(budget.deadline,epoch)!==csrf)refused();
  this.#root=Uint8Array.from(id.rootPoint);this.#generation=id.generation;this.#version=id.version;this.#digest=Uint8Array.from(id.digest);this.#now=c.nowMs;
  return {manifest,nowMs:c.nowMs};
 }
 async openLatest(input:TemplateOpeningInput):Promise<TemplateOpenedPreview>{
  if(this.#busy)throw new OwnerTemplateOpeningError('busy');
  const budget={deadline:performance.now()+this.#timeout},epoch=this.#epoch;this.#live(budget.deadline,epoch);
  // A Proxy can execute code during inspection. Acquire the gate first.
  this.#busy=true;let envelope:Uint8Array|undefined;
  try{
   const d=record(input,['privateKey']),key=d.privateKey;
   if(!(key instanceof CryptoKey)||key.type!=='private'||key.algorithm.name!=='ECDH'||(key.algorithm as EcKeyAlgorithm).namedCurve!=='P-256'||key.usages.length!==1||key.usages[0]!=='deriveBits')refused();
   const csrf=await this.#csrf(budget.deadline,epoch);await this.#current(null,budget,epoch,csrf);
   // Invoke the real private-branded implementation, never a caller's replaced method.
   const snapshot=await this.#wait(readLatest.call(this.#options.client),budget.deadline,epoch);
   const s=scope(snapshot.scope);envelope=Uint8Array.from(snapshot.envelope);
   const current=await this.#current(s,budget,epoch,csrf);
   const content=await this.#wait(openEncryptedTemplate(current.manifest,s,current.nowMs,key,envelope),budget.deadline,epoch);
   await this.#current(s,budget,epoch,csrf);const preview=previewEncryptedTemplate(content);
   await this.#current(s,budget,epoch,csrf);this.#live(budget.deadline,epoch);
   return Object.freeze({state:'opened_current_preview',requestAcknowledged:false,matchesPending:snapshot.matchesPending,revision:s.revision,encryptedDigest:snapshot.encryptedDigest,preview});
  }catch(error){this.close();if(error instanceof OwnerTemplateOpeningError)throw error;throw new OwnerTemplateOpeningError('refused');}
  finally{envelope?.fill(0);this.#busy=false;}
 }
}
