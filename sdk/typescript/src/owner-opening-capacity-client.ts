// SPDX-License-Identifier: AGPL-3.0-only
/** Opening transport foundation. No mounted server, page caller or capacity authority. */
import { authorizeWorkflowContext02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02 } from './draft02-manifest.js';
import type { ConversationSignerBinding02, ConversationSignerCurrent02 } from './conversation-signer.js';
import type { OwnerContextAuthoring, OwnerAcknowledgedSourceSnapshot } from './owner-context-authoring.js';

export interface OwnerOpeningCapacityOptions {
  enabled: boolean; origin: string; binding: ConversationSignerBinding02;
  contextId: Uint8Array; sourceExpiresMs: bigint;
  readSavedSource: OwnerContextAuthoring['savedSource'];
  readCurrent: () => Promise<ConversationSignerCurrent02|null>;
  currentCsrf: () => string; consumeCreateReview: (review: OpeningCreateReview) => Promise<void>;
  signal: AbortSignal; onSetupClose: (listener: () => void) => void|(() => void);
  onCustodyClose: (listener: () => void) => void|(() => void);
  totalTimeoutMs: number; attemptTimeoutMs: number; observationTimeoutMs: number; maxAttempts: number;
  fetchImpl?: typeof fetch;
}
export type OpeningCreateInput = Readonly<{requestId: string; openingId: string; capacity: number; decisionDeadlineMs: bigint}>;
export type OpeningCreateReview = Readonly<{accountId: string; requestId: string; openingId: string; capacity: number; source: OwnerAcknowledgedSourceSnapshot; decisionDeadlineMs: bigint; remainingMs: number}>;
export type OpeningCreateTicket = Readonly<{kind: 'opening_create'}>;
export type OpeningPending = Readonly<{accountId: string; requestId: string; openingId: string}>;
export type OpeningReceipt = Readonly<{opening: Readonly<{opening_id: string; definition_version: bigint; state_version: bigint}>; offer: null; allocation_id: null; allocation_version: null; phase: 'open'|'closed'|'cancelled'; pending: bigint; confirmed: bigint}>;
export type OpeningCreateResult = Readonly<
  {state: 'acknowledged'; accountId: string; requestId: string; openingId: string; receipt: OpeningReceipt; applied: boolean}|
  {state: 'refused'; code: string}|
  {state: 'unknown'; pending: OpeningPending; code: string}>;
export type OpeningMetadataSnapshot = Readonly<{state: 'metadata_snapshot'; accountId: string; openingId: string; receipt: OpeningReceipt}>;
export type OwnerOpeningCapacityClient = Readonly<{
  prepareCreate(input: OpeningCreateInput): Promise<OpeningCreateTicket>;
  create(ticket: OpeningCreateTicket): Promise<OpeningCreateResult>;
  retry(ticket: OpeningCreateTicket): Promise<OpeningCreateResult>;
  status(openingId: string): Promise<OpeningMetadataSnapshot>;
  state(): Readonly<{closed: boolean; busy: boolean; pending: OpeningPending|null}>;
  close(): void;
}>;
export class OpeningCapacityError extends Error {
  constructor(readonly code: string) { super('Opening operation unavailable'); this.name='OpeningCapacityError'; }
}
const MAX=(1n<<63n)-1n, CAP=8192, enc=new TextEncoder();
function fail(code='invalid'):never {throw new OpeningCapacityError(code);}
const names=['enabled','origin','binding','contextId','sourceExpiresMs','readSavedSource','readCurrent','currentCsrf','consumeCreateReview','signal','onSetupClose','onCustodyClose','totalTimeoutMs','attemptTimeoutMs','observationTimeoutMs','maxAttempts'];
const bindingNames=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'];
const byteNames=['account','device','line','interval','session','phoneReader','archiveReader'] as const;
function data(value: unknown, required: string[], optional: string[]=[]): Record<string, any> {
  if(value===null||typeof value!=='object'||Object.getPrototypeOf(value)!==Object.prototype)fail();
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
  if(keys.some(k=>typeof k!=='string'||!required.includes(k)&&!optional.includes(k))||required.some(k=>!Object.hasOwn(descriptors,k)))fail();
  const out:Record<string,any>={};for(const k of keys as string[]){const d=descriptors[k];if(!('value' in d)||!d.enumerable)fail();out[k]=d.value;}return out;
}
function bytes(value: unknown,n: number):Uint8Array { if(!(value instanceof Uint8Array)||value.length!==n||value.every(x=>x===0))fail();return Uint8Array.from(value); }
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hex=(a:Uint8Array)=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
const uuid=(a:Uint8Array)=>hex(a).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
function id(value: unknown):string { if(typeof value!=='string'||value.length!==36||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)||value.replaceAll('-','').split('').every(x=>x==='0'))fail();return value; }
function positive(value:unknown):bigint { if(typeof value!=='bigint'||value<1n||value>MAX)fail();return value; }
function decimal(value:unknown,zero=false):bigint { if(typeof value!=='string'||value.length>19||!(zero?/^(0|[1-9][0-9]*)$/:/^[1-9][0-9]*$/).test(value))fail();const n=BigInt(value);if(n>MAX||n.toString()!==value)fail();return n; }
function binding(value:unknown):ConversationSignerBinding02 {
  const b=data(value,bindingNames);for(const k of byteNames)b[k]=bytes(b[k],k.endsWith('Reader')?32:16);
  positive(b.generation);if(typeof b.peer!=='string'||b.peer.length>16||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))fail();return b as ConversationSignerBinding02;
}
const equalBinding=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&byteNames.every(k=>same(a[k],b[k]));
function digest(value:unknown):string { if(typeof value!=='string'||value.length!==64||!/^[0-9a-f]{64}$/.test(value)||/^0{64}$/.test(value))fail();return value; }
function source(value:unknown,account:string,context:string):OwnerAcknowledgedSourceSnapshot {
  const s=data(value,['accountId','receipt']),r=data(s.receipt,['requestId','contextId','revision','envelopeDigest','state','requestAcknowledged']);
  if(id(s.accountId)!==account||id(r.contextId)!==context||r.revision!==1||r.state!=='verified_current_snapshot'||r.requestAcknowledged!==true)fail('source');
  id(r.requestId);digest(r.envelopeDigest);return Object.freeze({accountId:account,receipt:Object.freeze({...r})}) as OwnerAcknowledgedSourceSnapshot;
}
function equalSource(a:OwnerAcknowledgedSourceSnapshot,b:OwnerAcknowledgedSourceSnapshot):boolean {return a.accountId===b.accountId&&['requestId','contextId','revision','envelopeDigest','state','requestAcknowledged'].every(k=>(a.receipt as any)[k]===(b.receipt as any)[k]);}

/** Bounded JSON syntax with duplicate-key detection before closed DTO validation. */
function json(text:string):unknown {
  let at=0;const ws=()=>{while(/[ \r\n\t]/.test(text[at]??'!'))at++;};
  function string():string { const start=at++;while(at<text.length){const c=text[at++];if(c==='"'){try{return JSON.parse(text.slice(start,at));}catch{fail('response');}}if(c==='\\'){if(at>=text.length)fail('response');at++;}}return fail('response'); }
  function value(depth:number):any {
    if(depth>6)fail('response');ws();const c=text[at];
    if(c==='"')return string();
    if(c==='{'){at++;const out:Record<string,any>={},seen=new Set<string>();ws();if(text[at]==='}'){at++;return out;}while(at<text.length){ws();if(text[at]!=='"')fail('response');const key=string();if(seen.has(key)||seen.size>=16||key==='__proto__')fail('response');seen.add(key);ws();if(text[at++]!==':')fail('response');out[key]=value(depth+1);ws();const end=text[at++];if(end==='}')return out;if(end!==',')fail('response');}fail('response');}
    for(const [token,result] of [['true',true],['false',false],['null',null]] as const)if(text.startsWith(token,at)){at+=token.length;return result;}
    // This response grammar has no numeric values or arrays: i64 fields are strings.
    return fail('response');
  }
  const result=value(0);ws();if(at!==text.length)fail('response');return result;
}
function receipt(value:unknown,openingId:string):OpeningReceipt {
  const r=data(value,['opening','offer','allocation_id','allocation_version','phase','pending','confirmed']),o=data(r.opening,['opening_id','definition_version','state_version']);
  if(id(o.opening_id)!==openingId||r.offer!==null||r.allocation_id!==null||r.allocation_version!==null||!['open','closed','cancelled'].includes(r.phase))fail('response');
  const pending=decimal(r.pending,true),confirmed=decimal(r.confirmed,true);if(pending+confirmed>100n)fail('response');
  return Object.freeze({opening:Object.freeze({opening_id:openingId,definition_version:decimal(o.definition_version),state_version:decimal(o.state_version)}),offer:null,allocation_id:null,allocation_version:null,phase:r.phase,pending,confirmed});
}
type Prepared={ticket:OpeningCreateTicket;body:string;csrf:string;identity:OpeningPending;sent:boolean;unknown:boolean};
class Client {
  #o:OwnerOpeningCapacityOptions;#binding:ConversationSignerBinding02;#account:string;#context:string;
  #deadline:number;#controller=new AbortController();#closed=false;#busy=false;#retired=false;
  #attempts=0;#prepared:Prepared|null=null;#pending:OpeningPending|null=null;#removers:(()=>void)[]=[];
  #tickets=new WeakMap<OpeningCreateTicket,Prepared>();
  #timer:ReturnType<typeof setTimeout>|null=null;#lastNow=0n;#root:Uint8Array|null=null;#generation:bigint|null=null;#version=0n;#manifestDigest:Uint8Array|null=null;
  #unsettled=new Set<Promise<unknown>>();
  constructor(input:OwnerOpeningCapacityOptions){
    const o=data(input,names,['fetchImpl']);
    if(typeof o.enabled!=='boolean'||!(o.signal instanceof AbortSignal)||['readSavedSource','readCurrent','currentCsrf','consumeCreateReview','onSetupClose','onCustodyClose'].some(k=>typeof o[k]!=='function')||o.fetchImpl!==undefined&&typeof o.fetchImpl!=='function')fail();
    if(typeof o.origin!=='string'||o.origin.length<1||o.origin.length>512||/[^\x21-\x7e]/.test(o.origin))fail();
    let url:URL;try{url=new URL(o.origin);}catch{throw new OpeningCapacityError('invalid');}if(url.protocol!=='https:'||url.origin!==o.origin||typeof location!=='undefined'&&location.origin!==o.origin)fail();
    for(const k of ['totalTimeoutMs','attemptTimeoutMs','observationTimeoutMs','maxAttempts'])if(!Number.isSafeInteger(o[k])||o[k]<1||o[k]>(k==='totalTimeoutMs'?60000:k==='maxAttempts'?3:10000))fail();
    const b=binding(o.binding),context=bytes(o.contextId,16);positive(o.sourceExpiresMs);
    this.#o={...o,binding:b,contextId:context} as OwnerOpeningCapacityOptions;this.#binding=b;this.#account=uuid(b.account);this.#context=uuid(context);this.#deadline=performance.now()+o.totalTimeoutMs;
    if(!o.enabled||o.signal.aborted){this.close();return;}
    const closed=()=>this.close();o.signal.addEventListener('abort',closed,{once:true});this.#removers.push(()=>o.signal.removeEventListener('abort',closed));
    for(const subscribe of [o.onSetupClose,o.onCustodyClose]){
      if(this.#closed)break;
      try{const remove=subscribe(closed);if(remove!==undefined&&typeof remove!=='function')fail();if(typeof remove==='function'){if(this.#closed){try{remove();}catch{}}else this.#removers.push(remove);}}catch{this.close();}
    }
    if(!this.#closed)this.#arm();
  }
  #arm(){if(this.#timer!==null)clearTimeout(this.#timer);this.#timer=setTimeout(()=>this.close(),Math.max(1,Math.ceil(this.#deadline-performance.now())));}
  #cap(deadline:number){if(deadline<this.#deadline){this.#deadline=deadline;this.#arm();}this.#live();}
  #live(){if(this.#closed||this.#o.signal.aborted||performance.now()>=this.#deadline){this.close();fail('closed');}}
  #csrf(){this.#live();const v=this.#o.currentCsrf();this.#live();if(typeof v!=='string'||v.length<1||v.length>256||/[^\x21-\x7e]/.test(v))fail('csrf');return v;}
  #isBusy(){return this.#busy||this.#unsettled.size>0;}
  #track<T>(work:Promise<T>):Promise<T>{this.#unsettled.add(work);void work.finally(()=>this.#unsettled.delete(work)).catch(()=>{});return work;}
  #wait<T>(work:Promise<T>,deadline:number):Promise<T>{
    return new Promise((resolve,reject)=>{
      let done=false;const finish=(fn:()=>void)=>{if(done)return;done=true;clearTimeout(timer);this.#controller.signal.removeEventListener('abort',abort);fn();};
      const abort=()=>finish(()=>reject(new OpeningCapacityError('closed'))),timer=setTimeout(()=>finish(()=>reject(new OpeningCapacityError('timeout'))),Math.max(0,deadline-performance.now()));
      this.#controller.signal.addEventListener('abort',abort,{once:true});if(this.#controller.signal.aborted)abort();
      work.then(v=>finish(()=>resolve(v)),()=>finish(()=>reject(new OpeningCapacityError('unavailable'))));
    });
  }
  async #observe():Promise<{now:bigint;ceiling:bigint;observedAt:number}>{
    this.#live();const started=performance.now(),deadline=Math.min(this.#deadline,started+this.#o.observationTimeoutMs);
    const c=data(await this.#wait(this.#track(Promise.resolve().then(()=>{this.#live();return this.#o.readCurrent();})),deadline),['binding','manifest','nowMs','ownerSessionLive','consentLive']);this.#live();
    if(c.ownerSessionLive!==true||c.consentLive!==true||!equalBinding(this.#binding,binding(c.binding)))fail('current');positive(c.nowMs);if(c.nowMs<this.#lastNow)fail('current');
    const original=verifiedManifestIdentity02(c.manifest,c.nowMs),owned=Uint8Array.from(c.manifest.bytes),trust=verifiedManifestTrust02(c.manifest,c.nowMs);
    const m=await this.#wait(this.#track(verifyManifest02(owned,trust,c.nowMs)),deadline);this.#live();
    const identity=verifiedManifestIdentity02(m,c.nowMs);
    if(identity.generation!==original.generation||identity.version!==original.version||!same(identity.accountId,original.accountId)||!same(identity.rootPoint,original.rootPoint)||!same(identity.digest,original.digest))fail('current');
    if(!same(identity.accountId,this.#binding.account)||this.#generation!==null&&(identity.generation!==this.#generation||!same(identity.rootPoint,this.#root!))||identity.version<this.#version||identity.version===this.#version&&this.#manifestDigest!==null&&!same(identity.digest,this.#manifestDigest))fail('current');
    authorizeWorkflowContext02(m,{accountId:this.#binding.account,deviceId:this.#binding.device,lineId:this.#binding.line,readerId:this.#binding.archiveReader,generation:m.generation,version:m.version,digest:m.digest},c.nowMs);
    const active=(k:typeof m.keys[number])=>k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs;
    const phone=m.keys.find(k=>k.role===1&&active(k)&&same(k.keyId,this.#binding.phoneReader)&&same(k.deviceId,this.#binding.device)&&same(k.lineId,this.#binding.line));
    const archive=m.keys.find(k=>k.role===2&&active(k)&&same(k.keyId,this.#binding.archiveReader));
    const signer=m.keys.find(k=>k.role===4&&active(k)&&same(k.deviceId,this.#binding.device)&&same(k.lineId,this.#binding.line));
    if(!phone||!archive||!signer)fail('current');
    const ceiling=[m.expiresMs,phone.untilMs,archive.untilMs,signer.untilMs,this.#o.sourceExpiresMs].reduce((a,b)=>a<b?a:b),remaining=ceiling-c.nowMs;
    if(remaining<1n)fail('current');this.#cap(Math.min(deadline,started+Number(remaining>60000n?60000n:remaining)));
    this.#lastNow=c.nowMs;this.#generation=identity.generation;this.#root=Uint8Array.from(identity.rootPoint);this.#version=identity.version;this.#manifestDigest=Uint8Array.from(identity.digest);
    return {now:c.nowMs,ceiling,observedAt:started};
  }
  async prepareCreate(input:OpeningCreateInput):Promise<OpeningCreateTicket>{
    this.#live();if(this.#isBusy()||this.#retired||this.#prepared)fail('busy');
    const i=data(input,['requestId','openingId','capacity','decisionDeadlineMs']);id(i.requestId);id(i.openingId);positive(i.decisionDeadlineMs);if(!Number.isSafeInteger(i.capacity)||i.capacity<1||i.capacity>100)fail();
    this.#busy=true;let captured:OwnerAcknowledgedSourceSnapshot,csrf:string;
    try{captured=source(this.#o.readSavedSource(),this.#account,this.#context);this.#live();csrf=this.#csrf();}
    catch{this.#busy=false;this.#retired=true;throw new OpeningCapacityError('source');}
    // Keep the slot charged until actual callback/crypto work settles, even after outward refusal.
    const operation=(async()=>{
      const current=await this.#observe();if(i.decisionDeadlineMs<=current.now||i.decisionDeadlineMs>current.ceiling)fail('expiry');
      const remaining=i.decisionDeadlineMs-current.now;this.#cap(current.observedAt+Number(remaining>60000n?60000n:remaining));
      const review=Object.freeze({accountId:this.#account,requestId:i.requestId,openingId:i.openingId,capacity:i.capacity,source:captured,decisionDeadlineMs:i.decisionDeadlineMs,remainingMs:Math.max(0,Math.floor(this.#deadline-performance.now()))});
      await this.#o.consumeCreateReview(review);this.#live();
      const final=await this.#observe();if(i.decisionDeadlineMs<=final.now||i.decisionDeadlineMs>final.ceiling||csrf!==this.#csrf()||!equalSource(captured,source(this.#o.readSavedSource(),this.#account,this.#context)))fail('changed');
      this.#live();const ticket=Object.freeze({kind:'opening_create' as const}),identity=Object.freeze({accountId:this.#account,requestId:i.requestId,openingId:i.openingId});
      const body=JSON.stringify({request_id:i.requestId,opening_id:i.openingId,capacity:i.capacity,description:{context_id:captured.receipt.contextId,revision:captured.receipt.revision,digest:captured.receipt.envelopeDigest},decision_deadline_ms:i.decisionDeadlineMs.toString()});if(enc.encode(body).length>CAP)fail();
      return {ticket,identity,body,csrf,sent:false,unknown:false};
    })();
    void operation.finally(()=>{this.#busy=false;}).catch(()=>{});
    try{const record=await this.#wait(operation,this.#deadline);this.#live();this.#prepared=record;this.#tickets.set(record.ticket,record);return record.ticket;}catch{this.#retired=true;throw new OpeningCapacityError('prepare');}
  }
  async #request(path:string,body:string,csrf:string,deadline:number,abort:AbortController):Promise<{status:number;value:unknown}>{
    const request=this.#o.fetchImpl??fetch;
    const response=await request(this.#o.origin+path,{method:'POST',body,headers:{'content-type':'application/json',accept:'application/json','x-zrotext-opening-account':this.#account,'x-zrotext-csrf':csrf},credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:abort.signal});
    let readable:ReadableStream<Uint8Array>;
    try{
      this.#live();if(performance.now()>=deadline||abort.signal.aborted)fail('timeout');
      if(response.redirected)fail('response');
      if(response.status!==200){try{await response.body?.cancel();}catch{}return {status:response.status,value:null};}
      if(response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json'||!response.body)fail('response');
      readable=response.body;
    }catch(error){try{await response.body?.cancel();}catch{}throw error;}
    const reader=readable.getReader(),parts:Uint8Array[]=[];let length=0,ended=false;
    try{while(true){const part=await reader.read();this.#live();if(performance.now()>=deadline||abort.signal.aborted)fail('timeout');if(part.done){ended=true;break;}if(!(part.value instanceof Uint8Array)||length+part.value.length>CAP)fail('response');parts.push(Uint8Array.from(part.value));length+=part.value.length;}}
    finally{if(!ended)try{await reader.cancel();}catch{}try{reader.releaseLock();}catch{}}
    if(length<1)fail('response');const out=new Uint8Array(length);let at=0;for(const p of parts){out.set(p,at);at+=p.length;}
    let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(out);}catch{return fail('response');}return {status:200,value:json(text)};
  }
  #begin(){this.#live();if(this.#isBusy())fail('busy');if(this.#attempts>=this.#o.maxAttempts)fail('attempts');this.#attempts++;this.#busy=true;}
  async #transport(path:string,body:string,csrf:string):Promise<{status:number;value:unknown}>{
    this.#begin();const deadline=Math.min(this.#deadline,performance.now()+this.#o.attemptTimeoutMs),abort=new AbortController(),closed=()=>abort.abort();
    this.#controller.signal.addEventListener('abort',closed,{once:true});
    const operation=this.#request(path,body,csrf,deadline,abort);
    void operation.finally(()=>{this.#busy=false;this.#controller.signal.removeEventListener('abort',closed);}).catch(()=>{});
    try{return await this.#wait(operation,deadline);}finally{abort.abort();}
  }
  #unknown(r:Prepared,code:string):OpeningCreateResult {r.unknown=true;this.#pending=r.identity;return Object.freeze({state:'unknown',pending:r.identity,code});}
  async #dispatch(ticket:OpeningCreateTicket,replay:boolean):Promise<OpeningCreateResult>{
    const r=this.#prepared;if(!r||this.#tickets.get(ticket)!==r||r.ticket!==ticket||replay!==r.sent||replay&&!r.unknown)return this.#pending?Object.freeze({state:'unknown',pending:this.#pending,code:'ticket'}):Object.freeze({state:'refused',code:'ticket'});
    try{this.#live();if(this.#isBusy())fail('busy');if(this.#attempts>=this.#o.maxAttempts)fail('attempts');if(this.#csrf()!==r.csrf)fail('csrf');}
    catch(error){return r.unknown?this.#unknown(r,error instanceof OpeningCapacityError?error.code:'unavailable'):Object.freeze({state:'refused',code:'unavailable'});}
    r.sent=true;
    try{
      const response=await this.#transport('/v1/owner/workflow/openings',r.body,r.csrf);this.#live();
      if(response.status!==200){if(!r.unknown&&[400,401,403,404,409,413,429].includes(response.status)){this.#prepared=null;this.#tickets.delete(r.ticket);this.#retired=true;return Object.freeze({state:'refused',code:'server'});}return this.#unknown(r,'server');}
      const value=data(response.value,['account_id','request_id','outcome']),outcome=data(value.outcome,['receipt','applied','recorded']);
      if(id(value.account_id)!==r.identity.accountId||id(value.request_id)!==r.identity.requestId||outcome.recorded!==true||typeof outcome.applied!=='boolean')fail('response');
      const decoded=receipt(outcome.receipt,r.identity.openingId);this.#live();if(this.#prepared!==r||this.#csrf()!==r.csrf)fail('closed');
      this.#prepared=null;this.#tickets.delete(r.ticket);this.#pending=null;this.#retired=true;
      return Object.freeze({state:'acknowledged',...r.identity,receipt:decoded,applied:outcome.applied});
    }catch(error){return this.#unknown(r,error instanceof OpeningCapacityError?error.code:'unavailable');}
  }
  create=(ticket:OpeningCreateTicket)=>this.#dispatch(ticket,false);
  retry=(ticket:OpeningCreateTicket)=>this.#dispatch(ticket,true);
  async status(openingId:string):Promise<OpeningMetadataSnapshot>{
    const opening=id(openingId);this.#live();if(this.#pending&&this.#pending.openingId!==opening)fail('selection');const csrf=this.#csrf();
    const response=await this.#transport('/v1/owner/workflow/openings/'+opening+'/status','{}',csrf);this.#live();if(csrf!==this.#csrf()||response.status!==200)fail('status');
    const value=data(response.value,['account_id','receipt']);if(id(value.account_id)!==this.#account)fail('response');
    return Object.freeze({state:'metadata_snapshot',accountId:this.#account,openingId:opening,receipt:receipt(value.receipt,opening)});
  }
  state=()=>Object.freeze({closed:this.#closed,busy:this.#isBusy(),pending:this.#pending?Object.freeze({...this.#pending}):null});
  close=()=>{
    if(this.#closed)return;this.#closed=true;const r=this.#prepared;
    if(r?.sent){r.unknown=true;this.#pending=r.identity;}
    this.#prepared=null;if(r){this.#tickets.delete(r.ticket);r.body='';r.csrf='';}this.#root=null;this.#manifestDigest=null;
    for(const k of byteNames)this.#binding[k].fill(0);this.#binding={...this.#binding,generation:0n,peer:''};this.#context='';this.#account='';this.#o.contextId.fill(0);
    this.#o={...this.#o,binding:this.#binding,sourceExpiresMs:0n,signal:this.#controller.signal,readSavedSource:()=>null,readCurrent:async()=>null,currentCsrf:()=>'',consumeCreateReview:async()=>{},onSetupClose:()=>{},onCustodyClose:()=>{},fetchImpl:undefined};
    if(this.#timer!==null){clearTimeout(this.#timer);this.#timer=null;}
    const remove=this.#removers.splice(0);try{this.#controller.abort();}catch{}finally{for(const f of remove)try{f();}catch{}}
  };
  public():OwnerOpeningCapacityClient{return Object.freeze({prepareCreate:this.prepareCreate.bind(this),create:this.create,retry:this.retry,status:this.status.bind(this),state:this.state,close:this.close});}
}
export function createOwnerOpeningCapacityClient(options:OwnerOpeningCapacityOptions):OwnerOpeningCapacityClient {return new Client(options).public();}
