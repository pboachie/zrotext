// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant browser owner transport. Ciphertext publication is not execution authority. */
import { authorizeWorkflowContext02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02 } from './draft02-manifest.js';
import type { ConversationSignerBinding02, ConversationSignerCurrent02 } from './conversation-signer.js';
import { workflowContextAad, type WorkflowContextScope } from './workflow-context.js';

export type OwnerContextCurrent = ConversationSignerCurrent02 & Readonly<{ phase: 'active'; validForMs: number }>;
export type OwnerContextSelection = Readonly<{binding: ConversationSignerBinding02; contextId: Uint8Array; kind: 1|2|3}>;
export type OwnerContextWrite = Readonly<{requestId: string; expectedRevision: number; scope: WorkflowContextScope; envelope: Uint8Array}>;
export type OwnerContextWriteReview = Readonly<{requestId: string; contextId: string; expectedRevision: number; revision: number; envelopeDigest: string; scope: WorkflowContextScope}>;
export type OwnerContextPending = Readonly<{requestId: string; contextId: string; revision: number; envelopeDigest: string}>;
export type OwnerContextReceipt = OwnerContextPending & Readonly<{state: 'verified_current_snapshot'; requestAcknowledged: boolean}>;
export type OwnerContextTicket = object;
export interface OwnerContextOptions {
  enabled?: boolean; origin: string; selection: OwnerContextSelection;
  readCurrent: () => Promise<OwnerContextCurrent|null>; currentCsrf: () => string;
  consumeWriteReview: (review: OwnerContextWriteReview) => Promise<void>;
  signal: AbortSignal; timeoutMs?: number; fetchImpl?: typeof fetch;
}
export class OwnerContextError extends Error {
  constructor(readonly code: string, readonly state: 'refused'|'unknown'|'not_current') {
    super(`Owner context ${code}`); this.name = 'OwnerContextError';
  }
}
function invalid(): never { throw new OwnerContextError('invalid_request', 'refused'); }
const maxSigned = (1n<<63n)-1n, maxEnvelope = 33075, headerLength = 291;
const scopeNames = ['kind','accountId','deviceId','lineId','intervalId','contextId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'] as const;
const bindingNames = ['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'] as const;
const equal = (a: Uint8Array,b: Uint8Array) => a.length===b.length && a.every((n,i)=>n===b[i]);
const hex = (a: Uint8Array) => Array.from(a,n=>n.toString(16).padStart(2,'0')).join('');
const uuid = (a: Uint8Array) => {const h=hex(a);return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;};
const validUuid = (s: unknown): s is string => typeof s==='string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) && !/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(s);
function data(value: unknown, names: readonly string[], optional: readonly string[]=[]): Record<string,any> {
  if (!value || Object.getPrototypeOf(value)!==Object.prototype) invalid();
  const allowed = new Set([...names,...optional]), keys=Reflect.ownKeys(value);
  if (keys.some(k=>typeof k!=='string'||!allowed.has(k)) || names.some(k=>!Object.hasOwn(value,k))) invalid();
  const copy: Record<string,any>={};
  for(const k of keys){const p=Object.getOwnPropertyDescriptor(value,k)!;if(!Object.hasOwn(p,'value'))invalid();copy[k as string]=p.value;}
  return copy;
}
function bytes(value: unknown,n: number): Uint8Array {
  if(!(value instanceof Uint8Array)||value.length!==n||!value.some(b=>b!==0))invalid();
  return Uint8Array.from(value);
}
function scopeCopy(value: unknown): WorkflowContextScope {
  const d=data(value,scopeNames);
  for(const n of ['accountId','deviceId','lineId','intervalId','contextId'])d[n]=bytes(d[n],16);
  for(const n of ['peerDigest','readerId','manifestDigest'])d[n]=bytes(d[n],32);
  for(const n of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])if(typeof d[n]!=='bigint'||d[n]<1n||d[n]>maxSigned)invalid();
  workflowContextAad(d as WorkflowContextScope); return d as WorkflowContextScope;
}
function bindingCopy(value: unknown): ConversationSignerBinding02 {
  const d=data(value,bindingNames);
  for(const n of ['account','device','line','interval','session'])d[n]=bytes(d[n],16);
  for(const n of ['phoneReader','archiveReader'])d[n]=bytes(d[n],32);
  if(typeof d.generation!=='bigint'||d.generation<1n||d.generation>maxSigned||typeof d.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(d.peer))invalid();
  return d as ConversationSignerBinding02;
}
function sameBinding(a: ConversationSignerBinding02,b: ConversationSignerBinding02): boolean {
  return a.generation===b.generation && a.peer===b.peer && ['account','device','line','interval','session','phoneReader','archiveReader'].every(n=>equal(a[n as 'account'],b[n as 'account']));
}
function parseScope(envelope: Uint8Array): WorkflowContextScope {
  if(envelope.length<headerLength+17||envelope.length>maxEnvelope||!equal(envelope.slice(0,5),new Uint8Array([90,84,87,67,1]))||envelope[222]!==4)invalid();
  const view=new DataView(envelope.buffer,envelope.byteOffset,envelope.byteLength);
  if(view.getUint32(287)!==envelope.length-headerLength)invalid();
  return scopeCopy({kind:envelope[5],accountId:envelope.slice(6,22),deviceId:envelope.slice(22,38),lineId:envelope.slice(38,54),intervalId:envelope.slice(54,70),contextId:envelope.slice(70,86),bindingGeneration:view.getBigUint64(86),revision:view.getBigUint64(94),expiresMs:view.getBigUint64(102),trustGeneration:view.getBigUint64(110),manifestVersion:view.getBigUint64(118),peerDigest:envelope.slice(126,158),readerId:envelope.slice(158,190),manifestDigest:envelope.slice(190,222)});
}
interface RecordWrite {
  ticket: object; requestId: string; expectedRevision: number; scope: WorkflowContextScope;
  envelope: Uint8Array; digest: string; csrf: string; deadline: number;
  attempts: number; verifies: number; unknown: boolean; timer?: ReturnType<typeof setTimeout>;
}
/** Requires an independently supplied authenticated current owner adapter. No cookie/key/bearer input. */
export class OwnerWorkflowContextClient {
  #origin: string; #selection: OwnerContextSelection; #options: OwnerContextOptions;
  #fetch: typeof fetch; #timeout: number; #closed: boolean; #expired=false; #busy=false; #controller=new AbortController();
  #record: RecordWrite|null=null; #pending: OwnerContextPending|null=null;
  #root: Uint8Array|null=null; #generation=0n; #version=0n; #manifestDigest: Uint8Array|null=null; #now=0n;
  constructor(input: OwnerContextOptions) {
    const o=data(input,['origin','selection','readCurrent','currentCsrf','consumeWriteReview','signal'],['enabled','timeoutMs','fetchImpl']);
    const url=new URL(o.origin), selection=data(o.selection,['binding','contextId','kind']);
    if(url.protocol!=='https:'||url.origin!==o.origin||url.username||url.password||url.pathname!=='/'||url.search||url.hash||!['readCurrent','currentCsrf','consumeWriteReview'].every(n=>typeof o[n]==='function')||!(o.signal instanceof AbortSignal)||o.fetchImpl!==undefined&&typeof o.fetchImpl!=='function')invalid();
    if(![1,2,3].includes(selection.kind)||o.enabled!==undefined&&typeof o.enabled!=='boolean')invalid();
    this.#timeout=o.timeoutMs??10000;if(!Number.isSafeInteger(this.#timeout)||this.#timeout<1||this.#timeout>10000)invalid();
    this.#selection={binding:bindingCopy(selection.binding),contextId:bytes(selection.contextId,16),kind:selection.kind};
    this.#origin=url.origin;this.#options={...o} as OwnerContextOptions;this.#fetch=o.fetchImpl??globalThis.fetch.bind(globalThis);
    this.#closed=o.enabled!==true||o.signal.aborted;
    o.signal.addEventListener('abort',this.#abort,{once:true});
    if(this.#closed)this.close();
  }
  #abort=()=>this.close();
  #expire(): void {this.#expired=true;this.close();}
  close(): void {
    if(this.#record)this.#clearTimer(this.#record);
    this.#closed=true;this.#controller.abort();this.#options.signal.removeEventListener('abort',this.#abort);
    this.#record?.envelope.fill(0);this.#record=null;
  }
  pending(): OwnerContextPending|null {return this.#pending?Object.freeze({...this.#pending}):null;}
  #csrf(): string {
    try {const s=this.#options.currentCsrf();if(typeof s!=='string'||s.length<1||s.length>256||/[^\x21-\x7e]/.test(s))invalid();return s;}
    catch {this.close();throw new OwnerContextError('owner_changed','refused');}
  }
  #live(deadline: number): void {
    if(this.#closed||this.#options.signal.aborted)throw new OwnerContextError(this.#expired?'expired':'closed','refused');
    if(performance.now()>=deadline){this.#expire();throw new OwnerContextError('expired','refused');}
  }
  async #race<T>(promise: Promise<T>,deadline: number): Promise<T> {
    const observed=Promise.resolve(promise);
    try{this.#live(deadline);}catch(error){void observed.catch(()=>{});throw error;}
    let timer: ReturnType<typeof setTimeout>|undefined,abort:()=>void=()=>{};
    try{return await Promise.race([observed,new Promise<never>((_,reject)=>{
      abort=()=>reject(new OwnerContextError(this.#expired?'expired':'closed','refused'));this.#controller.signal.addEventListener('abort',abort,{once:true});
      timer=setTimeout(()=>{reject(new OwnerContextError('expired','refused'));this.#expire();},Math.max(0,deadline-performance.now()));
    })]);}finally{if(timer!==undefined)clearTimeout(timer);this.#controller.signal.removeEventListener('abort',abort);}
  }
  async #current(scope: WorkflowContextScope,deadline: number,csrf: string): Promise<number> {
    this.#live(deadline);const started=performance.now();
    try {
      const value=await this.#race(this.#options.readCurrent(),deadline);this.#live(deadline);
      const c=data(value,['binding','manifest','nowMs','ownerSessionLive','consentLive','phase','validForMs']);
      if(c.phase!=='active'||c.ownerSessionLive!==true||c.consentLive!==true||!Number.isFinite(c.validForMs)||c.validForMs<=0||c.validForMs>60000||typeof c.nowMs!=='bigint'||c.nowMs<=0n||c.nowMs<this.#now||!sameBinding(this.#selection.binding,bindingCopy(c.binding)))invalid();
      const id=verifiedManifestIdentity02(c.manifest,c.nowMs), trust=verifiedManifestTrust02(c.manifest,c.nowMs);
      const encoded=Uint8Array.from(c.manifest.bytes);
      const manifest=await this.#race(verifyManifest02(encoded,trust,c.nowMs),deadline);this.#live(deadline);
      if(this.#root && (!equal(this.#root,id.rootPoint)||this.#generation!==id.generation)||id.version<this.#version||id.version===this.#version&&this.#manifestDigest&&!equal(id.digest,this.#manifestDigest))invalid();
      const b=this.#selection.binding;
      if(!equal(scope.accountId,b.account)||!equal(scope.deviceId,b.device)||!equal(scope.lineId,b.line)||!equal(scope.intervalId,b.interval)||!equal(scope.contextId,this.#selection.contextId)||!equal(scope.readerId,b.archiveReader)||scope.bindingGeneration!==b.generation||scope.kind!==this.#selection.kind||scope.trustGeneration!==id.generation||scope.manifestVersion!==id.version||!equal(scope.manifestDigest,id.digest))invalid();
      const peer=new Uint8Array(await this.#race(crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer)),deadline));
      if(!equal(peer,scope.peerDigest)||scope.expiresMs<=c.nowMs||scope.expiresMs-c.nowMs>30n*86400000n)invalid();
      authorizeWorkflowContext02(manifest,{accountId:scope.accountId,deviceId:scope.deviceId,lineId:scope.lineId,readerId:scope.readerId,generation:scope.trustGeneration,version:scope.manifestVersion,digest:scope.manifestDigest},c.nowMs);
      const reader=manifest.keys.find(k=>k.role===2&&equal(k.keyId,scope.readerId));if(!reader)invalid();
      const signer=manifest.keys.find(k=>k.role===4&&k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs&&equal(k.deviceId,scope.deviceId)&&equal(k.lineId,scope.lineId));if(!signer)invalid();
      const remaining=[scope.expiresMs,manifest.expiresMs,reader.untilMs,signer.untilMs].reduce((a,b)=>a<b?a:b)-c.nowMs;
      const capped=Math.min(deadline,started+c.validForMs,started+Number(remaining));this.#live(capped);
      if(this.#csrf()!==csrf)invalid();
      this.#root=Uint8Array.from(id.rootPoint);this.#generation=id.generation;this.#version=id.version;this.#manifestDigest=Uint8Array.from(id.digest);this.#now=c.nowMs;
      return capped;
    } catch(error){this.close();if(error instanceof OwnerContextError)throw error;throw new OwnerContextError('owner_changed','refused');}
  }
  #owned(ticket: object): RecordWrite {
    if(this.#busy)throw new OwnerContextError('busy','refused');
    if(this.#closed&&this.#pending)throw new OwnerContextError(this.#expired?'expired':'closed','unknown');
    const r=this.#record;if(!r||r.ticket!==ticket)throw new OwnerContextError('invalid_ticket','refused');
    try{this.#live(r.deadline);}catch(error){if(this.#pending)throw new OwnerContextError('expired','unknown');throw error;}return r;
  }
  #clearTimer(r: RecordWrite): void {if(r.timer!==undefined){clearTimeout(r.timer);r.timer=undefined;}}
  #deadline(r: RecordWrite,deadline: number): void {
    this.#live(deadline);
    // One idle expiry timer; authority may shorten it but no attempt renews it.
    if(deadline>r.deadline)invalid();
    if(r.timer!==undefined&&deadline===r.deadline)return;
    this.#clearTimer(r);r.deadline=deadline;
    r.timer=setTimeout(()=>{r.timer=undefined;if(this.#record===r)this.#expire();},Math.max(0,deadline-performance.now()));
  }
  #forget(r: RecordWrite): void {this.#clearTimer(r);r.envelope.fill(0);if(this.#record===r)this.#record=null;this.#pending=null;}
  async prepare(input: OwnerContextWrite): Promise<OwnerContextTicket> {
    if(this.#busy||this.#record||this.#pending)throw new OwnerContextError('pending_write','refused');
    this.#live(performance.now()+this.#timeout);
    const d=data(input,['requestId','expectedRevision','scope','envelope']),scope=scopeCopy(d.scope);
    if(!validUuid(d.requestId)||!Number.isSafeInteger(d.expectedRevision)||d.expectedRevision<0||d.expectedRevision>127||scope.revision!==BigInt(d.expectedRevision+1)||!(d.envelope instanceof Uint8Array)||d.envelope.length<headerLength+17||d.envelope.length>maxEnvelope)invalid();
    const envelope=Uint8Array.from(d.envelope);parseScope(envelope);if(!equal(envelope.slice(0,222),workflowContextAad(scope)))invalid();
    const r: RecordWrite={ticket:Object.freeze({}),requestId:d.requestId,expectedRevision:d.expectedRevision,scope,envelope,digest:'',csrf:this.#csrf(),deadline:performance.now()+this.#timeout,attempts:0,verifies:0,unknown:false};
    this.#busy=true;this.#record=r;
    try{
      this.#deadline(r,r.deadline);
      this.#deadline(r,await this.#current(scope,r.deadline,r.csrf));
      await this.#race(crypto.subtle.importKey('raw',Uint8Array.from(envelope.slice(222,287)).buffer,{name:'ECDH',namedCurve:'P-256'},false,[]),r.deadline);
      r.digest=hex(new Uint8Array(await this.#race(crypto.subtle.digest('SHA-256',Uint8Array.from(envelope).buffer),r.deadline)));
      const review=Object.freeze({...this.#identity(r),expectedRevision:r.expectedRevision,scope:scopeCopy(r.scope)});
      await this.#race(this.#options.consumeWriteReview(review),r.deadline);
      this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));return r.ticket;
    }catch(error){this.#clearTimer(r);r.envelope.fill(0);if(this.#record===r)this.#record=null;throw error;}finally{this.#busy=false;}
  }
  #identity(r: RecordWrite): OwnerContextPending {return Object.freeze({requestId:r.requestId,contextId:uuid(r.scope.contextId),revision:Number(r.scope.revision),envelopeDigest:r.digest});}
  async #body(response: Response,limit: number,deadline: number): Promise<Uint8Array> {
    const reader=response.body?.getReader();if(!reader)throw new OwnerContextError('response_unknown','unknown');
    const chunks: Uint8Array[]=[];let size=0;
    try{
      for(;;){const next=await this.#race(reader.read(),deadline);if(next.done)break;size+=next.value.length;if(size>limit)throw new OwnerContextError('response_unknown','unknown');chunks.push(Uint8Array.from(next.value));}
      const out=new Uint8Array(size);let offset=0;for(const c of chunks){out.set(c,offset);offset+=c.length;}return out;
    }finally{void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{ /* A late held read cannot publish content. */ }}
  }
  async #fetchResponse(r: RecordWrite,post: boolean): Promise<Response> {
    this.#live(r.deadline);if(this.#csrf()!==r.csrf){this.close();throw new OwnerContextError('owner_changed','refused');}
    this.#live(r.deadline);
    const url=this.#origin+'/v1/owner/workflow/contexts'+(post?'':'/'+uuid(r.scope.contextId));
    const response=await this.#race(this.#fetch(url,{method:post?'POST':'GET',credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:this.#controller.signal,
      headers:{Accept:post?'application/json':'application/vnd.zrotext.workflow-context.v1','x-zrotext-csrf':r.csrf,...(post?{'Content-Type':'application/vnd.zrotext.workflow-context.v1','idempotency-key':r.requestId,'x-zrotext-context-revision':String(r.expectedRevision)}:{})},...(post?{body:Uint8Array.from(r.envelope).buffer}:{})}),r.deadline);
    if(response.redirected||response.url&&response.url!==url){void response.body?.cancel().catch(()=>{});throw new OwnerContextError('response_unknown','unknown');}return response;
  }
  async #latest(r: RecordWrite,acknowledged: boolean): Promise<OwnerContextReceipt> {
    this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));
    const response=await this.#fetchResponse(r,false);
    if(response.status!==200||response.headers.get('content-type')!=='application/vnd.zrotext.workflow-context.v1'){void response.body?.cancel().catch(()=>{});throw new OwnerContextError('response_unknown','unknown');}
    const returned=await this.#body(response,maxEnvelope,r.deadline);this.#live(r.deadline);
    if(equal(returned,r.envelope)){
      this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));const receipt=Object.freeze({...this.#identity(r),state:'verified_current_snapshot' as const,requestAcknowledged:acknowledged});
      // A byte-identical GET proves current content, not this request's durable acknowledgement.
      if(acknowledged)this.#forget(r);return receipt;
    }
    try{
      const newer=parseScope(returned);
      for(const n of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId'] as const)if(!equal(newer[n],r.scope[n]))invalid();
      if(newer.kind!==r.scope.kind||newer.bindingGeneration!==r.scope.bindingGeneration||newer.trustGeneration!==r.scope.trustGeneration||newer.revision<=r.scope.revision)invalid();
      await this.#race(crypto.subtle.importKey('raw',Uint8Array.from(returned.slice(222,287)).buffer,{name:'ECDH',namedCurve:'P-256'},false,[]),r.deadline);
      this.#deadline(r,await this.#current(newer,r.deadline,r.csrf));
    }catch{throw new OwnerContextError('response_unknown','unknown');}
    if(acknowledged){this.#forget(r);throw new OwnerContextError('head_changed','not_current');}
    throw new OwnerContextError('response_unknown','unknown');
  }
  async #post(ticket: object,retry: boolean): Promise<OwnerContextReceipt> {
    const r=this.#owned(ticket);if(retry?!r.unknown:r.attempts!==0)throw new OwnerContextError('invalid_ticket','refused');
    if(r.attempts>=3)throw new OwnerContextError('attempts_exhausted',r.unknown?'unknown':'refused');
    this.#busy=true;const priorUnknown=r.unknown;let attempted=false;
    try{
      this.#deadline(r,await this.#current(r.scope,r.deadline,r.csrf));this.#live(r.deadline);
      r.attempts++;r.unknown=true;attempted=true;this.#pending=this.#identity(r);
      const response=await this.#fetchResponse(r,true);
      if([400,401,403,404,409,413,429].includes(response.status)){
        void response.body?.cancel().catch(()=>{});
        if(priorUnknown)throw new OwnerContextError('response_unknown','unknown');
        const code: Record<number,string>={400:'invalid_request',401:'unauthorized',403:'forbidden',404:'not_found',409:'conflict',413:'too_large',429:'rate_limited'};
        this.#forget(r);throw new OwnerContextError(code[response.status],'refused');
      }
      if(response.status!==200||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')){void response.body?.cancel().catch(()=>{});throw new OwnerContextError('response_unknown','unknown');}
      const raw=new TextDecoder('utf-8',{fatal:true}).decode(await this.#body(response,64,r.deadline));
      const revision=data(JSON.parse(raw),['revision']).revision;
      if(revision!==Number(r.scope.revision)||raw!==JSON.stringify({revision}))throw new OwnerContextError('response_unknown','unknown');
      return await this.#latest(r,true);
    }catch(error){if(error instanceof OwnerContextError&&(error.state==='not_current'||error.state==='refused'&&this.#record!==r&&!this.#pending))throw error;if(attempted||priorUnknown)throw new OwnerContextError('response_unknown','unknown');throw error;}finally{this.#busy=false;}
  }
  commit(ticket: OwnerContextTicket): Promise<OwnerContextReceipt> {return this.#post(ticket,false);}
  retryUnknown(ticket: OwnerContextTicket): Promise<OwnerContextReceipt> {return this.#post(ticket,true);}
  async verifyUnknown(ticket: OwnerContextTicket): Promise<OwnerContextReceipt> {
    const r=this.#owned(ticket);if(!r.unknown)throw new OwnerContextError('invalid_ticket','refused');if(r.verifies>=3)throw new OwnerContextError('attempts_exhausted','unknown');
    this.#busy=true;r.verifies++;
    try{return await this.#latest(r,false);}catch{throw new OwnerContextError('response_unknown','unknown');}finally{this.#busy=false;}
  }
}
