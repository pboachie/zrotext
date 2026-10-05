// SPDX-License-Identifier: AGPL-3.0-only
/** Unavailable application foundation. This owns the unchanged facts editor,
 * not a deployed page action or a genuine server/PG preparation factory.
 * Typing and delayed Review consume the original conservative window. A real
 * rendered pair still requires its separately selected fixture and runner. */
import {createOwnerContextAuthoring, type OwnerContextAuthoringOptions, type OwnerContextAuthoring, type OwnerAcknowledgedSourceSnapshot} from './owner-context-authoring.js';
import {createOwnerOpeningCapacityClient, type OwnerOpeningCapacityClient, type OpeningCreateInput, type OpeningCreateReview, type OpeningCreateResult, type OpeningCreateTicket, type OpeningMetadataSnapshot, type OpeningPending} from './owner-opening-capacity-client.js';
import {authorizeWorkflowContext02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02} from './draft02-manifest.js';
import {openWorkflowContext, workflowContextAad, type WorkflowContextScope} from './workflow-context.js';
import type {ConversationSignerBinding02} from './conversation-signer.js';

export type AcknowledgedOpeningConsumerOptions = Readonly<{
  /** The consumer constructs this actual author; injected preexisting authors
   * and self-reported author budget provenance are deliberately unsupported. */
  authorOptions: OwnerContextAuthoringOptions & Readonly<{timeoutMs: number; observationMs: number}>;
  expectedScope: WorkflowContextScope; expectedContentDigest: Uint8Array;
  sourceWindowMs: number; totalTimeoutMs: number; observationTimeoutMs: number;
  attemptTimeoutMs: number; maxAttempts: number;
  consumeCreateReview: (review: OpeningCreateReview) => Promise<void>;
}>;
export type AcknowledgedOpeningTicket = Readonly<{kind: 'acknowledged_opening'}>;
export type AcknowledgedOpeningConsumer = Readonly<{
  /** Explicit genuine current observation must finish before actual Review.
   * Construction itself performs no network, key or authority observation. */
  initialize(): Promise<void>;
  prepareCreate(input: OpeningCreateInput): Promise<AcknowledgedOpeningTicket>;
  create(ticket: AcknowledgedOpeningTicket): Promise<OpeningCreateResult>;
  retry(ticket: AcknowledgedOpeningTicket): Promise<OpeningCreateResult>;
  status(openingId: string): Promise<OpeningMetadataSnapshot>;
  state(): Readonly<{closed: boolean; busy: boolean; readyForReview: boolean; pending: OpeningPending|null}>;
  close(): void;
}>;
export class AcknowledgedOpeningError extends Error {
  constructor(readonly code: string) {super('Acknowledged opening unavailable'); this.name='AcknowledgedOpeningError';}
}
const MAX=(1n<<63n)-1n, CONTEXT_CAP=33075, media='application/vnd.zrotext.workflow-context.v1';
const enc=new TextEncoder(), fields=['account','device','line','interval','session','phoneReader','archiveReader'] as const;
const bindingFields=[...fields,'generation','peer'];
const authorFields=['enabled','origin','host','binding','contextId','expiresMs','readCurrent','currentCsrf','archiveLease','onSetupClose','onCustodyClose','signal','timeoutMs','observationMs'];
const optionFields=['authorOptions','expectedScope','expectedContentDigest','sourceWindowMs','totalTimeoutMs','observationTimeoutMs','attemptTimeoutMs','maxAttempts','consumeCreateReview'];
const scopeFields=['kind','accountId','deviceId','lineId','intervalId','contextId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'];
function fail(code='invalid'): never {throw new AcknowledgedOpeningError(code);}
function data(value: unknown, required: readonly string[], optional: readonly string[]=[]): Record<string, any> {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)fail();
  const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors),out:Record<string,any>={};
  if(keys.some(k=>typeof k!=='string'||!required.includes(k)&&!optional.includes(k))||required.some(k=>!Object.hasOwn(descriptors,k)))fail();
  for(const k of keys as string[]){const d=descriptors[k];if(!('value' in d)||!d.enumerable)fail();out[k]=d.value;}return out;
}
function bytes(value:unknown,length:number):Uint8Array {if(!(value instanceof Uint8Array)||value.length!==length||!value.some(v=>v!==0))fail();return Uint8Array.from(value);}
function positive(value:unknown):bigint {if(typeof value!=='bigint'||value<1n||value>MAX)fail();return value;}
function bound(value:unknown,max:number):number {if(!Number.isSafeInteger(value)||typeof value!=='number'||value<1||value>max)fail();return value;}
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hex=(b:Uint8Array)=>Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');
const uuid=(b:Uint8Array)=>hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
function id(value:unknown):string {if(typeof value!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)||/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value))fail();return value;}
function ownBinding(value:unknown):ConversationSignerBinding02 {
  const b=data(value,bindingFields);for(const k of fields)b[k]=bytes(b[k],k.endsWith('Reader')?32:16);
  positive(b.generation);if(typeof b.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))fail();return b as ConversationSignerBinding02;
}
const equalBinding=(a:ConversationSignerBinding02,b:ConversationSignerBinding02)=>a.generation===b.generation&&a.peer===b.peer&&fields.every(k=>same(a[k],b[k]));
function ownScope(value:unknown):WorkflowContextScope {
  const s=data(value,scopeFields);if(s.kind!==1||s.revision!==1n)fail('scope');
  for(const k of ['accountId','deviceId','lineId','intervalId','contextId'])s[k]=bytes(s[k],16);
  for(const k of ['peerDigest','readerId','manifestDigest'])s[k]=bytes(s[k],32);
  for(const k of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])positive(s[k]);
  workflowContextAad(s as WorkflowContextScope);return s as WorkflowContextScope;
}
function ownSource(value:unknown,account:string,context:string):OwnerAcknowledgedSourceSnapshot {
  const s=data(value,['accountId','receipt']),r=data(s.receipt,['requestId','contextId','revision','envelopeDigest','state','requestAcknowledged']);
  if(id(s.accountId)!==account||id(r.contextId)!==context||r.revision!==1||r.state!=='verified_current_snapshot'||r.requestAcknowledged!==true||typeof r.envelopeDigest!=='string'||!/^[0-9a-f]{64}$/.test(r.envelopeDigest)||/^0{64}$/.test(r.envelopeDigest))fail('source');
  id(r.requestId);return Object.freeze({accountId:account,receipt:Object.freeze({...r})}) as OwnerAcknowledgedSourceSnapshot;
}
const equalSource=(a:OwnerAcknowledgedSourceSnapshot,b:OwnerAcknowledgedSourceSnapshot)=>a.accountId===b.accountId&&['requestId','contextId','revision','envelopeDigest','state','requestAcknowledged'].every(k=>(a.receipt as any)[k]===(b.receipt as any)[k]);

class Consumer {
  #a:OwnerContextAuthoringOptions|null;#options:AcknowledgedOpeningConsumerOptions|null;#scope:WorkflowContextScope|null;
  #binding:ConversationSignerBinding02|null;#contentDigest:Uint8Array|null;#account:string;#context:string;
  #author:OwnerContextAuthoring|null=null;#client:OwnerOpeningCapacityClient|null=null;
  #controller=new AbortController();#closed=false;#ready=false;#reviewStarted=false;#used=false;
  #deadline:number;#timer:ReturnType<typeof setTimeout>|null=null;#operation=false;
  #work=new Set<Promise<unknown>>();#buffers=new Set<Uint8Array>();#removers:(()=>void)[]=[];
  #lastNow=0n;#root:Uint8Array|null=null;#pending:OpeningPending|null=null;
  #tickets=new WeakMap<AcknowledgedOpeningTicket,OpeningCreateTicket>();#ticket:AcknowledgedOpeningTicket|null=null;
  #reviewButton:HTMLButtonElement|null=null;#clearButton:HTMLButtonElement|null=null;#editor:HTMLTextAreaElement|null=null;
  constructor(input:AcknowledgedOpeningConsumerOptions){
    // B precedes all option capture, genuine author construction and Review.
    const B=performance.now(),o=data(input,optionFields),a=data(o.authorOptions,authorFields,['fetchImpl']);
    if(a.enabled!==true)fail('disabled');
    const lease=data(a.archiveLease,['withKey','close','onClose']);
    if(!(a.signal instanceof AbortSignal)||a.signal.aborted||['readCurrent','currentCsrf','onSetupClose','onCustodyClose'].some(k=>typeof a[k]!=='function')||typeof o.consumeCreateReview!=='function'||['withKey','close','onClose'].some(k=>typeof lease[k]!=='function')||!Object.isFrozen(a.archiveLease)||a.fetchImpl!==undefined&&typeof a.fetchImpl!=='function')fail();
    bound(a.timeoutMs,10000);bound(a.observationMs,10000);bound(o.sourceWindowMs,10000);bound(o.totalTimeoutMs,60000);bound(o.observationTimeoutMs,10000);bound(o.attemptTimeoutMs,10000);bound(o.maxAttempts,3);
    if(o.sourceWindowMs>Math.min(a.timeoutMs,a.observationMs)||o.totalTimeoutMs>o.sourceWindowMs)fail('joint_clock');
    const b=ownBinding(a.binding),s=ownScope(o.expectedScope),context=bytes(a.contextId,16),digest=bytes(o.expectedContentDigest,32);
    positive(a.expiresMs);
    if(!same(s.accountId,b.account)||!same(s.deviceId,b.device)||!same(s.lineId,b.line)||!same(s.intervalId,b.interval)||!same(s.contextId,context)||!same(s.readerId,b.archiveReader)||s.bindingGeneration!==b.generation||s.expiresMs!==a.expiresMs)fail('scope');
    if(typeof a.origin!=='string'||a.origin.length<1||a.origin.length>512||/[^\x21-\x7e]/.test(a.origin))fail();
    let origin:URL;try{origin=new URL(a.origin);}catch{fail();}if(origin.protocol!=='https:'||origin.origin!==a.origin)fail();
    const document=a.host?.ownerDocument,window=document?.defaultView;
    if(a.host?.nodeType!==1||!document||!window||window.location.origin!==a.origin||document.hidden)fail('host');
    this.#binding=b;this.#scope=s;this.#contentDigest=digest;this.#account=uuid(b.account);this.#context=uuid(context);
    this.#deadline=B+Math.min(o.sourceWindowMs,o.totalTimeoutMs);
    this.#a={...a,binding:b,contextId:context} as OwnerContextAuthoringOptions;
    this.#options={...o,authorOptions:this.#a,expectedScope:s,expectedContentDigest:digest} as AcknowledgedOpeningConsumerOptions;
    for(const buffer of [...fields.map(k=>b[k]),context,digest,...['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'].map(k=>(s as any)[k] as Uint8Array)])this.#buffers.add(buffer);
    try{
      this.#arm();
      const close=()=>this.close(),listen=(target:EventTarget,event:string,listener:EventListener,capture=false)=>{target.addEventListener(event,listener,capture);this.#removers.push(()=>target.removeEventListener(event,listener,capture));};
      listen(a.signal,'abort',close);listen(window,'pagehide',close);listen(document,'visibilitychange',()=>{if(document.hidden)this.close();});
      for(const subscribe of [a.onSetupClose,a.onCustodyClose,(listener:()=>void)=>a.archiveLease.onClose(listener)]){
        this.#live();const remove=subscribe(close);if(remove!==undefined&&typeof remove!=='function')fail('lifecycle');
        if(remove){if(this.#closed)remove();else this.#removers.push(remove);}
      }
      // Capture handlers are installed before the unchanged editor's handlers.
      // They govern only the exact newly constructed editor controls.
      listen(a.host,'click',event=>{
        if(event.target===this.#clearButton){this.close();return;}
        if(event.target===this.#reviewButton){
          if(this.#closed||!this.#ready||this.#reviewStarted){event.preventDefault();event.stopImmediatePropagation();return;}
          try{this.#live();this.#reviewStarted=true;}catch{event.preventDefault();event.stopImmediatePropagation();}
        }
      },true);
      listen(a.host,'input',event=>{if(event.target===this.#editor&&this.#reviewStarted)this.close();},true);
      this.#live();
      // This is the actual maintained constructor, never an injected author.
      // Captured explicit timeoutMs/observationMs are forwarded unchanged.
      this.#author=createOwnerContextAuthoring(this.#a!);
      const pane=a.host.lastElementChild as HTMLElement|null;
      if(!pane||pane.getAttribute('aria-label')!=='Owner facts')fail('host');
      const buttons=Array.from(pane.querySelectorAll('button'));
      this.#reviewButton=buttons.find(b=>b.textContent==='Review facts')??null;
      this.#clearButton=buttons.find(b=>b.textContent==='Clear')??null;
      this.#editor=pane.querySelector('textarea');
      if(!this.#reviewButton||!this.#clearButton||!this.#editor)fail('host');
      this.#live();
    }catch(error){this.close();throw error;}
  }
  #arm(){if(this.#timer!==null)clearTimeout(this.#timer);this.#timer=setTimeout(()=>this.close(),Math.max(0,this.#deadline-performance.now()));}
  #cap(deadline:number){if(!Number.isFinite(deadline))fail('clock');if(deadline<this.#deadline){this.#deadline=deadline;this.#arm();}this.#live();}
  #live(){
    if(this.#closed||this.#a!.signal.aborted||this.#a!.host.ownerDocument.hidden||performance.now()>=this.#deadline){this.close();fail('closed');}
    const phase=this.#author?.state().phase;
    if(phase==='closed'||phase==='refused'){this.close();fail('source_closed');}
  }
  #csrf(){this.#live();const value=this.#a!.currentCsrf();this.#live();if(typeof value!=='string'||value.length<1||value.length>256||/[^\x21-\x7e]/.test(value))fail('csrf');return value;}
  #track<T>(promise:Promise<T>):Promise<T>{this.#work.add(promise);void promise.finally(()=>this.#work.delete(promise)).catch(()=>{});return promise;}
  #release(buffer:Uint8Array){buffer.fill(0);this.#buffers.delete(buffer);}
  #digest(value:Uint8Array,deadline=this.#deadline):Promise<Uint8Array>{
    const owned=Uint8Array.from(value);this.#buffers.add(owned);
    const operation=(async()=>{
      try{
        this.#live();const output=new Uint8Array(await crypto.subtle.digest('SHA-256',owned.buffer));
        try{this.#live();this.#buffers.add(output);return output;}catch(error){output.fill(0);throw error;}
      }finally{this.#release(owned);}
    })();
    // This owned plaintext/hash copy remains charged until actual crypto settles.
    // WebCrypto/engine copies still have the documented best-effort limitation.
    return this.#wait(operation,deadline);
  }
  #busy(){return this.#operation||this.#work.size>0||this.#client?.state().busy===true;}
  #wait<T>(promise:Promise<T>,deadline=this.#deadline):Promise<T>{
    const work=this.#track(promise);
    return new Promise((resolve,reject)=>{
      let done=false;const finish=(f:()=>void)=>{if(done)return;done=true;clearTimeout(timer);this.#controller.signal.removeEventListener('abort',abort);f();};
      const abort=()=>finish(()=>reject(new AcknowledgedOpeningError('closed'))),timer=setTimeout(()=>{this.close();finish(()=>reject(new AcknowledgedOpeningError('timeout')));},Math.max(0,Math.min(this.#deadline,deadline)-performance.now()));
      this.#controller.signal.addEventListener('abort',abort,{once:true});if(this.#controller.signal.aborted)abort();
      work.then(v=>finish(()=>resolve(v)),()=>finish(()=>reject(new AcknowledgedOpeningError('unavailable'))));
    });
  }
  async #run<T>(operation:()=>Promise<T>):Promise<T>{
    this.#live();if(this.#busy())fail('busy');this.#operation=true;
    const work=operation();void work.finally(()=>{this.#operation=false;}).catch(()=>{});
    try{const result=await this.#wait(work);this.#live();return result;}catch(error){this.close();throw error;}
  }
  async #observe():Promise<{manifest:Manifest02;nowMs:bigint}>{
    this.#live();const started=performance.now(),deadline=Math.min(this.#deadline,started+this.#options!.observationTimeoutMs);
    const c=data(await this.#wait(Promise.resolve().then(()=>{this.#live();return this.#a!.readCurrent();}),deadline),['binding','manifest','nowMs','ownerSessionLive','consentLive']);this.#live();
    if(c.ownerSessionLive!==true||c.consentLive!==true||!equalBinding(this.#binding!,ownBinding(c.binding)))fail('current');positive(c.nowMs);if(c.nowMs<this.#lastNow)fail('clock');
    const initial=verifiedManifestIdentity02(c.manifest,c.nowMs),encoded=Uint8Array.from(c.manifest.bytes),trust=verifiedManifestTrust02(c.manifest,c.nowMs);
    const manifest=await this.#wait(verifyManifest02(encoded,trust,c.nowMs),deadline);this.#live();
    const identity=verifiedManifestIdentity02(manifest,c.nowMs),s=this.#scope!;
    if(initial.generation!==identity.generation||initial.version!==identity.version||!same(initial.accountId,identity.accountId)||!same(initial.rootPoint,identity.rootPoint)||!same(initial.digest,identity.digest)||!same(identity.accountId,s.accountId)||identity.generation!==s.trustGeneration||identity.version!==s.manifestVersion||!same(identity.digest,s.manifestDigest)||this.#root!==null&&!same(identity.rootPoint,this.#root))fail('expected');
    authorizeWorkflowContext02(manifest,{accountId:s.accountId,deviceId:s.deviceId,lineId:s.lineId,readerId:s.readerId,generation:s.trustGeneration,version:s.manifestVersion,digest:s.manifestDigest},c.nowMs);
    const active=(k:typeof manifest.keys[number])=>k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs;
    const phone=manifest.keys.find(k=>k.role===1&&active(k)&&same(k.keyId,this.#binding!.phoneReader)&&same(k.deviceId,s.deviceId)&&same(k.lineId,s.lineId));
    const archive=manifest.keys.find(k=>k.role===2&&active(k)&&same(k.keyId,s.readerId));
    const signer=manifest.keys.find(k=>k.role===4&&active(k)&&same(k.deviceId,s.deviceId)&&same(k.lineId,s.lineId));
    if(!phone||!archive||!signer)fail('current');
    const remaining=[manifest.expiresMs,phone.untilMs,archive.untilMs,signer.untilMs,s.expiresMs].reduce((a,b)=>a<b?a:b)-c.nowMs;
    if(remaining<=0n)fail('expiry');this.#cap(started+Number(remaining>60000n?60000n:remaining));
    const peerBytes=enc.encode(this.#binding!.peer);let peer:Uint8Array;
    try{peer=await this.#digest(peerBytes,deadline);}finally{peerBytes.fill(0);}this.#live();
    const peerMatches=same(peer,s.peerDigest);this.#release(peer);if(!peerMatches)fail('expected');
    this.#lastNow=c.nowMs;this.#root=Uint8Array.from(identity.rootPoint);return {manifest,nowMs:c.nowMs};
  }
  initialize():Promise<void>{
    return this.#run(async()=>{if(this.#ready||this.#reviewStarted)fail('used');const csrf=this.#csrf();await this.#observe();this.#live();if(csrf!==this.#csrf())fail('csrf');this.#ready=true;});
  }
  async #getEnvelope(csrf:string):Promise<Uint8Array>{
    const url=this.#a!.origin+'/v1/owner/workflow/contexts/'+this.#context,deadline=Math.min(this.#deadline,performance.now()+this.#options!.attemptTimeoutMs),abort=new AbortController(),closed=()=>abort.abort();
    this.#controller.signal.addEventListener('abort',closed,{once:true});
    const operation=(async()=>{
      const response=await (this.#a!.fetchImpl??fetch)(url,{method:'GET',headers:{accept:media,'x-zrotext-csrf':csrf},credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:abort.signal});
      let reader:ReadableStreamDefaultReader<Uint8Array>|null=null,ended=false;const parts:Uint8Array[]=[];
      try{
        this.#live();if(abort.signal.aborted||performance.now()>=deadline||response.status!==200||response.url!==url||response.redirected||response.headers.get('content-type')!==media||!response.body)fail('response');
        reader=response.body.getReader();let length=0;
        for(;;){const part=await reader.read();this.#live();if(abort.signal.aborted||performance.now()>=deadline)fail('timeout');if(part.done){ended=true;break;}if(!(part.value instanceof Uint8Array)||length+part.value.length>CONTEXT_CAP)fail('response');const owned=Uint8Array.from(part.value);parts.push(owned);this.#buffers.add(owned);length+=owned.length;}
        if(length<308)fail('response');const envelope=new Uint8Array(length);let at=0;for(const part of parts){envelope.set(part,at);at+=part.length;}this.#buffers.add(envelope);return envelope;
      }finally{
        if(!ended)try{if(reader)await reader.cancel();else await response.body?.cancel();}catch{}
        try{reader?.releaseLock();}catch{}
        for(const part of parts){part.fill(0);this.#buffers.delete(part);}
      }
    })();
    void operation.finally(()=>this.#controller.signal.removeEventListener('abort',closed)).catch(()=>{});
    try{return await this.#wait(operation,deadline);}finally{abort.abort();}
  }
  prepareCreate(input:OpeningCreateInput):Promise<AcknowledgedOpeningTicket>{
    const i=data(input,['requestId','openingId','capacity','decisionDeadlineMs']);id(i.requestId);id(i.openingId);positive(i.decisionDeadlineMs);bound(i.capacity,100);
    return this.#run(async()=>{
      if(!this.#ready||!this.#reviewStarted||this.#used||this.#author?.state().phase!=='saved')fail('source');this.#used=true;
      const source=ownSource(this.#author!.savedSource(),this.#account,this.#context),csrf=this.#csrf();
      let envelope:Uint8Array|null=null,plaintext:Uint8Array|null=null;let calls=0,completed=false,accepting=true;
      try{
        const current=await this.#observe();envelope=await this.#getEnvelope(csrf);this.#live();
        const ciphertextDigest=await this.#digest(envelope);this.#live();
        const ciphertextMatches=hex(ciphertextDigest)===source.receipt.envelopeDigest;this.#release(ciphertextDigest);if(!ciphertextMatches)fail('digest');
        const ownedEnvelope=envelope;
        try{
          await this.#wait(this.#a!.archiveLease.withKey(this.#binding!,key=>{
            calls++;if(!accepting||calls!==1)fail('callback');
            return this.#track((async()=>{
              this.#live();const actual=await openWorkflowContext(current.manifest,this.#scope!,current.nowMs,key,ownedEnvelope);
              try{this.#live();plaintext=actual;this.#buffers.add(actual);completed=true;}finally{if(!completed)actual.fill(0);}
            })());
          }));
        }finally{accepting=false;}
        this.#live();const content=plaintext as Uint8Array|null;if(calls!==1||!completed||content===null)fail('callback');
        // The lease's return value is ignored: only actual callback plaintext is used.
        const contentDigest=await this.#digest(content);this.#live();
        const contentMatches=same(contentDigest,this.#contentDigest!);this.#release(contentDigest);if(!contentMatches)fail('content');
        await this.#observe();this.#live();if(csrf!==this.#csrf()||!equalSource(source,ownSource(this.#author!.savedSource(),this.#account,this.#context)))fail('changed');
        const remaining=Math.floor(this.#deadline-performance.now());if(remaining<1||this.#client!==null)fail('clock');
        this.#client=createOwnerOpeningCapacityClient({enabled:true,origin:this.#a!.origin,binding:this.#binding!,contextId:this.#a!.contextId,sourceExpiresMs:this.#scope!.expiresMs,readSavedSource:()=>this.#author?.savedSource()??null,readCurrent:this.#a!.readCurrent,currentCsrf:this.#a!.currentCsrf,consumeCreateReview:async review=>{
          this.#live();if(review.accountId!==this.#account||review.requestId!==i.requestId||review.openingId!==i.openingId||review.capacity!==i.capacity||review.decisionDeadlineMs!==i.decisionDeadlineMs||!equalSource(source,ownSource(review.source,this.#account,this.#context)))fail('review');
          await this.#options!.consumeCreateReview(review);this.#live();
        },signal:this.#controller.signal,onSetupClose:this.#a!.onSetupClose,onCustodyClose:listener=>this.#a!.archiveLease.onClose(listener),totalTimeoutMs:remaining,attemptTimeoutMs:this.#options!.attemptTimeoutMs,observationTimeoutMs:this.#options!.observationTimeoutMs,maxAttempts:this.#options!.maxAttempts,...(this.#a!.fetchImpl?{fetchImpl:this.#a!.fetchImpl}:{})});
        const actual=await this.#wait(this.#client.prepareCreate(i as OpeningCreateInput));this.#live();
        await this.#observe();if(csrf!==this.#csrf()||!equalSource(source,ownSource(this.#author!.savedSource(),this.#account,this.#context)))fail('changed');this.#live();
        const ticket=Object.freeze({kind:'acknowledged_opening' as const});this.#tickets.set(ticket,actual);this.#ticket=ticket;return ticket;
      }finally{
        accepting=false;
        if(envelope){envelope.fill(0);this.#buffers.delete(envelope);}
        if(plaintext){(plaintext as Uint8Array).fill(0);this.#buffers.delete(plaintext);}
      }
    });
  }
  async #dispatch(ticket:AcknowledgedOpeningTicket,replay:boolean):Promise<OpeningCreateResult>{
    const actual=this.#tickets.get(ticket);
    if(!actual||ticket!==this.#ticket||!this.#client)return this.#pending?Object.freeze({state:'unknown',pending:this.#pending,code:'ticket'}):Object.freeze({state:'refused',code:'ticket'});
    try{
      // Lifecycle-only checks; no source, current or key reads on dispatch/replay.
      this.#live();if(this.#busy())return this.#pending?Object.freeze({state:'unknown',pending:this.#pending,code:'busy'}):Object.freeze({state:'refused',code:'busy'});
      const result=await this.#wait(replay?this.#client.retry(actual):this.#client.create(actual));this.#live();
      if(result.state==='unknown')this.#pending=result.pending;
      if(result.state!=='unknown'){this.#tickets.delete(ticket);this.#ticket=null;if(result.state==='acknowledged')this.#pending=null;}
      return result;
    }catch(error){
      this.close();return this.#pending?Object.freeze({state:'unknown',pending:this.#pending,code:'closed'}):Object.freeze({state:'refused',code:error instanceof AcknowledgedOpeningError?error.code:'unavailable'});
    }
  }
  create=(ticket:AcknowledgedOpeningTicket)=>this.#dispatch(ticket,false);
  retry=(ticket:AcknowledgedOpeningTicket)=>this.#dispatch(ticket,true);
  async status(openingId:string):Promise<OpeningMetadataSnapshot>{
    this.#live();if(!this.#client||this.#busy())fail('busy');
    try{const result=await this.#wait(this.#client.status(id(openingId)));this.#live();return result;}catch(error){this.close();throw error;}
  }
  state=()=>Object.freeze({closed:this.#closed,busy:this.#busy(),readyForReview:this.#ready&&!this.#closed,pending:this.#pending?Object.freeze({...this.#pending}):null});
  close=()=>{
    if(this.#closed)return;this.#closed=true;this.#ready=false;
    if(this.#ticket)this.#tickets.delete(this.#ticket);this.#ticket=null;
    for(const buffer of this.#buffers)buffer.fill(0);this.#buffers.clear();this.#root?.fill(0);this.#root=null;
    if(this.#timer!==null){clearTimeout(this.#timer);this.#timer=null;}
    const cleanup=this.#removers.splice(0);
    // Tickets/owned content are invalidated before abort and subscriber callbacks.
    try{this.#client?.close();this.#pending=this.#client?.state().pending??this.#pending;}finally{
      try{this.#author?.close();}finally{this.#author=null;this.#a=null;this.#options=null;this.#scope=null;this.#binding=null;this.#contentDigest=null;this.#account='';this.#context='';this.#reviewButton=null;this.#clearButton=null;this.#editor=null;try{this.#controller.abort();}finally{for(const remove of cleanup)try{remove();}catch{}}}
    }
  };
  public():AcknowledgedOpeningConsumer{return Object.freeze({initialize:this.initialize.bind(this),prepareCreate:this.prepareCreate.bind(this),create:this.create,retry:this.retry,status:this.status.bind(this),state:this.state,close:this.close});}
}
export function createAcknowledgedOpeningConsumer(options:AcknowledgedOpeningConsumerOptions):AcknowledgedOpeningConsumer{return new Consumer(options).public();}
