// SPDX-License-Identifier: AGPL-3.0-only
/** Local review only. Application-supplied custody/current observations are not send authority. */
import { authorizeWorkflowContext02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02 } from './draft02-manifest.js';
import type { ConversationSignerBinding02, ConversationSignerCurrent02 } from './conversation-signer.js';
import type { ArchiveReaderLease02 } from './conversation-archive-custody.js';
import { openWorkflowContext, workflowContextAad, type WorkflowContextScope } from './workflow-context.js';

export interface OwnerProviderDisclosureOptions {
  enabled: boolean; origin: string; host: HTMLElement; binding: ConversationSignerBinding02;
  source: Readonly<{scope: WorkflowContextScope; envelopeDigest: string}>;
  configuration: Readonly<{configId: string; configVersion: number; recordVersion: number}>;
  archiveLease: ArchiveReaderLease02; readCurrent: () => Promise<ConversationSignerCurrent02|null>;
  currentCsrf: () => string; onSetupClose: (listener:()=>void)=>()=>void;
  onCustodyClose: (listener:()=>void)=>()=>void; signal: AbortSignal;
  timeoutMs?: number; observationMs?: number; fetchImpl?: typeof fetch;
}
export type DisclosureReviewTicket = object;
export type DisclosureReviewIdentity = Readonly<{
  account_id: string; context_id: string; context_revision: number; source_envelope_digest: string;
  config_id: string; config_version: number; config_record_version: number; declaration_digest: string;
  rendered_body_digest: string; recipient_commitment: string; reader_key_id: string;
  trust_generation: number; manifest_version: number; manifest_digest: string;
}>;
export type DisclosureReviewCommitment = DisclosureReviewIdentity & Readonly<{
  review_binding_digest: string; state: 'local_reviewed_unavailable'; execution: 'unavailable';
}>;
type Phase = 'unavailable'|'idle'|'preparing'|'prepared'|'reviewing'|'reviewed'|'closed';
export interface OwnerProviderDisclosureReview {
  prepare(body: string): Promise<DisclosureReviewTicket>;
  review(ticket: DisclosureReviewTicket): Promise<DisclosureReviewCommitment>;
  pending(): DisclosureReviewIdentity|null;
  state(): Readonly<{phase: Phase; execution: 'unavailable'}>;
  close(): void;
}
const scopeNames=['kind','accountId','deviceId','lineId','intervalId','contextId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest'];
const bindingNames=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'];
const declarationNames=['adapter','organization_id','messaging_profile_id','sender','owner_label','intended_region','retention_policy_ref','eligibility_policy_ref','cost_policy_ref'];
const reasons=['provider_identity_unverified','sender_eligibility_unverified','policy_unaccepted','cost_bound_unavailable'];
const encoder=new TextEncoder(), decoder=new TextDecoder('utf-8',{fatal:true}), signed=(1n<<63n)-1n;
function refused(): never {throw Error('Local provider review unavailable');}
function data(value: unknown, required: readonly string[], optional: readonly string[]=[]): Record<string,any> {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)refused();
  const keys=Reflect.ownKeys(value),allowed=new Set([...required,...optional]),out:Record<string,any>={};
  if(keys.some(k=>typeof k!=='string'||!allowed.has(k))||required.some(k=>!Object.hasOwn(value,k)))refused();
  for(const k of keys){const p=Object.getOwnPropertyDescriptor(value,k)!;if(!Object.hasOwn(p,'value'))refused();out[k as string]=p.value;}
  return out;
}
const equal=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const hex=(b:Uint8Array)=>Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');
const uuid=(b:Uint8Array)=>hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const validUuid=(v:unknown):v is string=>typeof v==='string'&&v.length===36&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)&&v!=='00000000-0000-0000-0000-000000000000';
const digest=(v:unknown):v is string=>typeof v==='string'&&v.length===64&&/^[0-9a-f]+$/.test(v);
const e164=(v:unknown):v is string=>typeof v==='string'&&v.length>=3&&v.length<=16&&/^\+[1-9][0-9]+$/.test(v);
const text=(v:unknown):v is string=>typeof v==='string'&&v.length>=1&&v.length<=64&&!/[^\x21-\x7e]/.test(v);
const integer=(v:unknown,min=1,max=Number.MAX_SAFE_INTEGER):v is number=>Number.isSafeInteger(v)&&Number(v)>=min&&Number(v)<=max;
function bytes(v:unknown,n:number):Uint8Array {if(!(v instanceof Uint8Array)||v.length!==n||!v.some(v=>v!==0))refused();return Uint8Array.from(v);}
function binding(value:unknown):ConversationSignerBinding02 {
  const b=data(value,bindingNames);for(const n of ['account','device','line','interval','session'])b[n]=bytes(b[n],16);
  for(const n of ['phoneReader','archiveReader'])b[n]=bytes(b[n],32);
  if(typeof b.generation!=='bigint'||b.generation<1n||b.generation>signed||!e164(b.peer))refused();return b as ConversationSignerBinding02;
}
function scope(value:unknown):WorkflowContextScope {
  const s=data(value,scopeNames);for(const n of ['accountId','deviceId','lineId','intervalId','contextId'])s[n]=bytes(s[n],16);
  for(const n of ['peerDigest','readerId','manifestDigest'])s[n]=bytes(s[n],32);
  for(const n of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])if(typeof s[n]!=='bigint'||s[n]<1n||s[n]>signed)refused();
  if(s.kind!==1||s.revision>128n)refused();workflowContextAad(s as WorkflowContextScope);return s as WorkflowContextScope;
}
function sameBinding(a:ConversationSignerBinding02,b:ConversationSignerBinding02):boolean {
  return a.generation===b.generation&&a.peer===b.peer&&['account','device','line','interval','session','phoneReader','archiveReader'].every(k=>equal(a[k as 'account'],b[k as 'account']));
}
function canonical(v:Record<string,any>):string {
  return JSON.stringify(Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])));
}
function details(raw:Uint8Array,selection:OwnerProviderDisclosureOptions['configuration']):Record<string,any> {
  const wire=decoder.decode(raw),d=data(JSON.parse(wire),['config_id','config_version','record_version','state','acceptance','declaration','unavailable_reasons']);
  if(d.config_id!==selection.configId||d.config_version!==selection.configVersion||d.record_version!==selection.recordVersion||d.state!=='draft'||d.acceptance!=='unavailable'||!Array.isArray(d.unavailable_reasons)||JSON.stringify(d.unavailable_reasons)!==JSON.stringify(reasons))refused();
  const declaration=data(d.declaration,declarationNames);
  if(declaration.adapter!=='telnyx-sms-v2'||!validUuid(declaration.organization_id)||!validUuid(declaration.messaging_profile_id)||!e164(declaration.sender)||!text(declaration.owner_label)||!text(declaration.intended_region))refused();
  for(const k of declarationNames.slice(6))if(declaration[k]!==null&&!validUuid(declaration[k]))refused();
  // Match actual maintained serde field order; JSON.parse alone cannot reject duplicate keys.
  const ordered=Object.fromEntries(declarationNames.map(k=>[k,declaration[k]]));
  const projection={config_id:d.config_id,config_version:d.config_version,record_version:d.record_version,state:d.state,acceptance:d.acceptance,declaration:ordered,unavailable_reasons:d.unavailable_reasons};
  if(wire!==JSON.stringify(projection))refused();return ordered;
}

class LocalReview {
  #o:OwnerProviderDisclosureOptions; #binding:ConversationSignerBinding02; #scope:WorkflowContextScope;
  #window:Window; #document:Document; #fetch:typeof fetch; #phase:Phase='idle'; #closed=false; #started=false;
  #deadline=Infinity; #timer?:ReturnType<typeof setTimeout>; #controller=new AbortController(); #cleanup:Array<()=>void>=[];
  #ticket:object|null=null; #identity:DisclosureReviewIdentity|null=null; #csrfValue:string|null=null;
  #body:Uint8Array|null=null; #envelope:Uint8Array|null=null; #facts:Uint8Array|null=null; #declaration:Record<string,any>|null=null;
  #root:Uint8Array|null=null; #now=0n; #version=0n; #manifestDigest:Uint8Array|null=null;
  #region:HTMLElement; #status:HTMLElement; #button:HTMLButtonElement; #cancel:HTMLButtonElement;
  #decision:{resolve:()=>void;reject:(error:Error)=>void}|null=null; #reviewNodes:HTMLElement[]=[]; #reviewText:string[]=[];
  constructor(input:OwnerProviderDisclosureOptions) {
    const o=data(input,['enabled','origin','host','binding','source','configuration','archiveLease','readCurrent','currentCsrf','onSetupClose','onCustodyClose','signal'],['timeoutMs','observationMs','fetchImpl']);
    const source=data(o.source,['scope','envelopeDigest']),config=data(o.configuration,['configId','configVersion','recordVersion']);
    const doc=o.host?.ownerDocument,win=doc?.defaultView,url=new URL(o.origin);
    if(!doc||!win||!(o.host instanceof win.HTMLElement)||o.host.nodeType!==1||o.host.isConnected!==true||typeof o.host.replaceChildren!=='function'||win.location.origin!==o.origin||url.protocol!=='https:'||url.origin!==o.origin||o.origin.length>512||/[^\x21-\x7e]/.test(o.origin)||typeof o.enabled!=='boolean'||!(o.signal instanceof AbortSignal))refused();
    if(!['readCurrent','currentCsrf','onSetupClose','onCustodyClose'].every(k=>typeof o[k]==='function')||!['withKey','close','onClose'].every(k=>typeof o.archiveLease?.[k]==='function')||o.fetchImpl!==undefined&&typeof o.fetchImpl!=='function')refused();
    if(!digest(source.envelopeDigest)||!validUuid(config.configId)||!integer(config.configVersion,1,16)||!integer(config.recordVersion)||!integer(o.timeoutMs??10000,1,10000)||!integer(o.observationMs??1000,1,1000))refused();
    this.#binding=binding(o.binding);this.#scope=scope(source.scope);this.#window=win;this.#document=doc;
    this.#o={...o,source:{scope:this.#scope,envelopeDigest:source.envelopeDigest},configuration:{...config},timeoutMs:o.timeoutMs??10000,observationMs:o.observationMs??1000} as OwnerProviderDisclosureOptions;
    this.#fetch=o.fetchImpl??globalThis.fetch.bind(globalThis);
    this.#status=doc.createElement('p');this.#status.setAttribute('role','status');this.#status.textContent='Configuration is unaccepted. Sending is unavailable.';
    this.#region=doc.createElement('section');this.#region.setAttribute('aria-label','Local disclosure review');this.#region.hidden=true;
    this.#button=doc.createElement('button');this.#button.textContent='Review locally';this.#button.disabled=true;
    this.#cancel=doc.createElement('button');this.#cancel.textContent='Cancel';o.host.replaceChildren(this.#status,this.#region,this.#button,this.#cancel);
    const listen=(target:EventTarget,event:string,run:()=>void)=>{target.addEventListener(event,run);this.#cleanup.push(()=>target.removeEventListener(event,run));};
    listen(this.#button,'click',()=>{try{this.#visible();this.#decision?.resolve();}catch{this.close();}});
    listen(this.#cancel,'click',()=>this.close());listen(o.signal,'abort',()=>this.close());listen(win,'pagehide',()=>this.close());listen(doc,'visibilitychange',()=>{if(doc.hidden)this.close();});
    try {for(const subscribe of [o.onSetupClose,o.onCustodyClose,(listener:()=>void)=>o.archiveLease.onClose(listener)]){const release=subscribe(()=>this.close());if(typeof release!=='function')refused();if(this.#closed){try{release();}catch{}}else this.#cleanup.push(release);}}
    catch {this.close();refused();}
    if(!o.enabled||o.signal.aborted||doc.hidden){this.close();if(!o.enabled)this.#phase='unavailable';}
  }
  state(){return Object.freeze({phase:this.#phase,execution:'unavailable' as const});}
  pending(){return this.#identity?Object.freeze({...this.#identity}):null;}
  #scrub(){for(const value of [this.#body,this.#envelope,this.#facts])value?.fill(0);this.#body=null;this.#envelope=null;this.#facts=null;this.#declaration=null;this.#reviewNodes=[];this.#reviewText=[];this.#region.replaceChildren();this.#region.hidden=true;}
  close(){
    if(this.#closed)return;this.#closed=true;this.#controller.abort();if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=undefined;
    this.#ticket=null;this.#csrfValue=null;this.#root?.fill(0);this.#manifestDigest?.fill(0);this.#root=null;this.#manifestDigest=null;
    this.#decision?.reject(Error('Local provider review unavailable'));this.#decision=null;this.#scrub();this.#button.disabled=true;this.#cancel.disabled=true;
    for(const release of this.#cleanup.splice(0))try{release();}catch{}
    for(const k of ['account','device','line','interval','session','phoneReader','archiveReader'] as const)this.#binding[k].fill(0);
    this.#binding={...this.#binding,peer:''};for(const k of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'] as const)this.#scope[k].fill(0);
    // Release application closures/lease references without closing custody owned by the host.
    this.#o={...this.#o,binding:this.#binding,archiveLease:null as unknown as ArchiveReaderLease02,readCurrent:async()=>null,currentCsrf:()=>'',onSetupClose:()=>()=>{},onCustodyClose:()=>()=>{},fetchImpl:undefined};
    this.#fetch=async()=>refused();this.#phase='closed';
  }
  #live(){if(this.#closed||this.#o.signal.aborted||this.#document.hidden||!this.#o.host.isConnected||performance.now()>=this.#deadline){this.close();refused();}}
  #csrf(){this.#live();try{const token=this.#o.currentCsrf();this.#live();if(typeof token!=='string'||token.length<1||token.length>256||/[^\x21-\x7e]/.test(token)||this.#csrfValue!==null&&token!==this.#csrfValue)refused();this.#csrfValue=token;return token;}catch{this.close();refused();}}
  #cap(deadline:number){this.#live();if(deadline>this.#deadline)refused();this.#deadline=deadline;if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=setTimeout(()=>this.close(),Math.max(0,deadline-performance.now()));this.#live();}
  async #wait<T>(promise:Promise<T>):Promise<T>{
    const observed=Promise.resolve(promise);try{this.#live();}catch(e){void observed.catch(()=>{});throw e;}
    let abort=()=>{};try{return await Promise.race([observed,new Promise<never>((_,reject)=>{abort=()=>reject(Error('Local provider review unavailable'));this.#controller.signal.addEventListener('abort',abort,{once:true});})]);}
    finally{this.#controller.signal.removeEventListener('abort',abort);}
  }
  async #hash(value:Uint8Array){const copy=Uint8Array.from(value);try{return hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',copy.buffer))));}finally{copy.fill(0);}}
  async #current(){
    this.#live();const started=performance.now(),sample=data(await this.#wait(this.#o.readCurrent()),['binding','manifest','nowMs','ownerSessionLive','consentLive']);this.#live();
    if(sample.ownerSessionLive!==true||sample.consentLive!==true||typeof sample.nowMs!=='bigint'||sample.nowMs<1n||sample.nowMs<this.#now||!sameBinding(this.#binding,binding(sample.binding)))refused();
    const id=verifiedManifestIdentity02(sample.manifest,sample.nowMs);
    const manifest=await this.#wait(verifyManifest02(Uint8Array.from(sample.manifest.bytes),verifiedManifestTrust02(sample.manifest,sample.nowMs),sample.nowMs));this.#live();
    const b=this.#binding,s=this.#scope;
    if(this.#root&&!equal(this.#root,id.rootPoint)||id.version<this.#version||id.version===this.#version&&this.#manifestDigest&&!equal(this.#manifestDigest,id.digest)||!equal(id.accountId,b.account)||id.generation!==s.trustGeneration||id.version!==s.manifestVersion||!equal(id.digest,s.manifestDigest))refused();
    if(!equal(s.accountId,b.account)||!equal(s.deviceId,b.device)||!equal(s.lineId,b.line)||!equal(s.intervalId,b.interval)||!equal(s.readerId,b.archiveReader)||s.bindingGeneration!==b.generation||s.expiresMs<=sample.nowMs||s.expiresMs-sample.nowMs>30n*86400000n||await this.#hash(encoder.encode(b.peer))!==hex(s.peerDigest))refused();
    authorizeWorkflowContext02(manifest,{accountId:s.accountId,deviceId:s.deviceId,lineId:s.lineId,readerId:s.readerId,generation:s.trustGeneration,version:s.manifestVersion,digest:s.manifestDigest},sample.nowMs);
    const active=(k:typeof manifest.keys[number])=>k.state===1&&k.fromMs<=sample.nowMs&&sample.nowMs<k.untilMs;
    const phone=manifest.keys.find(k=>k.role===1&&active(k)&&equal(k.keyId,b.phoneReader)&&equal(k.deviceId,b.device)&&equal(k.lineId,b.line));
    const reader=manifest.keys.find(k=>k.role===2&&active(k)&&equal(k.keyId,b.archiveReader));
    const signer=manifest.keys.find(k=>k.role===4&&active(k)&&equal(k.deviceId,b.device)&&equal(k.lineId,b.line));
    if(!phone||!reader||!signer)refused();
    const until=[s.expiresMs,manifest.expiresMs,phone.untilMs,reader.untilMs,signer.untilMs].reduce((a,b)=>a<b?a:b);
    this.#cap(Math.min(this.#deadline,started+this.#o.observationMs!,started+Number(until-sample.nowMs)));this.#csrf();this.#live();
    this.#root=Uint8Array.from(id.rootPoint);this.#manifestDigest=Uint8Array.from(id.digest);this.#version=id.version;this.#now=sample.nowMs;return {manifest,now:sample.nowMs};
  }
  async #get(path:string,type:string,limit:number){
    this.#live();const token=this.#csrf();this.#live();const url=this.#o.origin+path;
    const response=await this.#wait(this.#fetch(url,{method:'GET',credentials:'same-origin',mode:'same-origin',redirect:'error',cache:'no-store',signal:this.#controller.signal,headers:{Accept:type,'x-zrotext-csrf':token}}));this.#live();
    const content=response.headers.get('content-type');
    if(response.status!==200||response.redirected||response.url&&response.url!==url||(type==='application/json'?!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(content??''):content!==type)){void response.body?.cancel().catch(()=>{});refused();}
    const reader=response.body?.getReader();if(!reader)refused();const chunks:Uint8Array[]=[];let length=0;
    try{for(;;){const next=await this.#wait(reader.read());this.#live();if(next.done)break;length+=next.value.length;if(length>limit)refused();chunks.push(Uint8Array.from(next.value));}
      const out=new Uint8Array(length);let at=0;for(const chunk of chunks){out.set(chunk,at);at+=chunk.length;}return out;
    }finally{chunks.forEach(c=>c.fill(0));void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{}}
  }
  async #selection(){
    const envelope=await this.#get('/v1/owner/workflow/contexts/'+uuid(this.#scope.contextId),'application/vnd.zrotext.workflow-context.v1',33075);
    let raw:Uint8Array|null=null;try{
      if(envelope.length<308||!equal(envelope.subarray(0,222),workflowContextAad(this.#scope))||await this.#hash(envelope)!==this.#o.source.envelopeDigest)refused();
      raw=await this.#get('/v1/owner/provider-configurations/'+this.#o.configuration.configId,'application/json',8192);
      return {envelope,declaration:details(raw,this.#o.configuration)};
    }catch(e){envelope.fill(0);throw e;}finally{raw?.fill(0);}
  }
  async prepare(body:string):Promise<object>{
    if(this.#started||this.#closed)refused();this.#started=true;this.#phase='preparing';this.#deadline=performance.now()+this.#o.timeoutMs!;
    try{
      this.#cap(this.#deadline);this.#csrf();if(typeof body!=='string'||body.length<1||body.length>4096)refused();this.#body=encoder.encode(body);if(this.#body.length>4096||decoder.decode(this.#body)!==body)refused();
      await this.#current();const selected=await this.#selection();this.#envelope=selected.envelope;this.#declaration=selected.declaration;
      const current=await this.#current();let calls=0,complete=false,opened:Uint8Array|null=null;
      try{
        await this.#wait(this.#o.archiveLease.withKey(binding(this.#binding),async key=>{
          this.#live();if(++calls!==1||key.type!=='private'||key.extractable||key.algorithm.name!=='ECDH'||(key.algorithm as EcKeyAlgorithm).namedCurve!=='P-256'||!key.usages.includes('deriveBits'))refused();
          const result=await openWorkflowContext(current.manifest,scope(this.#scope),current.now,key,Uint8Array.from(selected.envelope));
          try{this.#live();if(calls!==1||result.length<1||result.length>32768)refused();opened=Uint8Array.from(result);complete=true;}finally{result.fill(0);}
        }));this.#live();if(calls!==1||!complete||!opened)refused();this.#facts=opened;opened=null;
      }finally{(opened as Uint8Array|null)?.fill(0);}
      decoder.decode(this.#facts!);await this.#current();
      const safe=(v:bigint)=>{if(v>BigInt(Number.MAX_SAFE_INTEGER))refused();return Number(v);};
      this.#identity=Object.freeze({account_id:uuid(this.#binding.account),context_id:uuid(this.#scope.contextId),context_revision:Number(this.#scope.revision),source_envelope_digest:this.#o.source.envelopeDigest,config_id:this.#o.configuration.configId,config_version:this.#o.configuration.configVersion,config_record_version:this.#o.configuration.recordVersion,declaration_digest:await this.#hash(encoder.encode(canonical(this.#declaration!))),rendered_body_digest:await this.#hash(this.#body),recipient_commitment:await this.#hash(encoder.encode(this.#binding.peer)),reader_key_id:hex(this.#binding.archiveReader),trust_generation:safe(this.#scope.trustGeneration),manifest_version:safe(this.#scope.manifestVersion),manifest_digest:hex(this.#scope.manifestDigest)});
      this.#live();this.#ticket=Object.freeze({});this.#phase='prepared';return this.#ticket;
    }catch{this.close();refused();}
  }
  #visible(){
    this.#live();if(this.#phase!=='reviewing'||this.#region.hidden||this.#region.children.length!==this.#reviewNodes.length||this.#reviewNodes.some((n,i)=>this.#region.children[i]!==n||n.textContent!==this.#reviewText[i]))refused();
  }
  async review(ticket:object):Promise<DisclosureReviewCommitment>{
    if(this.#closed||this.#phase!=='prepared'||ticket!==this.#ticket)refused();this.#phase='reviewing';
    try{
      this.#live();const labels=['Configuration is unaccepted. Sending is unavailable.',`Recipient ${this.#binding.peer} · Declared sender ${this.#declaration!.sender} · Telnyx SMS`,decoder.decode(this.#facts!),decoder.decode(this.#body!)];
      this.#reviewNodes=labels.map((text,i)=>{const n=this.#document.createElement(i<2?'p':'pre');n.textContent=text;return n;});this.#reviewText=labels;this.#region.replaceChildren(...this.#reviewNodes);this.#region.hidden=false;this.#button.disabled=false;
      await this.#wait(new Promise<void>((resolve,reject)=>{this.#decision={resolve,reject};}));this.#decision=null;this.#button.disabled=true;this.#visible();
      await this.#current();const selected=await this.#selection();try{if(!equal(selected.envelope,this.#envelope!)||canonical(selected.declaration)!==canonical(this.#declaration!))refused();}finally{selected.envelope.fill(0);}
      await this.#current();this.#visible();const identity=this.#identity!,encoded=encoder.encode(canonical(identity)),domain=encoder.encode('ZT/owner-provider-local-review/v1\0'),input=new Uint8Array(domain.length+4+encoded.length);input.set(domain);new DataView(input.buffer).setUint32(domain.length,encoded.length);input.set(encoded,domain.length+4);
      let hash:string;try{hash=await this.#hash(input);}finally{input.fill(0);encoded.fill(0);}
      this.#visible();this.#csrf();this.#live();const result=Object.freeze({...identity,review_binding_digest:hash,state:'local_reviewed_unavailable' as const,execution:'unavailable' as const});this.close();this.#phase='reviewed';return result;
    }catch{this.close();refused();}
  }
}
/** Caller supplies the real owner-host dependencies. No page, router or effect is activated. */
export function createOwnerProviderDisclosureReview(input:OwnerProviderDisclosureOptions):OwnerProviderDisclosureReview {
  const local=new LocalReview(input);return Object.freeze({prepare:(body:string)=>local.prepare(body),review:(ticket:object)=>local.review(ticket),pending:()=>local.pending(),state:()=>local.state(),close:()=>local.close()});
}
