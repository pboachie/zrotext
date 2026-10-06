// SPDX-License-Identifier: AGPL-3.0-only
/** Isolated initial owner facts editor. No page integration or execution authority. */
import { OwnerWorkflowContextClient, OwnerContextError, type OwnerContextCurrent, type OwnerContextPending, type OwnerContextReceipt, type OwnerContextWriteReview } from './owner-workflow-context-client.js';
import { authorizeWorkflowContext02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02 } from './draft02-manifest.js';
import type { ConversationSignerBinding02, ConversationSignerCurrent02 } from './conversation-signer.js';
import type { ArchiveReaderLease02 } from './conversation-archive-custody.js';
import { sealWorkflowContext, workflowContextAad, type WorkflowContextScope } from './workflow-context.js';

export interface OwnerContextAuthoringOptions {
  enabled: boolean; origin: string; host: HTMLElement; binding: ConversationSignerBinding02;
  contextId: Uint8Array; expiresMs: bigint; readCurrent: () => Promise<ConversationSignerCurrent02|null>;
  currentCsrf: () => string; archiveLease: ArchiveReaderLease02;
  onSetupClose: (listener: () => void) => void|(() => void);
  onCustodyClose: (listener: () => void) => void|(() => void);
  signal: AbortSignal; timeoutMs?: number; observationMs?: number; fetchImpl?: typeof fetch;
}
export type OwnerAuthoringPhase = 'editing'|'preparing'|'review'|'saving'|'saved'|'unknown'|'refused'|'closed';
export type OwnerAuthoringState = Readonly<{phase: OwnerAuthoringPhase; pending: OwnerContextPending|null}>;
export type OwnerAcknowledgedSourceSnapshot = Readonly<{accountId: string; receipt: Readonly<OwnerContextReceipt & {requestAcknowledged: true}>}>;
export type OwnerContextAuthoring = Readonly<{close(): void; state(): OwnerAuthoringState; savedSource(): OwnerAcknowledgedSourceSnapshot|null}>;
const names=['enabled','origin','host','binding','contextId','expiresMs','readCurrent','currentCsrf','archiveLease','onSetupClose','onCustodyClose','signal'];
const bindingNames=['account','device','line','interval','session','generation','peer','phoneReader','archiveReader'];
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((n,i)=>n===b[i]);
const hex=(a:Uint8Array)=>Array.from(a,n=>n.toString(16).padStart(2,'0')).join('');
const uuid=(a:Uint8Array)=>hex(a).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
function fail():never{throw Error('Owner facts unavailable');}
function data(value:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,any>{
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)fail();
  const keys=Reflect.ownKeys(value),allowed=new Set([...required,...optional]),out:Record<string,any>={};
  if(keys.some(k=>typeof k!=='string'||!allowed.has(k))||required.some(k=>!Object.hasOwn(value,k)))fail();
  for(const key of keys){const p=Object.getOwnPropertyDescriptor(value,key)!;if(!Object.hasOwn(p,'value'))fail();out[key as string]=p.value;}return out;
}
function bytes(value:unknown,n:number):Uint8Array{if(!(value instanceof Uint8Array)||value.length!==n||!value.some(v=>v!==0))fail();return Uint8Array.from(value);}
function bindingCopy(value:unknown):ConversationSignerBinding02{
  const b=data(value,bindingNames);for(const k of ['account','device','line','interval','session'])b[k]=bytes(b[k],16);
  for(const k of ['phoneReader','archiveReader'])b[k]=bytes(b[k],32);
  if(typeof b.generation!=='bigint'||b.generation<1n||b.generation>=(1n<<63n)||typeof b.peer!=='string'||!/^\+[1-9][0-9]{1,14}$/.test(b.peer))fail();return b as ConversationSignerBinding02;
}
function equalBinding(a:ConversationSignerBinding02,b:ConversationSignerBinding02):boolean{return a.generation===b.generation&&a.peer===b.peer&&['account','device','line','interval','session','phoneReader','archiveReader'].every(k=>same(a[k as 'account'],b[k as 'account']));}

class Authoring {
  #o:OwnerContextAuthoringOptions;#binding:ConversationSignerBinding02;#context:Uint8Array;#document:Document;#window:Window;
  #phase:OwnerAuthoringPhase='editing';#closed=false;#pending:OwnerContextPending|null=null;
  #saved:OwnerAcknowledgedSourceSnapshot|null=null;
  #controller=new AbortController();#client:OwnerWorkflowContextClient|null=null;#ticket:object|null=null;
  #deadline=Infinity;#timer:ReturnType<typeof setTimeout>|undefined;#cleanup:Array<()=>void>=[];
  #now=0n;#content:Uint8Array|null=null;#envelope:Uint8Array|null=null;#text='';#scope:WorkflowContextScope|null=null;#request='';#digest='';
  #decision:Readonly<{resolve():void;reject(error:Error):void}>|null=null;
  #posts=0;#checks=0;
  #csrfValue:string|null=null;
  #pane:HTMLElement;#editor:HTMLTextAreaElement;#review:HTMLElement;#status:HTMLElement;
  #buttons:Record<string,HTMLButtonElement>={};
  constructor(input:OwnerContextAuthoringOptions){
    const o=data(input,names,['timeoutMs','observationMs','fetchImpl']);
    if(typeof o.enabled!=='boolean'||!(o.signal instanceof AbortSignal)||!['readCurrent','currentCsrf','onSetupClose','onCustodyClose'].every(k=>typeof o[k]==='function')||typeof o.archiveLease?.onClose!=='function'||o.fetchImpl!==undefined&&typeof o.fetchImpl!=='function')fail();
    const host=o.host as HTMLElement,document=host?.ownerDocument,window=document?.defaultView;
    if(host?.nodeType!==1||!document||!window||typeof host.append!=='function'||window.location.origin!==o.origin)fail();
    const origin=new URL(o.origin);if(origin.protocol!=='https:'||origin.origin!==o.origin||origin.username||origin.password)fail();
    for(const k of ['timeoutMs','observationMs']){o[k]??=10000;if(!Number.isSafeInteger(o[k])||o[k]<1||o[k]>10000)fail();}
    if(typeof o.expiresMs!=='bigint'||o.expiresMs<1n||o.expiresMs>=(1n<<63n))fail();
    this.#o=o as OwnerContextAuthoringOptions;this.#binding=bindingCopy(o.binding);this.#context=bytes(o.contextId,16);this.#document=document;this.#window=window;
    this.#pane=document.createElement('section');this.#pane.setAttribute('aria-label','Owner facts');
    const label=document.createElement('label');label.textContent='Facts';this.#editor=document.createElement('textarea');this.#editor.setAttribute('aria-label','Facts');this.#editor.setAttribute('autocomplete','off');this.#editor.spellcheck=false;this.#editor.maxLength=32768;label.append(this.#editor);
    this.#review=document.createElement('div');this.#review.setAttribute('aria-label','Review facts');this.#review.hidden=true;
    this.#status=document.createElement('p');this.#status.setAttribute('role','status');this.#status.setAttribute('aria-live','polite');
    this.#pane.append(label,this.#review,this.#status);
    for(const [key,text] of Object.entries({review:'Review facts',save:'Save encrypted facts',retry:'Retry same save',check:'Check saved facts',clear:'Clear'})){
      const button=document.createElement('button');button.type='button';button.textContent=text;this.#buttons[key]=button;this.#pane.append(button);
    }
    // Teardown subscriptions precede every authority, key or network operation.
    let subscriptionFailed=false;
    for(const subscribe of [o.onSetupClose,o.onCustodyClose,(listener:()=>void)=>o.archiveLease.onClose(listener)])try{
      const release=subscribe(()=>this.close());if(release!==undefined&&typeof release!=='function')fail();if(release){if(this.#closed)release();else this.#cleanup.push(release);}
    }catch{subscriptionFailed=true;this.close();}
    const listen=(target:EventTarget,event:string,listener:EventListener)=>{target.addEventListener(event,listener);this.#cleanup.push(()=>target.removeEventListener(event,listener));};
    listen(o.signal,'abort',()=>this.close());listen(window,'pagehide',()=>this.close());listen(document,'visibilitychange',()=>{if(document.hidden)this.close();});
    listen(this.#editor,'input',()=>{if(this.#phase!=='editing')this.close();});
    listen(this.#buttons.review,'click',()=>{void this.#prepare();});listen(this.#buttons.save,'click',()=>this.#decision?.resolve());
    listen(this.#buttons.retry,'click',()=>{void this.#reconcile(true);});listen(this.#buttons.check,'click',()=>{void this.#reconcile(false);});listen(this.#buttons.clear,'click',()=>this.close());
    if(subscriptionFailed||this.#closed||!o.enabled||o.signal.aborted||document.hidden){this.close();if(subscriptionFailed)fail();}
    host.append(this.#pane);this.#render();
  }
  state():OwnerAuthoringState{return Object.freeze({phase:this.#phase,pending:this.#pending?Object.freeze({...this.#pending}):null});}
  savedSource():OwnerAcknowledgedSourceSnapshot|null{
    if(this.#closed)return null;
    if(this.#o.signal.aborted||this.#document.hidden||performance.now()>=this.#deadline){this.close();return null;}
    if(this.#phase!=='saved'||!this.#saved)return null;
    const r=this.#saved.receipt;
    return Object.freeze({accountId:this.#saved.accountId,receipt:Object.freeze({requestId:r.requestId,contextId:r.contextId,revision:r.revision,envelopeDigest:r.envelopeDigest,state:r.state,requestAcknowledged:true as const})});
  }
  #retain(result:OwnerContextReceipt):void{
    const r=data(result,['requestId','contextId','revision','envelopeDigest','state','requestAcknowledged']);
    if(r.requestId!==this.#request||r.contextId!==uuid(this.#context)||r.revision!==1||r.envelopeDigest!==this.#digest||r.state!=='verified_current_snapshot'||r.requestAcknowledged!==true)fail();
    this.#saved=Object.freeze({accountId:uuid(this.#binding.account),receipt:Object.freeze({requestId:this.#request,contextId:uuid(this.#context),revision:1,envelopeDigest:this.#digest,state:'verified_current_snapshot' as const,requestAcknowledged:true as const})});
  }
  #render():void{
    this.#editor.disabled=this.#closed||this.#phase!=='editing';
    for(const [key,b]of Object.entries(this.#buttons))b.disabled=this.#closed||!(key==='review'&&this.#phase==='editing'||key==='save'&&this.#phase==='review'||key==='retry'&&this.#phase==='unknown'&&this.#posts<3||key==='check'&&this.#phase==='unknown'&&this.#checks<3||key==='clear');
    if(this.#pending)this.#status.textContent=`Save outcome unknown. Context ${this.#pending.contextId}, request ${this.#pending.requestId}, revision ${this.#pending.revision}. Check before authoring again.`;
    else this.#status.textContent=({editing:'Enter facts for your selected conversation.',preparing:'Preparing your private review.',review:'Review these facts before saving.',saving:'Saving encrypted facts.',saved:'Encrypted facts saved and current at this check.',refused:'Save refused. Check current facts before a new attempt.',closed:'Facts editor closed.'} as Record<string,string>)[this.#phase]??'Save outcome unknown.';
  }
  #scrub():void{this.#content?.fill(0);this.#content=null;this.#envelope?.fill(0);this.#envelope=null;this.#text='';this.#editor.value='';this.#review.textContent='';this.#review.hidden=true;}
  close():void{
    this.#closed=true;this.#saved=null;if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=undefined;
    this.#pending=this.#client?.pending()??this.#pending;this.#controller.abort();this.#csrfValue=null;
    this.#decision?.reject(Error('Owner facts closed'));this.#decision=null;
    try{this.#client?.close();}finally{this.#ticket=null;this.#scrub();for(const cleanup of this.#cleanup.splice(0))try{cleanup();}catch{/* Other teardown always continues. */}this.#phase='closed';this.#render();}
  }
  #live():void{if(this.#closed||this.#o.signal.aborted||this.#document.hidden||performance.now()>=this.#deadline){this.close();fail();}}
  #csrf():string{
    try{this.#live();const token=this.#o.currentCsrf();this.#live();
      if(typeof token!=='string'||token.length<1||token.length>256||/[^\x21-\x7e]/.test(token)||this.#csrfValue!==null&&token!==this.#csrfValue)fail();
      this.#csrfValue=token;return token;
    }catch(error){this.close();throw error;}
  }
  #cap(deadline:number):void{this.#live();if(deadline>this.#deadline)fail();this.#deadline=deadline;if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=setTimeout(()=>this.close(),Math.max(0,deadline-performance.now()));this.#live();}
  async #wait<T>(promise:Promise<T>):Promise<T>{
    const observed=Promise.resolve(promise);try{this.#live();}catch(error){void observed.catch(()=>{});throw error;}
    let abort=()=>{};
    try{return await Promise.race([observed,new Promise<never>((_,reject)=>{abort=()=>reject(Error('Owner facts closed'));this.#controller.signal.addEventListener('abort',abort,{once:true});})]);}
    finally{this.#controller.signal.removeEventListener('abort',abort);}
  }
  async #current():Promise<OwnerContextCurrent>{
    try{
    this.#live();const started=performance.now(),value=await this.#wait(this.#o.readCurrent());this.#live();
    const c=data(value,['binding','manifest','nowMs','ownerSessionLive','consentLive']);
    if(c.ownerSessionLive!==true||c.consentLive!==true||typeof c.nowMs!=='bigint'||c.nowMs<1n||c.nowMs<this.#now||!equalBinding(this.#binding,bindingCopy(c.binding)))fail();
    verifiedManifestIdentity02(c.manifest,c.nowMs);
    const manifest=await this.#wait(verifyManifest02(Uint8Array.from(c.manifest.bytes),verifiedManifestTrust02(c.manifest,c.nowMs),c.nowMs));this.#live();
    authorizeWorkflowContext02(manifest,{accountId:this.#binding.account,deviceId:this.#binding.device,lineId:this.#binding.line,readerId:this.#binding.archiveReader,generation:manifest.generation,version:manifest.version,digest:manifest.digest},c.nowMs);
    const active=(k:typeof manifest.keys[number])=>k.state===1&&k.fromMs<=c.nowMs&&c.nowMs<k.untilMs;
    const phone=manifest.keys.find(k=>k.role===1&&active(k)&&same(k.keyId,this.#binding.phoneReader)&&same(k.deviceId,this.#binding.device)&&same(k.lineId,this.#binding.line));
    const reader=manifest.keys.find(k=>k.role===2&&same(k.keyId,this.#binding.archiveReader));
    const signer=manifest.keys.find(k=>k.role===4&&active(k)&&same(k.deviceId,this.#binding.device)&&same(k.lineId,this.#binding.line));
    if(!phone||!reader||!signer||this.#o.expiresMs<=c.nowMs||this.#o.expiresMs-c.nowMs>30n*86400000n)fail();
    const signed=[manifest.expiresMs,phone.untilMs,reader.untilMs,signer.untilMs,this.#o.expiresMs].reduce((a,b)=>a<b?a:b);
    const deadline=Math.min(this.#deadline,started+this.#o.observationMs!,started+Number(signed-c.nowMs));this.#cap(deadline);this.#now=c.nowMs;
    const validForMs=Math.floor(deadline-performance.now());if(validForMs<1)fail();
    return {binding:bindingCopy(this.#binding),manifest,nowMs:c.nowMs,ownerSessionLive:true,consentLive:true,phase:'active',validForMs};
    }catch(error){this.close();throw error;}
  }
  async #reviewWrite(review:OwnerContextWriteReview):Promise<void>{
    this.#live();if(!this.#scope||review.requestId!==this.#request||review.contextId!==uuid(this.#context)||review.expectedRevision!==0||review.revision!==1||review.envelopeDigest!==this.#digest||!same(workflowContextAad(review.scope),workflowContextAad(this.#scope))||this.#editor.value!==this.#text)fail();
    this.#phase='review';this.#review.hidden=false;
    const summary=`Account ${uuid(this.#binding.account)} · Line ${uuid(this.#binding.line)} · Peer ${this.#binding.peer} · Facts expire ${new Date(Number(this.#o.expiresMs)).toISOString()}`;
    const details=this.#document.createElement('p');details.textContent=summary;
    const facts=this.#document.createElement('pre');facts.textContent=this.#text;this.#review.replaceChildren(details,facts);this.#render();
    await this.#wait(new Promise<void>((resolve,reject)=>{this.#decision={resolve,reject};}));this.#decision=null;this.#live();
    if(this.#editor.value!==this.#text||this.#review.hidden||facts.textContent!==this.#text||details.textContent!==summary||this.#review.children.length!==2||this.#review.children[0]!==details||this.#review.children[1]!==facts)fail();
    this.#phase='saving';this.#render();
  }
  async #prepare():Promise<void>{
    if(this.#closed||this.#phase!=='editing')return;this.#phase='preparing';this.#render();
    try{
      this.#deadline=performance.now()+this.#o.timeoutMs!;this.#cap(this.#deadline);this.#text=this.#editor.value;if(this.#text.length<1||this.#text.length>32768)fail();this.#content=new TextEncoder().encode(this.#text);if(this.#content.length>32768)fail();
      const current=await this.#current(),b=this.#binding;
      const peer=new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer))));this.#live();
      this.#scope={kind:1,accountId:bytes(b.account,16),deviceId:bytes(b.device,16),lineId:bytes(b.line,16),intervalId:bytes(b.interval,16),contextId:bytes(this.#context,16),bindingGeneration:b.generation,revision:1n,expiresMs:this.#o.expiresMs,trustGeneration:current.manifest.generation,manifestVersion:current.manifest.version,peerDigest:peer,readerId:bytes(b.archiveReader,32),manifestDigest:bytes(current.manifest.digest,32)};
      this.#envelope=await this.#wait(sealWorkflowContext(current.manifest,this.#scope,current.nowMs,this.#content));this.#live();this.#content.fill(0);this.#content=null;
      this.#digest=hex(new Uint8Array(await this.#wait(crypto.subtle.digest('SHA-256',Uint8Array.from(this.#envelope).buffer))));this.#live();this.#request=crypto.randomUUID();
      this.#client=new OwnerWorkflowContextClient({enabled:true,origin:this.#o.origin,selection:{binding:b,contextId:this.#context,kind:1},readCurrent:()=>this.#current(),currentCsrf:()=>this.#csrf(),consumeWriteReview:review=>this.#reviewWrite(review),signal:this.#controller.signal,timeoutMs:Math.max(1,Math.floor(this.#deadline-performance.now())),...(this.#o.fetchImpl?{fetchImpl:this.#o.fetchImpl}:{})});
      this.#ticket=await this.#wait(this.#client.prepare({requestId:this.#request,expectedRevision:0,scope:this.#scope,envelope:this.#envelope}));this.#live();this.#envelope.fill(0);this.#envelope=null;
      this.#posts++;const result=await this.#wait(this.#client.commit(this.#ticket));this.#live();this.#retain(result);this.#pending=null;this.#ticket=null;this.#phase='saved';this.#scrub();if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=undefined;this.#render();
    }catch(error){this.#outcome(error);}
  }
  #outcome(error:unknown):void{
    this.#saved=null;this.#pending=this.#client?.pending()??this.#pending;this.#scrub();
    if(error instanceof OwnerContextError&&['expired','closed','owner_changed'].includes(error.code)||performance.now()>=this.#deadline)this.close();
    if(this.#closed){this.#phase='closed';this.#render();return;}
    if(this.#pending){this.#phase='unknown';this.#render();}else{this.close();this.#phase='refused';this.#render();}
  }
  async #reconcile(retry:boolean):Promise<void>{
    if(this.#closed||this.#phase!=='unknown'||!this.#client||!this.#ticket)return;
    if(retry?this.#posts>=3:this.#checks>=3)return;
    this.#phase='saving';this.#render();
    try{this.#live();if(retry)this.#posts++;else this.#checks++;const result=await this.#wait(retry?this.#client.retryUnknown(this.#ticket):this.#client.verifyUnknown(this.#ticket));this.#live();
      if(!result.requestAcknowledged){this.#phase='unknown';this.#render();return;}
      this.#retain(result);
      this.#pending=null;this.#ticket=null;this.#phase='saved';this.#scrub();if(this.#timer!==undefined)clearTimeout(this.#timer);this.#timer=undefined;this.#render();
    }catch(error){this.#outcome(error);}
  }
}
/** Caller must supply real post-enrollment owner/custody callbacks; this factory mounts nothing. */
export function createOwnerContextAuthoring(input:OwnerContextAuthoringOptions):OwnerContextAuthoring{
  const author=new Authoring(input);return Object.freeze({close:()=>author.close(),state:()=>author.state(),savedSource:()=>author.savedSource()});
}
