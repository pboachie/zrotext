// SPDX-License-Identifier: AGPL-3.0-only
// Customer-side proposals only. No approval, send, scheduling or provider transport.
import { createHash, randomUUID } from 'node:crypto';
import { RoutineError, RoutineJournal } from './journal.mjs';
import { canonicalWorkflowAction } from '../typescript/dist/workflow-decisions.js';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex = /^[0-9a-f]{64}$/;
const kinds = ['faq','intake','note','reminder','owner_reply'];
const fail = code => { throw new RoutineError(code); };
const hash = value => createHash('sha256').update(value).digest('hex');
function object(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== keys.length) fail('invalid_request');
  const copy = {};
  for (const key of keys) {
    const entry = Object.getOwnPropertyDescriptor(value,key);
    if (!entry || !Object.hasOwn(entry,'value')) fail('invalid_request');
    copy[key] = entry.value;
  }
  return copy;
}
function id(value) { if (typeof value !== 'string' || !uuid.test(value)) fail('invalid_request'); return value; }
function integer(value, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail('invalid_request'); return value; }
function digest(value) { if (typeof value !== 'string' || !hex.test(value)) fail('invalid_request'); return value; }
const scopeFields = ['accountId','connectorId','lineId','recipientId','purposeId','contextId','routineId','readerId','providerId'];
const policyFields = [...scopeFields,'generation','readerGeneration','kind','expiresMs','callLimit','unitLimit','callUnits','turnLimit','timeoutMs'];
function policy(input) {
  const p = object(input,policyFields);
  for (const field of scopeFields) id(p[field]);
  for (const field of ['generation','readerGeneration']) integer(p[field],1,Number.MAX_SAFE_INTEGER);
  if (!kinds.includes(p.kind)) fail('invalid_request');
  integer(p.expiresMs,1,Number.MAX_SAFE_INTEGER); integer(p.callLimit,1,100);
  integer(p.unitLimit,1,1000000); integer(p.callUnits,1,p.unitLimit);
  integer(p.turnLimit,1,3); integer(p.timeoutMs,10,30000);
  return Object.freeze(p);
}
function event(input) {
  const e = object(input,[...scopeFields.slice(0,6),'eventId','contentRef','contentDigest','issuedMs','expiresMs','direction']);
  for (const field of [...scopeFields.slice(0,6),'eventId','contentRef']) id(e[field]);
  digest(e.contentDigest); integer(e.issuedMs,1,Number.MAX_SAFE_INTEGER); integer(e.expiresMs,e.issuedMs+1,e.issuedMs+86400000);
  if (!['inbound','owner'].includes(e.direction)) fail('invalid_request');
  return Object.freeze(e);
}
function bytes(value, maximum) {
  if (!(value instanceof Uint8Array) || value.length < 1 || value.length > maximum) fail('invalid_content');
  try { new TextDecoder('utf-8',{fatal:true}).decode(value); } catch { fail('invalid_content'); }
  return Uint8Array.from(value);
}
function opaqueResult(action, bindingDigest) {
  return {actionId:action.action_id,revision:action.revision,bindingDigest};
}

export function assistantReadiness() { return Object.freeze({available:false,code:'workflow_services_unavailable'}); }

/** Inject only authenticated shared-service and selected-customer-reader adapters.
 * Raw webhook/SMS input is not this API: #617 owns verified delivery/checkpoints.
 * Adapters own their credentials and never give them to the model or journal. */
export class AssistantRunner {
  #policy; #journal; #service; #reader; #renderer; #provider; #clock; #scope; #conversation; #controllers = new Set();
  constructor({enabled=false,policy:input,journalPath,service,reader,renderer,provider,clock=Date.now}) {
    if (enabled !== true) fail('workflow_services_unavailable');
    this.#policy = policy(input);
    for (const [adapter,method] of [[service,'current'],[service,'reserveProvider'],[service,'propose'],[reader,'readSelected'],[renderer,'prepare'],[provider,'generate']]) {
      if (!adapter || typeof adapter[method] !== 'function') fail('workflow_services_unavailable');
    }
    this.#clock=clock; const now=this.#now();
    if (this.#policy.expiresMs<=now || this.#policy.expiresMs-now>86400000) fail('expired');
    this.#service=service; this.#reader=reader; this.#renderer=renderer; this.#provider=provider;
    this.#conversation=hash(JSON.stringify(scopeFields.slice(0,6).map(field=>this.#policy[field])));
    this.#scope=hash(JSON.stringify([this.#conversation,this.#policy.routineId,this.#policy.generation]));
    this.#journal=new RoutineJournal(journalPath);
    try { this.#journal.bind(this.#scope,hash(JSON.stringify(this.#policy)),this.#policy.expiresMs); }
    catch (error) { this.#journal.close(); throw error; }
  }
  #now() { return integer(this.#clock(),1,Number.MAX_SAFE_INTEGER); }
  async #current(e, signal) {
    const now=this.#now(); this.#journal.check(this.#scope,now);
    if (now<e.issuedMs || now>=e.expiresMs) fail('expired');
    for (const field of scopeFields.slice(0,6)) if (e[field]!==this.#policy[field]) fail('scope_denied');
    const fields=[...scopeFields,'generation','readerGeneration','expiresMs','active','consent','takeover','suppressed','canRead','canPropose','window'];
    const a=object(await this.#service.current(Object.freeze({...e,routineId:this.#policy.routineId}),{signal}),fields);
    for (const field of scopeFields) if (a[field]!==this.#policy[field]) fail('scope_denied');
    if (a.generation!==this.#policy.generation || a.readerGeneration!==this.#policy.readerGeneration ||
        a.active!==true || a.consent!==true || a.canRead!==true || a.canPropose!==true ||
        a.takeover!==false || a.suppressed!==false) fail('authority_unavailable');
    integer(a.expiresMs,1,Number.MAX_SAFE_INTEGER);
    const window=object(a.window,['id','timezone','notBefore','expiresAt','state']);
    id(window.id);
    if (typeof window.timezone!=='string' || !/^[A-Za-z0-9_+\/-]{1,128}$/.test(window.timezone)) fail('owner_review');
    integer(window.notBefore,0,Number.MAX_SAFE_INTEGER); integer(window.expiresAt,window.notBefore+1,Number.MAX_SAFE_INTEGER);
    if (window.state!=='open') fail('owner_review');
    // Repeat local time and withdrawal checks after every external authority wait.
    const after=this.#now(); this.#journal.check(this.#scope,after);
    if (signal.aborted || after>=e.expiresMs || after>=a.expiresMs ||
        Math.floor(after/1000)<window.notBefore || Math.floor(after/1000)>=window.expiresAt) fail('authority_unavailable');
    return Object.freeze({...a,window:Object.freeze(window)});
  }
  async run(input) {
    // Snapshot before the first await. The model cannot supply routing/authority.
    const e=event(input), p=this.#policy;
    if (p.kind==='owner_reply' && e.direction!=='owner') fail('scope_denied');
    const requestId=hash(JSON.stringify([this.#scope,e.eventId]));
    const requestDigest=hash(JSON.stringify(e));
    const controller=new AbortController(); this.#controllers.add(controller);
    const held=[]; let reserved=false; let providerStarted=false; let timer;
    try {
      let authority=await this.#current(e,controller.signal);
      const previous=this.#journal.reserve({id:requestId,scope:this.#scope,conversation:this.#conversation,digest:requestDigest,
        now:this.#now(),expiresMs:e.expiresMs,units:p.callUnits,callLimit:p.callLimit,unitLimit:p.unitLimit,turnLimit:p.turnLimit});
      if (previous) return Object.freeze(previous);
      reserved=true;
      const selected=object(await this.#reader.readSelected(authority,e,{signal:controller.signal}),['instructions','content']);
      held.push(selected.instructions,selected.content);
      const instructions=bytes(selected.instructions,8192), content=bytes(selected.content,32768);
      held.push(instructions,content);
      authority=await this.#current(e,controller.signal);
      const reservation=object(await this.#service.reserveProvider(authority,{requestId,units:p.callUnits,expiresMs:e.expiresMs},{signal:controller.signal}),['requestId','units','generation','state']);
      if (reservation.requestId!==requestId || reservation.units!==p.callUnits || reservation.generation!==p.generation || reservation.state!=='fresh') fail('budget_unavailable');
      authority=await this.#current(e,controller.signal);
      // Crash-safe unknown checkpoint commits before provider invocation. No replay retries.
      this.#journal.mark(requestId,this.#scope,'unknown'); providerStarted=true;
      const timeout=new Promise((_,reject)=> { timer=setTimeout(()=> {controller.abort();reject(new RoutineError('provider_unknown'));},p.timeoutMs); });
      const response=await Promise.race([Promise.resolve().then(()=>{
        if (controller.signal.aborted) fail('withdrawn');
        return this.#provider.generate(Object.freeze({kind:p.kind,instructions,content}),
          {signal:controller.signal,maximumUnits:p.callUnits});
      }).then(response=>{
        if (controller.signal.aborted && response && typeof response==='object') {
          const text=Object.getOwnPropertyDescriptor(response,'text')?.value;
          if (text instanceof Uint8Array) text.fill(0);
        }
        return response;
      }),timeout]);
      clearTimeout(timer);
      const output=object(response,['text']); held.push(output.text);
      const text=bytes(output.text,8192); held.push(text);
      authority=await this.#current(e,controller.signal);
      const actionId=randomUUID();
      const prepared=object(await this.#renderer.prepare(authority,{actionId,text},{signal:controller.signal}),['contextId','version','ciphertext']);
      if (prepared.contextId!==p.contextId) fail('scope_denied');
      integer(prepared.version,1,Number.MAX_SAFE_INTEGER);
      if (!(prepared.ciphertext instanceof Uint8Array) || prepared.ciphertext.length<17 || prepared.ciphertext.length>33075) fail('invalid_content');
      const ciphertext=Uint8Array.from(prepared.ciphertext); held.push(prepared.ciphertext,ciphertext);
      authority=await this.#current(e,controller.signal);
      const action={account_id:p.accountId,action_id:actionId,revision:1,line_id:p.lineId,recipient_id:p.recipientId,purpose_id:p.purposeId,
        content_ref:prepared.contextId,content_digest:hash(ciphertext),content_version:prepared.version,
        not_before:authority.window.notBefore,expires_at:Math.min(authority.window.expiresAt,Math.floor(e.expiresMs/1000),Math.floor(p.expiresMs/1000)),
        timezone:authority.window.timezone,window_id:authority.window.id,routine_id:p.routineId,authority_generation:p.generation,
        // Free model text can contain commitments despite a claimed FAQ classification.
        // Every generated action therefore needs exact authenticated owner review.
        commitment:'sensitive'};
      const bindingDigest=hash(canonicalWorkflowAction(action));
      const result=object(await this.#service.propose(Object.freeze(action),ciphertext,{requestId,signal:controller.signal}),
        ['account_id','action_id','revision','binding_digest','state']);
      if (result.account_id!==p.accountId || result.action_id!==actionId || result.revision!==1 || result.binding_digest!==bindingDigest || result.state!=='proposed') fail('proposal_unknown');
      await this.#current(e,controller.signal);
      const opaque=opaqueResult(action,bindingDigest);
      this.#journal.mark(requestId,this.#scope,'proposed',opaque);
      return Object.freeze({state:'proposed',...opaque});
    } catch (error) {
      if (reserved && !providerStarted) this.#journal.mark(requestId,this.#scope,'refused');
      if (providerStarted) return Object.freeze({state:'unknown',code:'provider_or_proposal_unknown'});
      if (error instanceof RoutineError) throw error;
      fail('authority_unavailable');
    } finally {
      clearTimeout(timer); controller.abort(); this.#controllers.delete(controller);
      for (const value of held) if (value instanceof Uint8Array) value.fill(0);
    }
  }
  withdraw(reason) { this.#journal.withdraw(this.#scope,reason); for (const controller of this.#controllers) controller.abort(); }
  exportMetadata(before=null) { return this.#journal.exportMetadata(before); }
  prune() { this.#journal.prune(this.#now()); }
  eraseMetadata() { this.withdraw('takeover'); this.#journal.eraseMetadata(); }
  close() { for (const controller of this.#controllers) controller.abort(); this.#journal.close(); }
}
