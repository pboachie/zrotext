// SPDX-License-Identifier: AGPL-3.0-only
import { LocalProvider } from './local-provider.mjs';
import { randomUUID } from 'node:crypto';
import { CustomerRoutineService, closed, fail, id } from './routine-service.mjs';
import { CipherArtifactStore, ciphertextDigest } from './artifact-store.mjs';
import { WorkflowToolClient } from '../typescript/dist/workflow-tool-client.js';
import { OriginalReplyClient } from '../typescript/dist/original-reply-client.js';
import { openIntegrationWorkflowContext, openWorkflowContext, sealWorkflowContext,
  sealIntegrationWorkflowContext, workflowContextAad } from '../typescript/dist/workflow-context.js';

const textEncoder=new TextEncoder();
const uuidBytes=value=>{if(!id(value))fail('invalid_scope');return Uint8Array.from(Buffer.from(value.replaceAll('-',''),'hex'));};
const uuidText=bytes=>{const h=Buffer.from(bytes).toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;};
/** Exact, bounded owner-declared formats. No hosted model or inbound interpretation. */
export function renderRoutine(kind,input) {
  if(!(input instanceof Uint8Array)||input.length<1||input.length>32768) fail('invalid_content');
  let value; try {value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(input));}catch{fail('invalid_content');}
  const bounded=value=>{if(typeof value!=='string'||textEncoder.encode(value).length<1||textEncoder.encode(value).length>8192)fail('invalid_content');return value;};
  let output;
  switch(kind) {
    case 'faq': { const v=closed(value,['question','answer']); bounded(v.question); output=bounded(v.answer); break; }
    case 'intake': { const v=closed(value,['fields']); if(!Array.isArray(v.fields)||v.fields.length<1||v.fields.length>16)fail('invalid_content'); output=v.fields.map(f=>{const v=closed(f,['label','value']);return `${bounded(v.label)}: ${bounded(v.value)}`;}).join('\n');break; }
    case 'note': {const v=closed(value,['note']);output=bounded(v.note);break;}
    case 'reminder': {const v=closed(value,['reminder']);output=bounded(v.reminder);break;}
    case 'owner_reply': {const v=closed(value,['reply']);output=bounded(v.reply);break;}
    default: fail('invalid_kind');
  }
  const bytes=textEncoder.encode(output);if(bytes.length>8192)fail('invalid_content');return bytes;
}
/** Trusted local key custody is separate from service authority. No verified booleans. */
export class CustomerRoutineEngine {
  #service; #tools; #store; #crypto; #clock; #enabled; #provider; #original; #controllers=new Set(); #active=false;
  constructor({enabled=false,service,tools,store,cryptoContext,provider=null,originalClient=null,clock=Date.now}) {
    if(enabled!==true||!(service instanceof CustomerRoutineService)||!(tools instanceof WorkflowToolClient)||!(store instanceof CipherArtifactStore))fail('unavailable');
    const s=closed(cryptoContext.inputScope,['kind','accountId','deviceId','lineId','intervalId','contextId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest']);
    for(const field of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'])s[field]=Uint8Array.from(s[field]);
    workflowContextAad(s);
    this.#service=service;this.#tools=tools;this.#store=store;
    this.#crypto={manifest:cryptoContext.manifest,inputScope:Object.freeze(s),inputPrivateKey:cryptoContext.inputPrivateKey,archiveReaderId:Uint8Array.from(cryptoContext.archiveReaderId)};
    if(provider!==null&&!(provider instanceof LocalProvider))fail('invalid_configuration');
    if(originalClient!==null&&!(originalClient instanceof OriginalReplyClient))fail('invalid_configuration');
    this.#original=originalClient;
    this.#provider=provider;this.#clock=clock;this.#enabled=true;
  }
  withdraw() {this.#enabled=false;for(const c of this.#controllers)c.abort();}
  #now(){const now=this.#clock();if(!Number.isSafeInteger(now)||now<1)fail('clock_unavailable');return this.#store.observeTime(now);}
  #live(){if(!this.#enabled)fail('withdrawn');}
  #recheckArtifact(callId,expected) {
    this.#live();const current=this.#store.read(callId,this.#now());
    try {
      for(const field of ['archive_digest','input_context','input_revision','input_digest','expires_ms'])
        if(current[field]!==expected[field])fail('artifact_unavailable');
    }finally{current.envelope.fill(0);}
  }
  async execute(value) {
    const {request_id,context_id,policy_id}=closed(value,['request_id','context_id','policy_id']);
    if(this.#active)fail('busy');this.#live();this.#active=true;
    let plain,output;const controller=new AbortController();this.#controllers.add(controller);
    try {
      const p=await this.#service.current(context_id,policy_id);this.#live();
      if(p.original_input!=null)fail('original_input_required');
      const start=performance.now();
      const fresh=async({signal=controller.signal}={})=>{const next=await this.#service.current(context_id,policy_id,{signal});this.#live();
        if(signal.aborted||JSON.stringify(next)!==JSON.stringify(p)||this.#now()>=p.expires_ms||performance.now()-start>=p.timeout_ms)fail('authority_unavailable');};
      if(this.#now()>=p.expires_ms)fail('expired');
      const metadata=(await this.#tools.call('workflow.context.metadata',{request_id:randomUUID(),context_id})).result;this.#live();
      const scope=this.#crypto.inputScope;
      if(uuidText(scope.contextId)!==context_id||Number(scope.revision)!==metadata.revision||scope.expiresMs<=BigInt(this.#now()))fail('scope_denied');
      const call=await this.#service.admit({request_id,policy_id,context_id,input_revision:metadata.revision,input_source_digest:metadata.source_content_digest,direction:'owner_declared'});this.#live();
      // Lost admission responses/replays never execute again, even with no local artifact.
      if(!call.execute_once)return Object.freeze({state:call.phase,call});
      const content=(await this.#tools.call('workflow.context.content',{request_id:randomUUID(),context_id})).result;this.#live();
      if(content.revision!==metadata.revision)fail('scope_denied');
      plain=await openIntegrationWorkflowContext(this.#crypto.manifest,scope,BigInt(this.#now()),this.#crypto.inputPrivateKey,Uint8Array.from(Buffer.from(content.envelope_base64url,'base64url')));this.#live();
      await fresh();
      if(p.executor==='deterministic_local')output=renderRoutine(p.kind,plain);
      else {
        if(!this.#provider||this.#provider.identity.adapter_id!==p.adapter_id||this.#provider.identity.artifact_digest!==p.artifact_digest)fail('executor_unavailable');
        const remaining=Math.floor(p.timeout_ms-(performance.now()-start));if(remaining<10)fail('authority_unavailable');
        try{output=await this.#provider.run({call,adapter_id:p.adapter_id,kind:p.kind,policyArtifactDigest:p.artifact_digest,input:plain,timeoutMs:remaining,signal:controller.signal,preInvoke:fresh,postReturn:fresh});}catch{fail('provider_unknown','unknown');}this.#live();
      }
      const outputScope={...scope,contextId:uuidBytes(call.assigned_output_context_id),revision:1n,readerId:Uint8Array.from(this.#crypto.archiveReaderId),expiresMs:BigInt(Math.min(Number(scope.expiresMs),p.expires_ms))};
      const envelope=await sealWorkflowContext(this.#crypto.manifest,outputScope,BigInt(this.#now()),output);this.#live();
      await fresh();
      const hash=this.#store.put({call_id:call.call_id,input_context:context_id,input_revision:metadata.revision,input_digest:metadata.source_content_digest,expires_ms:Number(outputScope.expiresMs),envelope});
      const produced=await this.#service.produced(context_id,call.call_id,hash);this.#live();
      return Object.freeze({state:'awaiting_owner_publication',call:produced,archive_ciphertext_digest:hash});
    } finally {plain?.fill(0);output?.fill(0);this.#active=false;controller.abort();this.#controllers.delete(controller);}
  }
  /** Original ciphertext is opened locally; owner-configured policy, rather than
   * message text or sender identity, admits one bounded executor call.
   */
  async executeOriginal(value) {
    const {request_id,context_id,policy_id,event_id}=closed(value,['request_id','context_id','policy_id','event_id']);
    if(![request_id,context_id,policy_id,event_id].every(id))fail('invalid_request');
    if(this.#active)fail('busy');this.#live();
    if(!this.#original||!this.#provider)fail('executor_unavailable');
    this.#active=true;
    let instructions,input,output,deadlineTimer;const controller=new AbortController();this.#controllers.add(controller);
    const start=performance.now();
    try {
      const p=await this.#service.currentOriginalPolicy(context_id,policy_id);this.#live();
      if(p.original_input==null||p.executor!=='local_process'||this.#provider.identity.adapter_id!==p.adapter_id||
        this.#provider.identity.artifact_digest!==p.artifact_digest)fail('executor_unavailable');
      const remainingBudget=Math.floor(p.timeout_ms-(performance.now()-start));
      if(remainingBudget<10)fail('authority_unavailable');
      deadlineTimer=setTimeout(()=>controller.abort(),remainingBudget);
      const scope=this.#crypto.inputScope;
      const metadata=(await this.#tools.call('workflow.context.metadata',{request_id:randomUUID(),context_id})).result;this.#live();
      if(uuidText(scope.contextId)!==context_id||Number(scope.revision)!==metadata.revision||scope.expiresMs<=BigInt(this.#now()))fail('scope_denied');
      const source=await this.#original.readVerified(uuidBytes(event_id));this.#live();
      const authority=source.authority;
      const same=(a,b)=>a.length===b.length&&a.every((byte,index)=>byte===b[index]);
      for(const [field,expected] of [['account',scope.accountId],['device',scope.deviceId],['line',scope.lineId],
        ['interval',scope.intervalId],['reader',scope.readerId]])if(!same(authority[field],expected))fail('scope_denied');
      const peer=new Uint8Array(await crypto.subtle.digest('SHA-256',textEncoder.encode(authority.peer)));
      if(!same(peer,scope.peerDigest)||!same(authority.manifest.digest,scope.manifestDigest)||authority.manifest.version!==scope.manifestVersion)fail('scope_denied');
      const expiresMs=Math.min(Number(scope.expiresMs),p.expires_ms,Number(authority.expiresMs));
      if(!Number.isSafeInteger(expiresMs)||this.#now()>=expiresMs)fail('expired');
      const admitted=await this.#service.admitOriginal({request_id,policy_id,context_id,input_revision:metadata.revision,
        input_source_digest:metadata.source_content_digest,event_id,accepted_manifest_version:source.accepted_manifest_version,
        event_envelope_digest:source.event_envelope_digest},{signal:controller.signal});this.#live();
      // The server retains the event identity across response loss and policy changes.
      if(!admitted.execute_once)return Object.freeze({state:admitted.phase,call:admitted});
      const fresh=async({signal=controller.signal}={})=>{
        if(signal.aborted)fail('authority_unavailable');
        const next=await this.#service.currentOriginalPolicy(context_id,policy_id,{signal});this.#live();
        if(JSON.stringify(next)!==JSON.stringify(p))fail('authority_unavailable');
        const current=await this.#service.currentOriginal(admitted.call_id,{signal});this.#live();
        if(current.policy_id!==policy_id||current.phase!=='unknown'||signal.aborted||this.#now()>=expiresMs||
          performance.now()-start>=p.timeout_ms)fail('authority_unavailable');
      };
      const content=(await this.#tools.call('workflow.context.content',{request_id:randomUUID(),context_id})).result;this.#live();
      if(content.revision!==metadata.revision)fail('scope_denied');
      instructions=await openIntegrationWorkflowContext(this.#crypto.manifest,scope,BigInt(this.#now()),this.#crypto.inputPrivateKey,
        Uint8Array.from(Buffer.from(content.envelope_base64url,'base64url')));this.#live();
      let configuration;
      try{configuration=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(instructions));}catch{fail('invalid_content');}
      if(!configuration||Object.getPrototypeOf(configuration)!==Object.prototype)fail('invalid_content');
      input=textEncoder.encode(JSON.stringify({configuration,original_message:source.plaintext}));
      if(input.length<1||input.length>32768)fail('invalid_content');
      await fresh();
      const remaining=Math.floor(p.timeout_ms-(performance.now()-start));if(remaining<10)fail('authority_unavailable');
      try{output=await this.#provider.run({call:admitted,adapter_id:p.adapter_id,kind:p.kind,policyArtifactDigest:p.artifact_digest,
        input,timeoutMs:remaining,signal:controller.signal,preInvoke:fresh,postReturn:fresh});}catch{fail('provider_unknown','unknown');}
      this.#live();await fresh();
      const outputScope={...scope,contextId:uuidBytes(admitted.assigned_output_context_id),revision:1n,
        readerId:Uint8Array.from(this.#crypto.archiveReaderId),expiresMs:BigInt(expiresMs)};
      const envelope=await sealWorkflowContext(this.#crypto.manifest,outputScope,BigInt(this.#now()),output);this.#live();
      await fresh();
      const hash=this.#store.put({call_id:admitted.call_id,input_context:context_id,input_revision:metadata.revision,
        input_digest:metadata.source_content_digest,expires_ms:expiresMs,envelope});
      await fresh();
      const produced=await this.#service.produced(context_id,admitted.call_id,hash);this.#live();
      return Object.freeze({state:'awaiting_owner_publication',call:produced,archive_ciphertext_digest:hash});
    } finally {clearTimeout(deadlineTimer);instructions?.fill(0);input?.fill(0);output?.fill(0);this.#active=false;controller.abort();this.#controllers.delete(controller);}
  }
  /** Owner-local decryption/review. Returned bytes are caller-owned and must be wiped. */
  async review(callId,archivePrivateKey) {
    this.#live();const artifact=this.#store.read(callId,this.#now());
    const scope={...this.#crypto.inputScope,contextId:uuidBytes(callId),revision:1n,readerId:this.#crypto.archiveReaderId,expiresMs:BigInt(artifact.expires_ms)};
    let plain;
    try {
      plain=await openWorkflowContext(this.#crypto.manifest,scope,BigInt(this.#now()),archivePrivateKey,artifact.envelope);
      this.#recheckArtifact(callId,artifact);return plain;
    }catch(error){plain?.fill(0);throw error;}
    finally{artifact.envelope.fill(0);}
  }
  /** Explicit owner action after review; never called by execute or a model. */
  async publishArchive(callId,requestId) {this.#live();const a=this.#store.read(callId,this.#now());return this.#service.publishArchive(requestId,a.envelope);}
  /** A separately encrypted owner-declared representation. No grant is minted here. */
  async projection(callId,archivePrivateKey,selectedReaderId) {
    let text,envelope,artifact;try {text=await this.review(callId,archivePrivateKey);artifact=this.#store.read(callId,this.#now());
      const scope={...this.#crypto.inputScope,contextId:uuidBytes(callId),revision:1n,readerId:selectedReaderId,expiresMs:BigInt(artifact.expires_ms)};
      envelope=await sealIntegrationWorkflowContext(this.#crypto.manifest,scope,BigInt(this.#now()),text);
      this.#recheckArtifact(callId,artifact);return envelope;
    }catch(error){envelope?.fill(0);throw error;}
    finally{text?.fill(0);artifact?.envelope.fill(0);}
  }
  async bindAndResume(callId,requestId,outputService) {
    this.#live();if(!(outputService instanceof CustomerRoutineService))fail('output_grant_required');
    const artifact=this.#store.read(callId,this.#now());
    await outputService.bindOutput({request_id:requestId,call_id:callId,output_context_id:callId,output_revision:1,output_source_digest:ciphertextDigest(artifact.envelope),produced_digest:artifact.archive_digest});this.#live();
    return outputService.resume(callId);
  }
}
