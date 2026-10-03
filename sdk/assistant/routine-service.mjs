// SPDX-License-Identifier: AGPL-3.0-only
// Customer-owned credentials only. No provider or plaintext transport.
export class CustomerRoutineError extends Error {
  constructor(code, state = 'refused') { super(code); this.name = 'CustomerRoutineError'; this.code = code; this.state = state; }
}
export const fail = (code, state) => { throw new CustomerRoutineError(code, state); };
export const id = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
export const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export function closed(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Reflect.ownKeys(value).length !== fields.length) fail('invalid_request');
  const copy = {};
  for (const field of fields) {
    const property = Object.getOwnPropertyDescriptor(value, field);
    if (!property || !Object.hasOwn(property, 'value')) fail('invalid_request');
    copy[field] = property.value;
  }
  return copy;
}
const integer = (v, min, max) => Number.isSafeInteger(v) && v >= min && v <= max;
export function policy(value) {
  const fields=['request_id','policy_id','context_id','routine_id','generation','kind','executor','period','expires_ms','call_limit','unit_limit','units_per_call','turn_limit','timeout_ms','window'];
  const legacy=value&&typeof value==='object'&&!Object.hasOwn(value,'adapter_id')&&!Object.hasOwn(value,'artifact_digest');
  const normalized=legacy?{...closed(value,fields),adapter_id:null,artifact_digest:null}:value;
  const p = closed(normalized,[...fields,'adapter_id','artifact_digest']);
  if (!['request_id','policy_id','context_id','routine_id'].every(k => id(p[k])) ||
      !['faq','intake','note','reminder','owner_reply'].includes(p.kind) || !['deterministic_local','local_process'].includes(p.executor) || p.period !== 'utc_day' ||
      !integer(p.generation,1,Number.MAX_SAFE_INTEGER) || !integer(p.expires_ms,1,Number.MAX_SAFE_INTEGER) ||
      !integer(p.call_limit,1,100) || !integer(p.unit_limit,1,1000000) || !integer(p.units_per_call,1,p.unit_limit) ||
      !integer(p.turn_limit,1,3) || !integer(p.timeout_ms,10,30000)) fail('invalid_request');
  if(p.executor==='deterministic_local' ? (p.adapter_id!==null||p.artifact_digest!==null) :
    (!/^[a-z][a-z0-9_-]{0,63}$/.test(p.adapter_id)||!digest(p.artifact_digest)))fail('invalid_request');
  const w = closed(p.window,['timezone','first_local_date','opens_minute','closes_minute','repeat_every_days','max_occurrences','pacing_seconds']);
  if (!(w.timezone === null || (typeof w.timezone === 'string' && /^[!-~]{1,128}$/.test(w.timezone))) ||
      !/^\d{4}-\d{2}-\d{2}$/.test(w.first_local_date) || !integer(w.opens_minute,0,1439) ||
      !integer(w.closes_minute,0,1439) || w.opens_minute === w.closes_minute || w.repeat_every_days !== null ||
      w.max_occurrences !== 1 || !integer(w.pacing_seconds,60,86400)) fail('invalid_request');
  return Object.freeze({...p, window:Object.freeze(w)});
}
export function call(value) {
  const c = closed(value,['call_id','assigned_output_context_id','execute_once','policy_id','phase','output_context_id','output_revision','action_id','binding_digest']);
  if (!id(c.call_id) || c.assigned_output_context_id !== c.call_id || !id(c.policy_id) || typeof c.execute_once !== 'boolean' ||
      !['unknown','produced','published','proposed'].includes(c.phase) ||
      !(c.output_context_id === null || c.output_context_id === c.call_id) ||
      !(c.output_revision === null || integer(c.output_revision,1,128)) || !(c.action_id === null || id(c.action_id)) ||
      !(c.binding_digest === null || digest(c.binding_digest))) fail('response_unknown','unknown');
  if(c.execute_once && (c.phase!=='unknown'||c.output_context_id!==null||c.output_revision!==null||c.action_id!==null||c.binding_digest!==null))fail('response_unknown','unknown');
  const published=c.phase==='published'||c.phase==='proposed';
  if(published ? (c.output_context_id!==c.call_id||c.output_revision!==1) :
    (c.output_context_id!==null||c.output_revision!==null))fail('response_unknown','unknown');
  if(c.phase==='proposed' ? (c.action_id!==c.call_id||c.binding_digest===null) :
    (c.action_id!==null||c.binding_digest!==null))fail('response_unknown','unknown');
  return Object.freeze(c);
}
function credential(value) {
  if (typeof value !== 'string' || !/^ztw_[A-Za-z0-9_-]{43}$/.test(value)) fail('invalid_configuration');
  const bytes = Buffer.from(value.slice(4),'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value.slice(4)) fail('invalid_configuration');
  return value;
}
async function boundedJson(response) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type') ?? '')) fail('response_unknown','unknown');
  const reader = response.body?.getReader(); if (!reader) fail('response_unknown','unknown');
  let size=0; const chunks=[];
  try { for (;;) { const next=await reader.read(); if (next.done) break; size+=next.value.length; if(size>65536) fail('response_unknown','unknown'); chunks.push(next.value); } }
  finally { await reader.cancel().catch(()=>{}); reader.releaseLock(); }
  return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));
}
/** Explicit trusted startup configuration. Neither credential is a tool argument. */
export class CustomerRoutineService {
  #origin; #input; #output; #fetch; #timeout; #owner;
  constructor({origin,inputCredential,outputCredential=null,fetchImpl=fetch,timeoutMs=10000,owner=null}) {
    let parsed; try { parsed=new URL(origin); } catch { fail('invalid_configuration'); }
    if(parsed.protocol!=='https:' || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname!=='/' || !integer(timeoutMs,10,10000)) fail('invalid_configuration');
    this.#origin=parsed.origin; this.#input=credential(inputCredential); this.#output=outputCredential===null?null:credential(outputCredential);
    this.#fetch=fetchImpl; this.#timeout=timeoutMs;
    // A separately supplied live owner session; never reconstructed from an integration grant.
    if(owner!==null) {
      const o=closed(owner,['cookie','csrf']);
      if(typeof o.cookie!=='string' || !o.cookie || /[\r\n]/.test(o.cookie) || typeof o.csrf!=='string' || !o.csrf || /[\r\n]/.test(o.csrf)) fail('invalid_configuration');
      this.#owner=o;
    }
  }
  async #request(path,body,{owner=false,dual=false,binary=false,headers={},expected=200,signal}={}) {
    if(owner && !this.#owner) fail('owner_required'); if(dual && !this.#output) fail('output_grant_required');
    const controller=new AbortController(); let timer,abort;
    const cancellation=new Promise((_,reject)=>{if(signal){abort=()=>{controller.abort();reject(new CustomerRoutineError('response_unknown','unknown'));};if(signal.aborted)abort();else signal.addEventListener('abort',abort,{once:true});}});
    const snapshot=binary?Uint8Array.from(body):JSON.stringify(body);
    if((binary?snapshot.length:Buffer.byteLength(snapshot))>(binary?33075:path==='/v1/auth/workflow-grants'?50000:8192)) fail('invalid_request');
    try {
      return await Promise.race([cancellation,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new CustomerRoutineError('response_unknown','unknown'));},this.#timeout);}), (async()=>{
        const url=this.#origin+path;
        if(controller.signal.aborted)fail('response_unknown','unknown');
        const response=await this.#fetch(url,{method:'POST',redirect:'error',cache:'no-store',credentials:'omit',signal:controller.signal,body:snapshot,
          headers:{Accept:'application/json','Content-Type':binary?'application/vnd.zrotext.workflow-context.v1':'application/json',
            ...(owner?{Cookie:this.#owner.cookie,Origin:this.#origin,'x-zrotext-csrf':this.#owner.csrf,
              ...(path.includes('/routines/')?{'x-zrotext-routine-input':this.#input}:{})}:
              {Authorization:`Bearer ${dual?this.#output:this.#input}`}),
            ...(dual?{[owner?'x-zrotext-routine-output':'x-zrotext-routine-input']:owner?this.#output:this.#input}:{}),...headers}});
        if(response.redirected || (response.url && response.url!==url)) fail('response_unknown','unknown');
        const value=await boundedJson(response);
        if(response.status!==expected) {
          const e=closed(value,['error']); const code=closed(e.error,['code']).code;
          const statuses={invalid_request:400,unauthorized:401,forbidden:403,not_found:404,conflict:409,rate_limited:429,unavailable:503};
          if(statuses[code]!==response.status) fail('response_unknown','unknown');
          fail(code,code==='unavailable'?'unknown':'refused');
        }
        return value;
      })()]);
    } catch(error) { if(error instanceof CustomerRoutineError) throw error; fail('response_unknown','unknown'); }
    finally { clearTimeout(timer);if(abort)signal.removeEventListener('abort',abort); controller.abort(); }
  }
  async current(contextId,policyId,{signal}={}) {
    if(!id(contextId)||!id(policyId)) fail('invalid_request');
    const v=closed(await this.#request('/v1/workflow/routines',{operation:'current',params:{context_id:contextId,policy_id:policyId}},{signal}),['kind','result']);
    if(v.kind!=='policy') fail('response_unknown','unknown'); const p=policy(v.result);
    if(p.context_id!==contextId||p.policy_id!==policyId) fail('response_unknown','unknown'); return p;
  }
  async #call(operation,params,dual=false) {
    const v=closed(await this.#request('/v1/workflow/routines',{operation,params},{dual}),['kind','result']);
    if(v.kind!=='call') fail('response_unknown','unknown'); return call(v.result);
  }
  async admit(value) {
    const v=closed(value,['request_id','policy_id','context_id','input_revision','input_source_digest','direction']);
    if(!id(v.request_id)||!id(v.policy_id)||!id(v.context_id)||!integer(v.input_revision,1,128)||!digest(v.input_source_digest)||v.direction!=='owner_declared') fail('invalid_request');
    const result=await this.#call('admit',v); if(result.policy_id!==v.policy_id||result.call_id!==v.request_id) fail('response_unknown','unknown'); return result;
  }
  async produced(contextId,callId,archiveDigest) {
    if(!id(contextId)||!id(callId)||!digest(archiveDigest)) fail('invalid_request');
    const result=await this.#call('produced',{context_id:contextId,call_id:callId,archive_ciphertext_digest:archiveDigest});
    if(result.call_id!==callId||result.phase!=='produced'||result.execute_once) fail('response_unknown','unknown'); return result;
  }
  async resume(callId) { if(!id(callId)) fail('invalid_request'); const result=await this.#call('resume',{call_id:callId},true); if(result.call_id!==callId) fail('response_unknown','unknown'); return result; }
  async configure(value) { const p=policy(value); const result=closed(await this.#request('/v1/owner/workflow/routines/policy',p,{owner:true}),['configured']); if(result.configured!==true)fail('response_unknown','unknown');return result; }
  async publishArchive(requestId,envelope) {
    if(!id(requestId)||!(envelope instanceof Uint8Array)) fail('invalid_request');
    const r=closed(await this.#request('/v1/owner/workflow/contexts',envelope,{owner:true,binary:true,headers:{'idempotency-key':requestId,'x-zrotext-context-revision':'0'}}),['revision']);
    if(r.revision!==1) fail('response_unknown','unknown'); return r;
  }
  async bindOutput(value) {
    const v=closed(value,['request_id','call_id','output_context_id','output_revision','output_source_digest','produced_digest']);
    if(!id(v.request_id)||!id(v.call_id)||v.output_context_id!==v.call_id||v.output_revision!==1||!digest(v.output_source_digest)||!digest(v.produced_digest)) fail('invalid_request');
    const r=closed(await this.#request('/v1/owner/workflow/routines/output',v,{owner:true,dual:true}),['kind','result']);
    if(r.kind!=='call') fail('response_unknown','unknown'); const result=call(r.result); if(result.call_id!==v.call_id) fail('response_unknown','unknown'); return result;
  }
  /** Explicit live-owner password/MFA ceremony. Never invoked by the executor. */
  async issueOutputGrant(value) {
    const v=closed(value,['current_password','code','connector_id','context_id','contact_id','purpose','permissions','signer_key_id','expires_at_ms','content_envelope_base64url']);
    if(!id(v.connector_id)||!id(v.context_id)||!id(v.contact_id)||!['transactional','operational','marketing'].includes(v.purpose)||
      typeof v.current_password!=='string'||!v.current_password||v.current_password.length>1024||typeof v.code!=='string'||!v.code||v.code.length>128||
      !Array.isArray(v.permissions)||v.permissions.length<1||v.permissions.length>7||new Set(v.permissions).size!==v.permissions.length||
      v.permissions.some(p=>!['contact_read','context_metadata','context_content','propose','status','schedule','send'].includes(p))||
      !integer(v.expires_at_ms,1,Number.MAX_SAFE_INTEGER)||typeof v.content_envelope_base64url!=='string'||v.content_envelope_base64url.length>44100)fail('invalid_request');
    const result=closed(await this.#request('/v1/auth/workflow-grants',v,{owner:true,expected:201}),['grant_id','token']);
    if(!id(result.grant_id))fail('response_unknown','unknown');credential(result.token);return result;
  }
}
