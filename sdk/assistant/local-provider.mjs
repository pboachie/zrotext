// SPDX-License-Identifier: AGPL-3.0-only
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync, openSync, fstatSync, closeSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';
import { privateDirectory } from './private-store.mjs';
import { closed } from './routine-service.mjs';

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hash=v=>createHash('sha256').update(v).digest('hex');
export class ProviderError extends Error {constructor(code){super(code);this.code=code;}}
const refuse=code=>{throw new ProviderError(code);};
function installationHash(path){
  let fd;
  try{fd=openSync(path,'r');const stat=fstatSync(fd);
    if(!stat.isFile()||stat.size<1||stat.size>128*1024*1024)refuse('artifact_changed');
    const bytes=readFileSync(fd);try{if(bytes.length!==stat.size)refuse('artifact_changed');return hash(bytes);}finally{bytes.fill(0);}
  }catch(error){if(error instanceof ProviderError)throw error;refuse('artifact_changed');}
  finally{if(fd!==undefined)closeSync(fd);}
}
async function boundedHash(path,deadline,signal){
  const file=await open(path,'r');const buffer=Buffer.alloc(32768);
  try{const stat=await file.stat();if(!stat.isFile()||stat.size<1||stat.size>128*1024*1024)refuse('artifact_changed');
    const h=createHash('sha256');let count=0;
    while(true){if(signal.aborted||performance.now()>=deadline)refuse('provider_unknown');
      const {bytesRead}=await file.read(buffer,0,buffer.length,null);if(!bytesRead)break;count+=bytesRead;if(count>stat.size)refuse('artifact_changed');h.update(buffer.subarray(0,bytesRead));}
    if(count!==stat.size)refuse('artifact_changed');return h.digest('hex');
  }finally{buffer.fill(0);await file.close();}
}
// This is a trusted local launcher, not a sandbox. The parent engine owns
// actual HTTP admission, policy freshness, key custody and sensitive proposals.
export class LocalProvider {
  #seen=new Map(); #selected; #directory; #active=false;
  constructor({approvedArtifact}) {
    const a=closed(approvedArtifact,['adapter_id','executable','executable_digest','args','cwd','artifact_files']);
    if(!isAbsolute(a.executable)||!isAbsolute(a.cwd)||/^[\\/]{2}/.test(a.executable)||/^[\\/]{2}/.test(a.cwd))refuse('invalid_configuration');
    if(!/^[a-z][a-z0-9_-]{0,63}$/.test(a.adapter_id)||!/^[0-9a-f]{64}$/.test(a.executable_digest)||
      !Array.isArray(a.args)||a.args.length>16||a.args.some(v=>typeof v!=='string'||v.length>1024)||
      !Array.isArray(a.artifact_files)||a.artifact_files.length>16)refuse('invalid_configuration');
    const executable=realpathSync(a.executable),cwd=realpathSync(a.cwd);
    this.#directory=privateDirectory(a.cwd);
    if(installationHash(executable)!==a.executable_digest)refuse('artifact_changed');
    const artifacts=a.artifact_files.map(value=>{const v=closed(value,['path','digest']);if(!isAbsolute(v.path)||/^[\\/]{2}/.test(v.path)||!/^[0-9a-f]{64}$/.test(v.digest))refuse('invalid_configuration');
      const path=realpathSync(v.path);if(installationHash(path)!==v.digest)refuse('artifact_changed');return Object.freeze({path,digest:v.digest});});
    const approval_digest=hash(Buffer.concat([Buffer.from('ZT/customer-routine-local-executor/v1\0'),Buffer.from(JSON.stringify([a.adapter_id,executable,a.executable_digest,a.args,cwd,artifacts]))]));
    this.#selected=Object.freeze({adapter_id:a.adapter_id,executable,cwd,digest:a.executable_digest,args:Object.freeze([...a.args]),artifacts,approval_digest});

  }
  close(){if(this.#active)refuse('busy');}
  get identity(){return Object.freeze({adapter_id:this.#selected.adapter_id,artifact_digest:this.#selected.approval_digest});}
  async run({call,adapter_id,kind,input,timeoutMs,signal,preInvoke,postReturn,policyArtifactDigest}) {
    const deadline=performance.now()+timeoutMs;
    if(this.#active)refuse('busy');
    if(!uuid.test(call.call_id)||call.assigned_output_context_id!==call.call_id||adapter_id!==this.#selected.adapter_id||
      !(input instanceof Uint8Array)||input.length<1||input.length>32768||!Number.isInteger(timeoutMs)||timeoutMs<10||timeoutMs>30000||
      !['faq','intake','note','reminder','owner_reply'].includes(kind)||typeof preInvoke!=='function'||typeof postReturn!=='function'||policyArtifactDigest!==this.#selected.approval_digest)refuse('invalid_invocation');
    const digest=hash(input), prior=this.#seen.get(call.call_id);
    if(prior){if(prior.adapter!==this.#selected.approval_digest||prior.input_digest!==digest)refuse('replay_conflict');refuse('unknown_no_retry');}
    if(call.execute_once!==true||call.phase!=='unknown'||call.output_context_id!==null||call.output_revision!==null||call.action_id!==null||call.binding_digest!==null)refuse('not_executable');
    if(signal?.aborted)refuse('withdrawn');
    // In-process duplicate guard only. Actual service admission unknown and
    // execute_once=false are the durable restart authority; no new local ledger.
    this.#seen.set(call.call_id,{adapter:this.#selected.approval_digest,input_digest:digest});
    this.#active=true;
    const frame=Buffer.from(JSON.stringify({v:1,call_id:call.call_id,kind,input_base64url:Buffer.from(input).toString('base64url')})+'\n');
    const chunks=[];let total=0,child,timer,exited=false,exitDone;
    const controller=new AbortController();
    const aborted=()=>controller.abort();
    signal?.addEventListener('abort',aborted,{once:true});
    const terminate=()=>{if(child&&!exited){try{child.kill('SIGKILL');}catch{}}
      child?.stdin.destroy();child?.stdout.destroy();child?.stderr.destroy();};
    const bounded=operation=>new Promise((resolve,reject)=>{
      let complete=false,timeout;
      const stop=()=>{if(complete)return;complete=true;clearTimeout(timeout);controller.abort();terminate();reject(new ProviderError('provider_unknown'));};
      const abort=()=>stop();controller.signal.addEventListener('abort',abort,{once:true});
      timeout=setTimeout(stop,Math.max(0,deadline-performance.now()));
      Promise.resolve().then(()=>{if(controller.signal.aborted)refuse('provider_unknown');return operation();}).then(value=>{
        if(complete){if(value instanceof Uint8Array)value.fill(0);return;}complete=true;resolve(value);
      },error=>{if(!complete){complete=true;reject(error instanceof ProviderError?error:new ProviderError('provider_unknown'));}}).finally(()=>{clearTimeout(timeout);controller.signal.removeEventListener('abort',abort);});
    });
    try {
      await bounded(async()=>{
        if(await boundedHash(this.#selected.executable,deadline,controller.signal)!==this.#selected.digest)refuse('artifact_changed');
        for(const a of this.#selected.artifacts)if(await boundedHash(a.path,deadline,controller.signal)!==a.digest)refuse('artifact_changed');
        if(controller.signal.aborted||performance.now()>=deadline)refuse('provider_unknown');
        await preInvoke({signal:controller.signal});
      });
      if(controller.signal.aborted||performance.now()>=deadline)refuse('provider_unknown');
      this.#directory.verify();
      const response=await bounded(()=>new Promise((resolve,reject)=>{
        let failure;
        const stop=code=>{if(!failure)failure=new ProviderError(code);terminate();reject(failure);};
        child=spawn(this.#selected.executable,this.#selected.args,{shell:false,windowsHide:true,
          // No inherited owner/workflow/provider credentials or NODE_OPTIONS.
          env:{},cwd:this.#selected.cwd,stdio:['pipe','pipe','pipe']});
        exitDone=new Promise(r=>child.once('exit',()=>{exited=true;r();}));
        child.stdout.on('data',bytes=>{if(failure||controller.signal.aborted||performance.now()>=deadline){bytes.fill(0);stop('provider_unknown');return;}
          total+=bytes.length;if(total>12000){bytes.fill(0);stop('invalid_output');return;}chunks.push(bytes);});
        child.stderr.on('data',bytes=>{bytes.fill(0);stop('invalid_output');});
        child.stdin.on('error',()=>stop('provider_unknown'));
        child.on('error',()=>stop('provider_unknown'));
        child.on('close',code=>{
          if(failure||code!==0||performance.now()>=deadline){reject(failure??new ProviderError('provider_unknown'));return;}
          resolve(Buffer.concat(chunks));});
        child.stdin.end(frame);
      }));
      let output;
      try {
        let value;try{value=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(response));}catch{refuse('invalid_output');}
        if(value===null||typeof value!=='object'||Array.isArray(value))refuse('invalid_output');
        if(Object.keys(value).sort().join(',')!=='call_id,output_base64url,v'||value.v!==1||value.call_id!==call.call_id||
          typeof value.output_base64url!=='string'||!/^[A-Za-z0-9_-]+$/.test(value.output_base64url))refuse('invalid_output');
        output=Uint8Array.from(Buffer.from(value.output_base64url,'base64url'));
        if(output.length<1||output.length>8192||Buffer.from(output).toString('base64url')!==value.output_base64url)refuse('invalid_output');
        try{new TextDecoder('utf8',{fatal:true}).decode(output);}catch{refuse('invalid_output');}
        // Hook supplied by real engine, outside child/model; no verified flag.
        await bounded(()=>postReturn({signal:controller.signal}));
        if(signal?.aborted||performance.now()>=deadline)refuse('provider_unknown');
        // Service Call unknown and execute_once=false fence process restarts.
        return output;
      }catch(error){output?.fill(0);throw error instanceof ProviderError?error:new ProviderError('provider_unknown');}
      finally{response.fill(0);}
    }catch(error){throw error instanceof ProviderError?error:new ProviderError('provider_unknown');}
    finally{clearTimeout(timer);controller.abort();signal?.removeEventListener('abort',aborted);terminate();
      // Wait for exact direct-child exit, never inherited-pipe close. Bounded
      // observation grace does not imply descendants were terminated.
      if(exitDone&&!exited)await Promise.race([exitDone,new Promise(r=>setTimeout(r,250))]);
      frame.fill(0);for(const b of chunks)b.fill(0);this.#active=false;}
  }
}
