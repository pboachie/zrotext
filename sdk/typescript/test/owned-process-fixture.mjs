// SPDX-License-Identifier: AGPL-3.0-only
// Test-only PID-owned process lifetime; no product execution or credentials.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
const failureObservations=new WeakMap();
const failureCategories=new Set(['launch-error','exit-failure','deadline','output-bound']);
function failureSnapshot(category,exitCode,started,stdoutBytes,stderrBytes){
  try{
    const elapsed=Math.floor(performance.now()-started);
    if(!failureCategories.has(category)||![elapsed,stdoutBytes,stderrBytes].every(value=>Number.isSafeInteger(value)&&value>=0))return null;
    return Object.freeze(Object.assign(Object.create(null),{category,exit_code:Number.isSafeInteger(exitCode)?exitCode:null,
      elapsed_ms:elapsed,stdout_bytes:stdoutBytes,stderr_bytes:stderrBytes}));
  }catch{return null;}
}
function observeFailure(error,snapshot){
  try{if(snapshot&&error!==null&&(typeof error==='object'||typeof error==='function'))failureObservations.set(error,snapshot);}catch{}
  return error;
}
export function ownedProcessFailureObservation(error){
  try{return error!==null&&(typeof error==='object'||typeof error==='function')?failureObservations.get(error)||null:null;}catch{return null;}
}
async function deadline(promise,milliseconds){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned process deadline exceeded')),milliseconds);})]);}finally{clearTimeout(timer);}}
export class CleanupFailure extends Error{}
export async function terminateOwnedTree(child,closed){
  assert.ok(Number.isSafeInteger(child.pid)&&child.pid>0,'Owned child PID required');
  if(process.platform==='win32'){
    const cleanup=fileURLToPath(new URL('../../../scripts/owned_process_cleanup.py',import.meta.url));
    await new Promise((resolve,reject)=>{const killer=spawn('python',[cleanup,String(child.pid)],{windowsHide:true,shell:false,stdio:'ignore'});const timer=setTimeout(()=>{killer.kill();reject(new CleanupFailure('Owned process tree termination failed'));},10000);killer.once('error',()=>{clearTimeout(timer);reject(new CleanupFailure('Owned process tree termination failed'));});killer.once('close',code=>{clearTimeout(timer);if(code===0)resolve();else reject(new CleanupFailure('Owned process tree termination failed'));});});
  }else{try{process.kill(-child.pid,'SIGKILL');}catch{throw new CleanupFailure('Owned process group termination failed');}}
  try{await deadline(closed,10000);}catch{throw new CleanupFailure('Owned process termination receipt missing');}
}
export async function runOwnedProcess(command,args,{cwd=process.cwd(),env=process.env,timeoutMs=1200000,maximum=16*1024*1024}={}){
  return new Promise((resolve,reject)=>{
    let started,child;try{started=performance.now();}catch{}
    try{child=spawn(command,args,{cwd,env,windowsHide:true,shell:false,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});}
    catch(error){reject(observeFailure(error,failureSnapshot('launch-error',null,started,0,0)));return;}
    let size=0,stdoutBytes=0,stderrBytes=0,output='',done=false;
    const closed=new Promise(resolveClose=>child.once('close',resolveClose));
    const timer=setTimeout(()=>void fail('deadline'),timeoutMs);
    async function fail(category){
      if(done)return;done=true;clearTimeout(timer);
      // Freeze the triggering observation before cleanup can close or write again.
      const snapshot=failureSnapshot(category,null,started,stdoutBytes,stderrBytes);
      try{if(child.pid)await terminateOwnedTree(child,closed);reject(observeFailure(Error('Fixture subprocess failed or exceeded bound'),snapshot));}
      catch(error){reject(observeFailure(error,snapshot));}
    }
    child.stdout.on('data',chunk=>{size+=chunk.length;stdoutBytes+=chunk.length;if(size>maximum)void fail('output-bound');else if(!done)output+=chunk.toString('utf8');});
    child.stderr.on('data',chunk=>{size+=chunk.length;stderrBytes+=chunk.length;if(size>maximum)void fail('output-bound');});
    child.on('error',()=>void fail('launch-error'));
    child.on('close',code=>{clearTimeout(timer);if(done)return;done=true;
      if(code!==0)reject(observeFailure(Error('Fixture subprocess failed or exceeded bound'),failureSnapshot('exit-failure',code,started,stdoutBytes,stderrBytes)));
      else resolve(output);
    });
  });
}
