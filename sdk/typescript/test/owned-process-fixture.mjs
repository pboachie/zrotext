// SPDX-License-Identifier: AGPL-3.0-only
// Test-only PID-owned process lifetime; no product execution or credentials.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
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
  return new Promise((resolve,reject)=>{const child=spawn(command,args,{cwd,env,windowsHide:true,shell:false,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});let size=0,output='',done=false;
    const closed=new Promise(resolveClose=>child.once('close',resolveClose));
    const timer=setTimeout(()=>void fail(),timeoutMs);async function fail(){if(done)return;done=true;clearTimeout(timer);try{if(child.pid)await terminateOwnedTree(child,closed);reject(Error('Fixture subprocess failed or exceeded bound'));}catch(error){reject(error);}}
    child.stdout.on('data',chunk=>{size+=chunk.length;if(size>maximum)void fail();else if(!done)output+=chunk.toString('utf8');});child.stderr.on('data',chunk=>{size+=chunk.length;if(size>maximum)void fail();});child.on('error',()=>void fail());child.on('close',code=>{clearTimeout(timer);if(done)return;done=true;if(code!==0)reject(Error('Fixture subprocess failed or exceeded bound'));else resolve(output);});
  });
}
