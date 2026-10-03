// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,renameSync,linkSync,symlinkSync,rmSync,realpathSync,chmodSync} from 'node:fs';
import {join,sep} from 'node:path';import {tmpdir} from 'node:os';
import {privateStore,readPrivateConfiguration} from '../../assistant/private-store.mjs';
import {policy,CustomerRoutineService} from '../../assistant/routine-service.mjs';
function fixture(t){const anchor=realpathSync(tmpdir()),p=mkdtempSync(join(anchor,'zt-routine-store-'));chmodSync(p,0o700);const c=realpathSync(p);
 t.after(()=>{assert.equal(realpathSync(p),c);assert.ok(c.startsWith(anchor+sep));rmSync(c,{recursive:true});});return p;}
test('database identity and private sidecars persist, replaced file refuses',t=>{const p=fixture(t),file=join(p,'store.sqlite'),guard=privateStore(file);
 writeFileSync(file+'-wal','ciphertext',{mode:0o600});guard.verify();renameSync(file,file+'.old');writeFileSync(file,'replacement',{mode:0o600});assert.throws(()=>guard.verify(),/storage_unavailable/);});
test('hardlinked foreign sidecar refusal preserves foreign bytes',t=>{const p=fixture(t),file=join(p,'store.sqlite'),guard=privateStore(file),foreign=join(p,'foreign');writeFileSync(foreign,'synthetic preserved',{mode:0o600});linkSync(foreign,file+'-wal');assert.throws(()=>guard.verify(),/storage_unavailable/);assert.equal(readFileSync(foreign,'utf8'),'synthetic preserved');});
test('junction or symlink parent is refused and paths never enter errors',t=>{const p=fixture(t),target=join(p,'target'),alias=join(p,'alias');mkdirSync(target,{mode:0o700});symlinkSync(target,alias,process.platform==='win32'?'junction':'dir');
 for(const path of [join(alias,'store.sqlite'),join(p,'synthetic-sensitive-path','absent')])assert.throws(()=>privateStore(path),e=>{assert.equal(e.message,'storage_unavailable');assert.equal(e.stack.includes('synthetic-sensitive-path'),false);return true;});});
test('missing and non-directory private configuration have fixed errors and normalized Windows separators',t=>{const p=fixture(t),file=join(p,'config');writeFileSync(file,'synthetic config',{mode:0o600});
 const prior=process.cwd();try{process.chdir(p);const bytes=readPrivateConfiguration(process.platform==='win32'?file.replaceAll('\\','/'):file);assert.equal(bytes.toString(),'synthetic config');bytes.fill(0);
 for(const path of [join(p,'synthetic-sensitive-canary'),join(file,'child')])assert.throws(()=>readPrivateConfiguration(path),e=>{assert.equal(e.message,'storage_unavailable');assert.equal(e.stack.includes('synthetic-sensitive-canary'),false);return true;});}finally{process.chdir(prior);}});
test('POSIX public permissions refuse while Windows uses documented customer ACL trust',t=>{const p=fixture(t),file=join(p,'config');writeFileSync(file,'synthetic config',{mode:0o600});
 const prior=process.cwd();try{process.chdir(p);if(process.platform!=='win32'){chmodSync(p,0o777);assert.throws(()=>readPrivateConfiguration(file),/storage_unavailable/);chmodSync(p,0o700);chmodSync(file,0o644);assert.throws(()=>readPrivateConfiguration(file),/storage_unavailable/);}
 else{const bytes=readPrivateConfiguration(file);bytes.fill(0);}}finally{process.chdir(prior);} // No Windows ACL-verification claim.
});
test('configuration permits private nested files but refuses sibling and linked parent selection',t=>{
 const p=fixture(t),anchor=join(p,'selected'),nested=join(anchor,'nested'),foreign=join(p,'selected-sibling'),linked=join(anchor,'linked');
 mkdirSync(anchor,{mode:0o700});mkdirSync(nested,{mode:0o700});mkdirSync(foreign,{mode:0o700});
 const selected=join(nested,'config'),outside=join(foreign,'config');
 writeFileSync(selected,'synthetic selected config',{mode:0o600});writeFileSync(outside,'synthetic preserved foreign config',{mode:0o600});
 symlinkSync(foreign,linked,process.platform==='win32'?'junction':'dir');
 const prior=process.cwd();try{process.chdir(anchor);
  const bytes=readPrivateConfiguration(selected);assert.equal(bytes.toString(),'synthetic selected config');bytes.fill(0);
  for(const candidate of [outside,join(anchor,'..','selected-sibling','config'),join(linked,'config')])assert.throws(()=>readPrivateConfiguration(candidate),/storage_unavailable/);
  assert.equal(readFileSync(outside,'utf8'),'synthetic preserved foreign config');
 }finally{process.chdir(prior);}
});
const id='00000000-0000-4000-8000-000000000004';
const p={request_id:id,policy_id:id,context_id:id,routine_id:id,generation:1,kind:'faq',executor:'deterministic_local',period:'utc_day',expires_ms:100000,call_limit:1,unit_limit:1,units_per_call:1,turn_limit:1,timeout_ms:1000,window:{timezone:'UTC',first_local_date:'2026-01-01',opens_minute:1,closes_minute:2,repeat_every_days:null,max_occurrences:1,pacing_seconds:60}};
test('legacy deterministic pair normalizes null, process identity and closed owner fields are required',()=>{
 assert.equal(policy(p).adapter_id,null);assert.equal(policy({...p,executor:'local_process',adapter_id:'approved_local',artifact_digest:'ab'.repeat(32)}).executor,'local_process');
 for(const extra of [{adapter_id:'ignored',artifact_digest:null},{executor:'local_process'},{executor:'local_process',adapter_id:'../escape',artifact_digest:'ab'.repeat(32)},{executor:'local_process',adapter_id:'approved_local',artifact_digest:'AB'.repeat(32)},{executable:'not policy'}])assert.throws(()=>policy({...p,...extra}),{code:'invalid_request'});
});
test('actual current HTTP operation forwards cancellation and refuses hanging fetch with fixed unknown',async()=>{
 const c=new AbortController();let observed,entered;const ready=new Promise(r=>entered=r);
 const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:'ztw_'+Buffer.alloc(32,7).toString('base64url'),fetchImpl:async(_url,options)=>{observed=options.signal;entered();return new Promise(()=>{});}});
 const pending=assert.rejects(service.current(id,id,{signal:c.signal}),{code:'response_unknown',state:'unknown'});await ready;c.abort();await pending;assert.equal(observed.aborted,true);
});
