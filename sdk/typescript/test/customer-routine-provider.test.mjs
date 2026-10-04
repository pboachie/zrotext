// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,readFileSync,rmSync,realpathSync,existsSync,chmodSync} from 'node:fs';
import {join,sep} from 'node:path';import {tmpdir} from 'node:os';import {createHash,randomUUID} from 'node:crypto';
import {LocalProvider} from '../../assistant/local-provider.mjs';
import {customerRoutineDiagnostic} from '../../assistant/customer-routines.mjs';
test('CLI diagnostic exposes only closed codes and never exception text',()=>{
 const canary='synthetic private output';
 assert.equal(customerRoutineDiagnostic({code:'artifact_changed',message:canary,stack:canary}),'artifact_changed');
 for(const error of [Error(canary),{code:canary,message:canary},{code:'artifact_changed\n'+canary},null])assert.equal(customerRoutineDiagnostic(error),'unavailable');
});
const hash=v=>createHash('sha256').update(v).digest('hex');
const response='response';
async function waitForAuthorityCallback(ready,outcome){
 let timer;
 try{await Promise.race([ready,outcome.then(()=>{throw new Error('provider_settled_before_authority_callback');}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('authority_callback_not_reached')),6000);})]);}
 finally{clearTimeout(timer);}
}
test('authority readiness refuses an already settled invocation instead of hanging',async()=>{
 await assert.rejects(waitForAuthorityCallback(new Promise(()=>{}),Promise.resolve()),{message:'provider_settled_before_authority_callback'});
 await assert.rejects(waitForAuthorityCallback(new Promise(()=>{}),Promise.reject(new Error('fixed_invocation_failure'))),{message:'fixed_invocation_failure'});
 await waitForAuthorityCallback(Promise.resolve(),new Promise(()=>{}));
});
function fixture(t,body){const anchor=realpathSync(tmpdir()),dir=mkdtempSync(join(anchor,'zt-routine-child-'));chmodSync(dir,0o700);const canonical=realpathSync(dir);
 t.after(()=>{assert.equal(realpathSync(dir),canonical);assert.ok(canonical.startsWith(anchor+sep));rmSync(canonical,{recursive:true});});
 const script=join(dir,'child.mjs'),marker=join(dir,'invocations'),pid=join(dir,'owned-pid');
 const code=String.raw`import fs from 'node:fs';import {dirname} from 'node:path';import {fileURLToPath} from 'node:url';
const mode=JSON.parse(fs.readFileSync(new URL('./mode.json',import.meta.url),'utf8'));let text='';
process.stdin.on('data',b=>text+=b);process.stdin.on('end',()=>{const q=JSON.parse(text);
fs.writeFileSync(new URL('./owned-pid',import.meta.url),String(process.pid));fs.appendFileSync(new URL('./invocations',import.meta.url),'x');
switch(mode){
case 'environment':if(process.env.ZT_PROVIDER_TEST_CANARY||process.env.NODE_OPTIONS||process.cwd()!==dirname(fileURLToPath(import.meta.url)))process.exit(9);
case 'response':process.stdout.write(JSON.stringify({v:1,call_id:q.call_id,output_base64url:Buffer.from('synthetic local output').toString('base64url')}));break;
case 'timeout':process.on('SIGTERM',()=>{});setInterval(()=>{},1000);break;
case 'canary':process.stdout.write('synthetic-private-canary-not-json');break;
case 'wrong_id':process.stdout.write(JSON.stringify({v:1,call_id:'foreign',output_base64url:'eA'}));break;
case 'oversize':process.stdout.write('x'.repeat(13000));break;
case 'utf8':process.stdout.write(Buffer.from([255,254,253]));break;
case 'descendant':import('node:child_process').then(({spawn})=>{const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{env:{},stdio:['ignore',process.stdout,process.stderr]});fs.writeFileSync(new URL('./descendant',import.meta.url),String(c.pid));process.exit(0);});break;
default:process.exit(9);
}});`;
 writeFileSync(join(dir,'mode.json'),JSON.stringify(body),{mode:0o600});writeFileSync(script,code,{mode:0o600});
 const artifact={adapter_id:'synthetic_local',executable:process.execPath,executable_digest:hash(readFileSync(process.execPath)),args:[script],cwd:dir,artifact_files:[{path:script,digest:hash(readFileSync(script))},{path:join(dir,'mode.json'),digest:hash(readFileSync(join(dir,'mode.json')))}]};
 const provider=new LocalProvider({approvedArtifact:artifact}),id=randomUUID();
 const request={call:{call_id:id,assigned_output_context_id:id,execute_once:true,phase:'unknown',output_context_id:null,output_revision:null,action_id:null,binding_digest:null},adapter_id:artifact.adapter_id,kind:'faq',policyArtifactDigest:provider.identity.artifact_digest,input:new TextEncoder().encode('synthetic input'),timeoutMs:5000,preInvoke:async()=>{},postReturn:async()=>{}};
 return {provider,request,artifact,marker,pid};}
test('real local child has explicit cwd and credential-free environment, duplicate call never respawns',async t=>{
 const f=fixture(t,'environment');
 process.env.ZT_PROVIDER_TEST_CANARY='synthetic';try{const bytes=await f.provider.run(f.request);assert.equal(new TextDecoder().decode(bytes),'synthetic local output');bytes.fill(0);await assert.rejects(f.provider.run(f.request),{code:'unknown_no_retry'});assert.equal(readFileSync(f.marker,'utf8'),'x');}finally{delete process.env.ZT_PROVIDER_TEST_CANARY;f.provider.close();}
});
test('real SIGTERM-handler child reaches timeout and direct owned PID exits',async t=>{
 const f=fixture(t,'timeout');const start=performance.now();
 await assert.rejects(f.provider.run({...f.request,timeoutMs:3000}),{code:'provider_unknown'});assert.ok(performance.now()-start<4500);
 assert.equal(readFileSync(f.marker,'utf8'),'x');assert.throws(()=>process.kill(Number(readFileSync(f.pid,'utf8')),0));f.provider.close();
});
test('hung authority callback and withdrawal cannot hold returned plaintext',async t=>{
 const f=fixture(t,response),c=new AbortController();let entered,observed;const ready=new Promise(r=>entered=r);
 const outcome=assert.rejects(f.provider.run({...f.request,signal:c.signal,postReturn:({signal})=>{observed=signal;entered();return new Promise(()=>{});}}),{code:'provider_unknown'});
 await waitForAuthorityCallback(ready,outcome);c.abort();await outcome;assert.equal(observed.aborted,true);await assert.rejects(f.provider.run(f.request),{code:'unknown_no_retry'});f.provider.close();
});
test('expired preInvoke and policy mismatch launch zero children',async t=>{
 const f=fixture(t,response);await assert.rejects(f.provider.run({...f.request,policyArtifactDigest:'0'.repeat(64)}),{code:'invalid_invocation'});
 await assert.rejects(f.provider.run({...f.request,timeoutMs:1000,preInvoke:()=>new Promise(()=>{})}),{code:'provider_unknown'});assert.equal(existsSync(f.marker),false);f.provider.close();
});
test('child JSON error canary is redacted and a non-executable replay shape is refused',async t=>{
 const f=fixture(t,'canary');await assert.rejects(f.provider.run(f.request),e=>{assert.equal(e.code,'invalid_output');assert.equal(e.message,'invalid_output');assert.equal(e.stack.includes('synthetic-private-canary'),false);return true;});f.provider.close();
 const replay=new LocalProvider({approvedArtifact:f.artifact});await assert.rejects(replay.run({...f.request,call:{...f.request.call,execute_once:false}}),{code:'not_executable'});replay.close();assert.equal(readFileSync(f.marker,'utf8'),'x');
 // This tests the non-executable shape. Actual HTTPS admission/restart authority
 // is independently exercised by the Rust/router integration fixture.
});
test('wrong call ID, oversized output and invalid UTF8 are fixed refusals',async t=>{
 for(const body of ['wrong_id','oversize','utf8']){const f=fixture(t,body);await assert.rejects(f.provider.run(f.request),{code:'invalid_output',message:'invalid_output'});f.provider.close();}
});
test('actual changed approved script refuses before any child launch',async t=>{
 const f=fixture(t,response);writeFileSync(f.artifact.args[0],'process.exit(0);');await assert.rejects(f.provider.run(f.request),{code:'artifact_changed'});assert.equal(existsSync(f.marker),false);f.provider.close();
});
test('withdrawal during deferred preInvoke never launches child',async t=>{
 const f=fixture(t,response),c=new AbortController();let entered;const ready=new Promise(r=>entered=r);
 const pending=assert.rejects(f.provider.run({...f.request,signal:c.signal,preInvoke:()=>{entered();return new Promise(()=>{});}}),{code:'provider_unknown'});await waitForAuthorityCallback(ready,pending);c.abort();await pending;assert.equal(existsSync(f.marker),false);f.provider.close();
});
test('postReturn completing after remaining deadline never returns plaintext or permits retry',async t=>{
 const f=fixture(t,response);let late;const authority=new Promise(r=>late=r);let reached;const ready=new Promise(r=>reached=r);
 const pending=assert.rejects(f.provider.run({...f.request,timeoutMs:3000,postReturn:()=>{reached();return authority;}}),{code:'provider_unknown'});
 await waitForAuthorityCallback(ready,pending);await pending;late();await new Promise(r=>setTimeout(r,10));await assert.rejects(f.provider.run(f.request),{code:'unknown_no_retry'});f.provider.close();
});
test('POSIX inherited pipe cannot delay bounded return and exact synthetic descendant cleanup', {skip:process.platform==='win32'},async t=>{
 const f=fixture(t,'descendant'),receipt=join(f.artifact.cwd,'descendant');
 try{const start=performance.now();await assert.rejects(f.provider.run({...f.request,timeoutMs:3000}),{code:'provider_unknown'});assert.ok(performance.now()-start<4500);assert.throws(()=>process.kill(Number(readFileSync(f.pid,'utf8')),0));}
 finally{if(existsSync(receipt)){const pid=Number(readFileSync(receipt,'utf8'));try{process.kill(pid,'SIGKILL');}catch(e){assert.equal(e.code,'ESRCH');}}f.provider.close();}
 // Direct-child termination does not claim process-tree isolation. The one
 // descendant is created and cleaned only by this explicitly owned test.
});
