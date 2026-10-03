// SPDX-License-Identifier: AGPL-3.0-only
// Client journal/control tests only; real HTTP/database proof is a Rust fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { WorkflowToolClient, workflowTools } from '../dist/workflow-tool-client.js';
import { ScheduledRunner } from '../../scheduler/runner.mjs';
import { waitForFixturePoll } from '../../scheduler/service-fixture-wakeup.mjs';
import { DatabaseSync } from 'node:sqlite';
const uuid = n => `${String(n).repeat(8)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(12)}`;
const key={account_id:uuid(1),action_id:uuid(2),revision:1,binding_digest:'ab'.repeat(32)};
const policy={timezone:'UTC',first_local_date:'2027-01-01',opens_minute:500,closes_minute:600,repeat_every_days:null,max_occurrences:1,pacing_seconds:60};
function fixture() {
  const occurrence={occurrence_id:uuid(3),series_id:uuid(4),ordinal:0,phase:'waiting_window',opens_at_ms:Date.now()-1000,closes_at_ms:Date.now()+60000,expires_at_ms:Date.now()+60000};
  const readiness={available:true,methods:workflowTools.map(tool=>({method:tool.name,operation:tool.name==='workflow.action.cancel'?'send':tool.name.replace('workflow.','').replace('action.','').replaceAll('.','_'),read_only_hint:tool.annotations.readOnlyHint,destructive_hint:tool.annotations.destructiveHint,idempotent_hint:true,implementation:'library_candidate',transport_mounted:true,permission_granted:true})),scope:{context_id:uuid(5),device_id:uuid(6),line_id:uuid(7)},send_semantics:'owner_bound_prepared_only'};
  let phase='approved',state='waiting_phone',unknown=false,refuse=false,available=true,statusUnavailable=false;
  const calls=[];
  const client=new WorkflowToolClient({origin:'https://gateway.example',credential:'ztw_'+Buffer.alloc(32,7).toString('base64url'),fetchImpl:async(_,init)=>{
    if(refuse)return new Response(JSON.stringify({error:{code:'unauthorized'}}),{status:401,headers:{'content-type':'application/json'}});
    if(init.method==='GET')return new Response(JSON.stringify(readiness),{headers:{'content-type':'application/json'}});
    const request=JSON.parse(init.body);calls.push(request);
    if(statusUnavailable&&request.method==='workflow.action.status')return new Response(JSON.stringify({error:{code:'unavailable'}}),{status:503,headers:{'content-type':'application/json'}});
    let response;
    switch(request.method){
      case'workflow.action.schedule':response={kind:'occurrence',result:{...occurrence,series_id:request.params.series_id,ordinal:request.params.ordinal}};break;
      case'workflow.action.status':response={kind:'action',result:{key,record_version:1,phase,delivery:['dispatching','unknown'].includes(phase)?(available?{availability:'available',message_id:uuid(8),dispatch_id:uuid(9),state:'queued',state_version:1,accepted_at_ms:1,updated_at_ms:2}:{availability:'unavailable'}):{availability:'not_bound'}}};break;
      case'workflow.action.send':if(unknown)throw new Error('synthetic response loss');response={kind:'send',result:state==='prepared'?{state,message_id:uuid(8),dispatch_id:uuid(9)}:{state}};break;
      case'workflow.action.cancel':response={kind:'cancel',result:{key,message_id:uuid(8),state:'cancelled'}};break;
      default:throw new Error('unexpected call');
    }
    return new Response(JSON.stringify(response),{headers:{'content-type':'application/json'}});
  }});
  return{client,calls,params:{request_id:uuid(6),key,policy,series_id:uuid(4),ordinal:0},set(values){if(values.phase)phase=values.phase;if(values.state)state=values.state;if(values.unknown!==undefined)unknown=values.unknown;if(values.refuse!==undefined)refuse=values.refuse;if(values.available!==undefined)available=values.available;if(values.statusUnavailable!==undefined)statusUnavailable=values.statusUnavailable;}};
}
const due=()=>new Promise(resolve=>setTimeout(resolve,5100));
test('unattended waiting poll uses a new correlation identity while retaining the exact occurrence',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture();const filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});
    await runner.enqueue(f.params);
    const controller=new AbortController();setTimeout(()=>controller.abort(),200);
    await runner.run({signal:controller.signal});
    assert.equal(runner.inspect(key.action_id).result.state,'waiting_phone');
    f.set({state:'prepared'});await due();await runner.advance(key.action_id);
    const sends=f.calls.filter(call=>call.method==='workflow.action.send');
    assert.equal(sends.length,2);assert.notEqual(sends[0].params.request_id,sends[1].params.request_id);
    assert.deepEqual(sends.map(call=>call.params.occurrence_id),[uuid(3),uuid(3)]);
    assert.equal(runner.inspect(key.action_id).state,'prepared');
    const bytes=await readFile(filename);assert.equal(bytes.includes(Buffer.from('ztw_')),false);
    await runner.cancel(key.action_id);assert.equal(runner.inspect(key.action_id).state,'cancelled');
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});
test('response loss and restart reconcile status without another Send or invented binding',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);
    f.set({unknown:true});await assert.rejects(runner.advance(key.action_id),error=>error.state==='unknown');
    const identity=runner.inspect(key.action_id).request_id;runner.close();runner=new ScheduledRunner({client:f.client,filename,enabled:true});
    await due();await runner.advance(key.action_id);assert.equal(runner.inspect(key.action_id).state,'unknown');
    assert.equal(runner.inspect(key.action_id).request_id,identity);
    assert.equal(f.calls.filter(call=>call.method==='workflow.action.send').length,1);
    f.set({phase:'dispatching',available:false});await due();await runner.advance(key.action_id);
    assert.equal(runner.inspect(key.action_id).state,'unknown');
    assert.equal(runner.inspect(key.action_id).request_id,identity);
    assert.equal(f.calls.filter(call=>call.method==='workflow.action.send').length,1);
    f.set({available:true});await due();await runner.advance(key.action_id);
    assert.deepEqual(runner.inspect(key.action_id).result,{state:'prepared',message_id:uuid(8),dispatch_id:uuid(9)});
    assert.equal(f.calls.filter(call=>call.method==='workflow.action.send').length,1);
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});
test('current credential refusal and disabled installation cannot execute a journaled actor',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename});await assert.rejects(runner.enqueue(f.params),/disabled/);
    runner.close();runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);f.set({refuse:true});
    await assert.rejects(runner.advance(key.action_id),error=>error.code==='unauthorized');assert.equal(runner.inspect(key.action_id).state,'blocked');
    assert.equal(f.calls.filter(call=>call.method==='workflow.action.send').length,0);
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});

test('local failure after the durable Send checkpoint remains unknown and polls status only',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture(),filename=join(directory,'journal.sqlite');
    const call=f.client.call.bind(f.client);
    f.client.call=async(method,params)=>{
      const response=await call(method,params);
      if(method==='workflow.action.send')throw new TypeError('synthetic local response handling failure');
      return response;
    };
    runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);
    await assert.rejects(runner.advance(key.action_id),TypeError);
    const identity=runner.inspect(key.action_id).request_id;
    assert.equal(runner.inspect(key.action_id).state,'unknown');
    await due();await runner.advance(key.action_id);
    assert.equal(runner.inspect(key.action_id).state,'unknown');
    assert.equal(runner.inspect(key.action_id).request_id,identity);
    assert.equal(f.calls.filter(entry=>entry.method==='workflow.action.send').length,1);
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});

test('disable during a pending status read prevents a new Send checkpoint or request',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});await runner.enqueue(f.params);
    let entered,release;
    const reached=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});
    const call=f.client.call.bind(f.client);
    f.client.call=async(method,params)=>{const response=await call(method,params);if(method==='workflow.action.status'){entered();await held;}return response;};
    const pending=runner.advance(key.action_id);await reached;runner.disable();release();
    await assert.rejects(pending,error=>error.code==='disabled');
    assert.equal(f.calls.filter(entry=>entry.method==='workflow.action.send').length,0);
    assert.equal(runner.inspect(key.action_id).request_id,null);
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});

test('disable while readiness is pending prevents Schedule and Cancel',async()=>{
  for(const operation of ['enqueue','cancel']){
    const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
    try{
      const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});
      if(operation==='cancel')await runner.enqueue(f.params);
      let entered,release;const reached=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});
      const ready=f.client.readiness.bind(f.client);f.client.readiness=async()=>{const result=await ready();entered();await held;return result;};
      const before=f.calls.length;const pending=operation==='enqueue'?runner.enqueue(f.params):runner.cancel(key.action_id);
      await reached;runner.disable();release();await assert.rejects(pending,error=>error.code==='disabled');assert.equal(f.calls.length,before);
    }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
  }
});

test('disable releases its waiting lease and preserves unknown identity for a restarted runner',async()=>{
  for(const unknown of [false,true]){
    const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
    try{
      const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);
      if(unknown){f.set({unknown:true});await assert.rejects(runner.advance(key.action_id));await due();}
      const original=runner.inspect(key.action_id);let entered,release;
      const reached=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});const call=f.client.call.bind(f.client);
      f.client.call=async(method,params)=>{const result=await call(method,params);if(method==='workflow.action.status'){entered();await held;}return result;};
      const pending=runner.advance(key.action_id);await reached;runner.disable();release();await assert.rejects(pending,error=>error.code==='disabled');
      assert.deepEqual(runner.inspect(key.action_id),original);runner.close();f.client.call=call;f.set({unknown:false,state:'prepared'});
      runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.advance(key.action_id);
      assert.equal(runner.inspect(key.action_id).state,unknown?'unknown':'prepared');assert.equal(f.calls.filter(c=>c.method==='workflow.action.send').length,1);
      if(unknown)assert.equal(runner.inspect(key.action_id).request_id,original.request_id);
    }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
  }
});

test('disable after Send starts records its returned outcome without issuing another request',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture();f.set({state:'prepared'});runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});await runner.enqueue(f.params);
    let entered,release;const reached=new Promise(resolve=>{entered=resolve;});const held=new Promise(resolve=>{release=resolve;});const call=f.client.call.bind(f.client);
    f.client.call=async(method,params)=>{const response=await call(method,params);if(method==='workflow.action.send'){entered();await held;}return response;};
    const pending=runner.advance(key.action_id);await reached;runner.disable();release();assert.equal((await pending).state,'prepared');
    assert.equal(f.calls.filter(c=>c.method==='workflow.action.send').length,1);await assert.rejects(runner.advance(key.action_id),error=>error.code==='disabled');
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});


test('TLS fixture observes the durable local poll deadline without rewriting it or sending early',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
  try{
    const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);await runner.advance(key.action_id);
    const readDeadline=()=>{const db=new DatabaseSync(filename,{readOnly:true});try{return db.prepare('SELECT next_ms FROM scheduled_actions WHERE action_id=?').get(key.action_id).next_ms;}finally{db.close();}};
    const deadline=readDeadline();assert.ok(deadline>Date.now());f.set({state:'prepared'});
    // A real future journal wake returns the prior waiting observation, even
    // when the remote server would now permit preparation.
    assert.equal((await runner.advance(key.action_id)).state,'waiting');
    assert.equal(f.calls.filter(c=>c.method==='workflow.action.send').length,1);
    await waitForFixturePoll(filename,key.action_id);assert.equal(readDeadline(),deadline);assert.ok(Date.now()>=deadline);
    assert.equal((await runner.advance(key.action_id)).state,'prepared');assert.equal(f.calls.filter(c=>c.method==='workflow.action.send').length,2);
  }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});


test('journal export is bounded and erasure permanently fences restart and pending work',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner,other;
 try {
  const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});
  await runner.enqueue(f.params);
  assert.equal(runner.exportPage({limit:1}).items.length,1);
  assert.deepEqual(runner.exportPage().items[0].identity.params,f.params);
  assert.throws(()=>runner.exportPage({limit:101}),/invalid_page/);
  other=new ScheduledRunner({client:f.client,filename,enabled:true});
  runner.erase();assert.deepEqual(runner.exportPage(),{items:[],next:null});
  await assert.rejects(other.advance(key.action_id),/disabled/);
  other.close();other=new ScheduledRunner({client:f.client,filename,enabled:true});
  await assert.rejects(other.enqueue(f.params),/disabled/);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.send').length,0);
 }finally{other?.close();runner?.close();await rm(directory,{recursive:true,force:true});}
});
test('retention removes expired resolved metadata while preserving unknown and retired identity',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});await runner.enqueue(f.params);
  const db=new DatabaseSync(filename);
  const row=db.prepare('SELECT identity FROM scheduled_actions').get(),identity=JSON.parse(row.identity);
  identity.occurrence.expires_at_ms=Date.now()-1000;
  db.prepare("UPDATE scheduled_actions SET identity=?,state='unknown'").run(JSON.stringify(identity));
  assert.equal(runner.retain({beforeMs:Date.now()}),0);
  db.prepare("UPDATE scheduled_actions SET state='cancelled'").run();
  assert.equal(runner.retain({beforeMs:Date.now(),limit:1}),1);db.close();
  assert.equal(runner.exportPage().items[0].state,'retired');
  assert.equal(runner.exportPage().items[0].identity,null);
  await assert.rejects(runner.enqueue(f.params),/retired/);
  assert.throws(()=>runner.retain({beforeMs:Date.now()+100000}),/invalid_retention/);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});
test('recurrence cannot reuse an action approval for a different ordinal or change an existing occurrence',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});
  await runner.enqueueOccurrence(f.params);
  const policy={...f.params.policy,repeat_every_days:1,max_occurrences:2};
  await assert.rejects(runner.enqueueOccurrence({...f.params,policy,ordinal:1,request_id:uuid(7)}),/approval_reused/);
  await assert.rejects(runner.enqueueOccurrence({...f.params,policy}),/changed_schedule/);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.schedule').length,1);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});


test('each supplied recurring ordinal retains its distinct action and actual service occurrence',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});
  const policy={...f.params.policy,repeat_every_days:1,max_occurrences:2};
  await runner.enqueueOccurrence({...f.params,policy});
  const second={...f.params,policy,request_id:uuid(7),key:{...key,action_id:uuid(8)},ordinal:1};
  await runner.enqueueOccurrence(second);
  const items=runner.exportPage().items;
  assert.deepEqual(items.map(x=>x.identity.params.ordinal),[0,1]);
  assert.deepEqual(items.map(x=>x.action_id),[key.action_id,second.key.action_id]);
  const page=runner.exportPage({limit:1});assert.equal(page.items.length,1);assert.equal(page.next,key.action_id);
  assert.equal(runner.exportPage({after:page.next,limit:1}).items[0].action_id,second.key.action_id);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.schedule').length,2);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});
test('prepared work polls verified server cancellation without a second Send or local reply authority',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});
  await runner.enqueue(f.params);f.set({state:'prepared'});await runner.advance(key.action_id);
  assert.equal(runner.inspect(key.action_id).state,'prepared');
  f.set({phase:'cancelled'});await due();await runner.advance(key.action_id);
  assert.equal(runner.inspect(key.action_id).state,'cancelled');
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.send').length,1);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.cancel').length,0);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});


test('unknown action with available dispatch metadata remains unknown and cannot be retained as resolved',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture();runner=new ScheduledRunner({client:f.client,filename:join(directory,'journal.sqlite'),enabled:true});
  await runner.enqueue(f.params);f.set({phase:'unknown'});await runner.advance(key.action_id);
  assert.equal(runner.inspect(key.action_id).state,'unknown');
  assert.equal(runner.retain({beforeMs:Date.now()}),0);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.send').length,0);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});


for(const refusal of ['readiness','status','changed_phase'])test(`prepared reconciliation survives ${refusal} and retention/restart without another Send`,async()=>{
 const directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-'));let runner;
 try {
  const f=fixture(),filename=join(directory,'journal.sqlite');runner=new ScheduledRunner({client:f.client,filename,enabled:true});
  await runner.enqueue(f.params);f.set({state:'prepared'});await runner.advance(key.action_id);
  const before=runner.inspect(key.action_id),db=new DatabaseSync(filename);
  const identity=JSON.parse(db.prepare('SELECT identity FROM scheduled_actions').get().identity);identity.occurrence.expires_at_ms=Date.now()-1;
  db.prepare('UPDATE scheduled_actions SET identity=?,next_ms=0').run(JSON.stringify(identity));
  f.set(refusal==='readiness'?{refuse:true}:refusal==='status'?{statusUnavailable:true}:{phase:'expired'});
  if(refusal==='changed_phase')await runner.advance(key.action_id);else await assert.rejects(runner.advance(key.action_id),e=>['unauthorized','unavailable'].includes(e.code));
  assert.deepEqual(runner.inspect(key.action_id),before);
  assert.equal(runner.retain({beforeMs:Date.now()}),0);
  runner.close();runner=new ScheduledRunner({client:f.client,filename,enabled:true});
  db.prepare('UPDATE scheduled_actions SET next_ms=0').run();db.close();
  if(refusal==='changed_phase')await runner.advance(key.action_id);else await assert.rejects(runner.advance(key.action_id));
  assert.deepEqual(runner.inspect(key.action_id),before);
  assert.equal(f.calls.filter(x=>x.method==='workflow.action.send').length,1);
 }finally{runner?.close();await rm(directory,{recursive:true,force:true});}
});
