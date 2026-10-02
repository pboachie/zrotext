// SPDX-License-Identifier: AGPL-3.0-only
// Client journal/control tests only; real HTTP/database proof is a Rust fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { WorkflowToolClient, workflowTools } from '../dist/workflow-tool-client.js';
import { ScheduledRunner } from '../../scheduler/runner.mjs';
const uuid = n => `${String(n).repeat(8)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(12)}`;
const key={account_id:uuid(1),action_id:uuid(2),revision:1,binding_digest:'ab'.repeat(32)};
const policy={timezone:'UTC',first_local_date:'2027-01-01',opens_minute:500,closes_minute:600,repeat_every_days:null,max_occurrences:1,pacing_seconds:60};
function fixture() {
  const occurrence={occurrence_id:uuid(3),series_id:uuid(4),ordinal:0,phase:'waiting_window',opens_at_ms:Date.now()-1000,closes_at_ms:Date.now()+60000,expires_at_ms:Date.now()+60000};
  const readiness={available:true,methods:workflowTools.map(tool=>({method:tool.name,operation:tool.name==='workflow.action.cancel'?'send':tool.name.replace('workflow.','').replace('action.','').replaceAll('.','_'),read_only_hint:tool.annotations.readOnlyHint,destructive_hint:tool.annotations.destructiveHint,idempotent_hint:true,implementation:'library_candidate',transport_mounted:true,permission_granted:true})),scope:{context_id:uuid(5),device_id:uuid(6),line_id:uuid(7)},send_semantics:'owner_bound_prepared_only'};
  let phase='approved',state='waiting_phone',unknown=false,refuse=false,available=true;
  const calls=[];
  const client=new WorkflowToolClient({origin:'https://gateway.example',credential:'ztw_'+Buffer.alloc(32,7).toString('base64url'),fetchImpl:async(_,init)=>{
    if(refuse)return new Response(JSON.stringify({error:{code:'unauthorized'}}),{status:401,headers:{'content-type':'application/json'}});
    if(init.method==='GET')return new Response(JSON.stringify(readiness),{headers:{'content-type':'application/json'}});
    const request=JSON.parse(init.body);calls.push(request);
    let response;
    switch(request.method){
      case'workflow.action.schedule':response={kind:'occurrence',result:occurrence};break;
      case'workflow.action.status':response={kind:'action',result:{key,record_version:1,phase,delivery:phase==='dispatching'?(available?{availability:'available',message_id:uuid(8),dispatch_id:uuid(9),state:'queued',state_version:1,accepted_at_ms:1,updated_at_ms:2}:{availability:'unavailable'}):{availability:'not_bound'}}};break;
      case'workflow.action.send':if(unknown)throw new Error('synthetic response loss');response={kind:'send',result:state==='prepared'?{state,message_id:uuid(8),dispatch_id:uuid(9)}:{state}};break;
      case'workflow.action.cancel':response={kind:'cancel',result:{key,message_id:uuid(8),state:'cancelled'}};break;
      default:throw new Error('unexpected call');
    }
    return new Response(JSON.stringify(response),{headers:{'content-type':'application/json'}});
  }});
  return{client,calls,params:{request_id:uuid(6),key,policy,series_id:uuid(4),ordinal:0},set(values){if(values.phase)phase=values.phase;if(values.state)state=values.state;if(values.unknown!==undefined)unknown=values.unknown;if(values.refuse!==undefined)refuse=values.refuse;if(values.available!==undefined)available=values.available;}};
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
