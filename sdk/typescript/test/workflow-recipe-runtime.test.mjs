// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { request as httpRequest } from 'node:http';
import { createWorkflowRecipeServer } from '../../recipes/workflow-runtime.mjs';
import { fixture, id } from '../../recipes/test-support/runtime-fixture.mjs';

test('disabled installation and actual read-only HTTPS preview precede exact proposal and independent preparation',()=>fixture(async f=>{
  assert.equal((await f.recipe.setup()).installed_state,'disabled');
  await assert.rejects(()=>f.recipe.call({operation:'task_completion',request_id:id(20)}),e=>e.code==='disabled');
  assert.equal((await f.recipe.preview(id(21))).approval,false);
  assert.deepEqual(f.calls.map(call=>call.method),['workflow.context.metadata']);
  await f.recipe.enable();
  assert.equal((await f.recipe.call({operation:'task_completion',request_id:id(22)})).result.phase,'proposed');
  assert.equal((await f.recipe.prepare({request_id:id(23),key:f.key})).result.state,'waiting_owner_binding');
  f.approve();assert.equal((await f.recipe.prepare({request_id:id(24),key:f.key})).result.state,'prepared');
  await assert.rejects(()=>f.recipe.prepare({request_id:id(25),key:{...f.key,binding_digest:'cd'.repeat(32)}}),e=>e.code==='scope_mismatch');
  await assert.rejects(()=>f.recipe.call({operation:'owner_proposal',request_id:id(26),verified:true}),e=>e.code==='invalid_request');
  await assert.rejects(()=>f.recipe.prepare([]),e=>e.code==='invalid_request');
  await assert.rejects(()=>f.recipe.prepare(Object.create({request_id:id(40),key:f.key})),e=>e.code==='invalid_request');
  f.revoke();await assert.rejects(()=>f.recipe.prepare({request_id:id(27),key:f.key}),e=>e.code==='unauthorized');
}));

test('signed replies use durable adapter identity and cannot approve send or repeat a proposal',()=>fixture(async f=>{
  await f.recipe.enable();const [raw,headers]=f.signed();
  assert.throws(()=>f.recipe.ingestReply(Buffer.concat([raw,Buffer.from(' ')]),headers),e=>e.code==='invalid_signature');
  f.recipe.ingestReply(raw,headers);
  const input={event_id:id(14),request_id:id(30)};
  assert.equal((await f.recipe.routeReply(input)).approval,false);
  assert.equal((await f.recipe.routeReply(input)).execute,false);
  assert.deepEqual(f.calls.map(call=>call.method),['workflow.action.propose']);
  assert.equal(f.adapter.exportMetadata().actions.length,1);
  const stop=f.signed(id(16),'opt_out');f.recipe.ingestReply(...stop);
  assert.equal((await f.recipe.routeReply({event_id:id(16),request_id:id(31)})).disposition,'stop');
  assert.equal(f.calls.length,1);
}));

test('missing remote grants refuse activation and local bridge rejects browser origin and caller authority fields',()=>fixture(async f=>{
  f.deny();await assert.rejects(()=>f.recipe.enable(),e=>e.code==='missing_grant');
  const local=Buffer.alloc(32,9),server=createWorkflowRecipeServer(f.recipe,local);
  await new Promise(done=>server.listen(0,'localhost',done));
  try{
    const url=`http://localhost:${server.address().port}/recipe`,headers={authorization:`Bearer ${local.toString('base64url')}`,'content-type':'application/json'};
    assert.equal((await fetch(url,{headers:{...headers,origin:'https://example.test'}})).status,401);
    assert.equal((await fetch(url,{headers:{...headers,cookie:''}})).status,401);
    const response=await fetch(url,{method:'POST',headers,body:JSON.stringify({operation:'verified_reply',params:{event_id:id(14),request_id:id(32),verified:true}})});
    assert.equal(response.status,400);
    assert.equal(f.calls.length,0);
    const slow=httpRequest(url,{method:'POST',headers:{...headers,'content-length':'1000'}});
    let timer;
    try {
      const closed=new Promise(done=>{slow.once('error',()=>done('closed'));slow.once('close',()=>done('closed'));});
      slow.write('{');
      const deadline=new Promise(done=>{timer=setTimeout(()=>done('late'),7500);});
      assert.equal(await Promise.race([closed,deadline]),'closed');
      assert.equal(f.calls.length,0);
    } finally {clearTimeout(timer);slow.destroy();}
  }finally{server.closeAllConnections();await new Promise(done=>server.close(done));}
}));

test('lost HTTPS reply leaves the durable reservation unknown and never automatically repeats the proposal',()=>fixture(async f=>{
  await f.recipe.enable();f.recipe.ingestReply(...f.signed());f.disconnect();
  const input={event_id:id(14),request_id:id(33)};
  assert.equal((await f.recipe.routeReply(input)).state,'unknown');
  assert.equal((await f.recipe.routeReply(input)).state,'unknown');
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].method,'workflow.action.propose');
  assert.equal(f.adapter.exportMetadata().actions.length,1);
}));

test('proposal-only grants can activate without send authority and cannot prepare output',()=>fixture(async f=>{
  f.denySend();await f.recipe.enable();
  assert.deepEqual((await f.recipe.setup()).required_permissions,['context_metadata','propose','status']);
  assert.equal((await f.recipe.call({operation:'owner_proposal',request_id:id(34)})).result.phase,'proposed');
  await assert.rejects(()=>f.recipe.prepare({request_id:id(35),key:f.key}),e=>e.code==='forbidden');
}));

test('disable cancels pending activation without allowing later requests',()=>fixture(async f=>{
  const release=f.holdReadiness();
  const enabling=f.recipe.enable();
  f.recipe.disable(); release();
  await assert.rejects(()=>enabling,e=>e.code==='disabled');
  await assert.rejects(()=>f.recipe.call({operation:'status',request_id:id(40)}),e=>e.code==='disabled');
  assert.equal(f.calls.length,0);
}));

test('disable fences preparation and proposal digest awaits without a POST',()=>fixture(async f=>{
  await f.recipe.enable();
  const preparing=f.recipe.prepare({request_id:id(41),key:f.key});
  f.recipe.disable();
  await assert.rejects(()=>preparing,e=>e.code==='disabled' || e.code==='forbidden');
  await f.recipe.enable();
  const proposal=f.recipe.call({operation:'owner_proposal',request_id:id(42)});
  f.recipe.disable();
  const refused=assert.rejects(()=>proposal,e=>e.code==='disabled' || e.code==='forbidden');
  await f.recipe.enable(); await refused;
  assert.equal(f.calls.length,0);
}));

test('disable during reply consumption preserves a nonreplayable unknown reservation without proposing',()=>fixture(async f=>{
  await f.recipe.enable();f.recipe.ingestReply(...f.signed());
  const input={event_id:id(14),request_id:id(43)};
  const pending=f.recipe.routeReply(input);
  f.recipe.disable();
  assert.equal((await pending).state,'unknown');
  await f.recipe.enable();
  assert.equal((await f.recipe.routeReply(input)).state,'unknown');
  assert.equal(f.calls.length,0);
  assert.equal(f.adapter.exportMetadata().actions.length,1);
}));
test('preparation snapshots the exact owner key before digest awaits',()=>fixture(async f=>{
  await f.recipe.enable();
  const key={...f.key};
  const pending=f.recipe.prepare({request_id:id(44),key});
  key.action_id=id(45);
  await pending;
  assert.equal(f.calls.length,1);
  assert.equal(f.calls[0].params.key.action_id,f.key.action_id);
}));
test('reply turn cap routes a second distinct signed event to owner review without another proposal',()=>fixture(async f=>{
  await f.recipe.enable();f.recipe.ingestReply(...f.signed());
  assert.equal((await f.recipe.routeReply({event_id:id(14),request_id:id(36)})).disposition,'reply_notice');
  f.recipe.ingestReply(...f.signed(id(17)));
  assert.equal((await f.recipe.routeReply({event_id:id(17),request_id:id(37)})).disposition,'owner_review');
  assert.equal(f.calls.length,1);
}));

test('offline request expiry refuses reply effects even while the event and source grant remain live',()=>fixture(async f=>{
  await f.recipe.enable();f.recipe.ingestReply(...f.signed());f.advance(31000);
  assert.equal((await f.recipe.routeReply({event_id:id(14),request_id:id(38)})).disposition,'owner_review');
  assert.equal(f.calls.length,0);
}));

test('trusted takeover after ingestion refuses cached reply authority before a service call',()=>fixture(async f=>{
  await f.recipe.enable();f.recipe.ingestReply(...f.signed());f.adapter.deny('takeover');
  await assert.rejects(()=>f.recipe.routeReply({event_id:id(14),request_id:id(39)}),e=>e.code==='revoked');
  assert.equal(f.calls.length,0);
}));
