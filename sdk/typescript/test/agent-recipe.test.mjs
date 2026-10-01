// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {AgentRecipe} from '../dist/agent-recipe.js';
import {FileRecipeStore,recipeScope,verifyFixtureReply,callableRecipe,previewServer} from '../examples/recipe-simulator.mjs';

const fixture=JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json',import.meta.url),'utf8'));
const outbound=Uint8Array.from(Buffer.from(fixture.outbound.envelopeHex,'hex'));
const now=()=>recipeScope.expiresAt-60000;
async function storage(t){
  const directory=await mkdtemp(join(tmpdir(),'zrotext-recipe-test-'));
  t.after(()=>rm(directory,{recursive:true,force:true}));
  return {directory,store:new FileRecipeStore(directory)};
}
test('task completion persists exact identity and unknown stays unknown after restart',async t=>{
  const {directory,store}=await storage(t);
  const recipe=new AgentRecipe(recipeScope,store,now);
  assert.equal((await recipe.taskCompletion('job_one',outbound,true)).state,'unknown');
  const restarted=new AgentRecipe(recipeScope,new FileRecipeStore(directory),now);
  assert.equal((await restarted.taskCompletion('job_one',outbound)).state,'unknown');
  const checkpoint=JSON.parse(await readFile(join(directory,'checkpoint.json'),'utf8'));
  assert.equal(checkpoint.used,1);assert.equal(checkpoint.notifications.job_one.result.attempts,1);
  assert.equal(JSON.stringify(checkpoint).includes(fixture.outbound.envelopeHex),false);
});
test('reply signature and selected reader are verified before durable consumption',async t=>{
  const {directory,store}=await storage(t);const recipe=new AgentRecipe(recipeScope,store,now);
  const event=await verifyFixtureReply();
  const first=await recipe.verifiedReply(event);
  assert.equal(first.state,'reply_routed_for_review');assert.equal(first.content,'selected-reader');
  const replay=await new AgentRecipe(recipeScope,new FileRecipeStore(directory),now).verifiedReply(event);
  assert.equal(replay.state,'replayed');
  assert.equal((await recipe.ownerProposal(event.actionId)).state,'awaiting_authenticated_exact_approval');
  const tampered=Uint8Array.from(Buffer.from(fixture.inbound.envelopeHex,'hex'));tampered[tampered.length-1]^=1;
  await assert.rejects(verifyFixtureReply(tampered));
  assert.equal((await recipe.verifiedReply({...event,eventId:'foreign',lineId:'foreign'})).state,'unverified_or_foreign_event');
});
test('ambiguous replies and missing content never become approval or model authority',async t=>{
  const {store}=await storage(t);const recipe=new AgentRecipe(recipeScope,store,now);const event=await verifyFixtureReply();
  assert.equal((await recipe.verifiedReply({...event,eventId:'ambiguous',activeRequest:false})).state,'owner_review');
  const unavailable=await recipe.verifiedReply({...event,eventId:'missing',contentAvailable:false});
  assert.equal(unavailable.state,'content_unavailable');assert.equal(unavailable.content,'unavailable');assert.equal(unavailable.modelProviderAccess,'none');
  assert.equal((await recipe.ownerProposal('proposal')).state,'awaiting_authenticated_exact_approval');
});
test('STOP persists and blocks subsequent notifications without decrypting content',async t=>{
  const {directory,store}=await storage(t);const event=await verifyFixtureReply();
  await new AgentRecipe(recipeScope,store,now).verifiedReply(event);
  const stopped=await new AgentRecipe(recipeScope,store,now).verifiedReply({...event,eventId:'stop_after_turn_cap',kind:'stop',contentAvailable:false});
  assert.equal(stopped.state,'metadata_only_stop');assert.equal(stopped.content,'unavailable');
  assert.equal((await new AgentRecipe(recipeScope,new FileRecipeStore(directory),now).taskCompletion('later',outbound)).state,'opted_out');
});
test('exported workflow and callable tool have no activation or credential channel',async()=>{
  const workflow=JSON.parse(await readFile(new URL('../../recipes/n8n-owner-preview.json',import.meta.url),'utf8'));
  const callable=JSON.parse(await readFile(new URL('../../recipes/callable-owner-preview.json',import.meta.url),'utf8'));
  assert.equal(workflow.active,false);assert.equal(workflow.nodes.length,2);
  assert.deepEqual(workflow.nodes.map(node=>node.type),['n8n-nodes-base.manualTrigger','n8n-nodes-base.httpRequest']);
  assert.equal(workflow.nodes.some(node=>node.credentials),false);
  const adapter=workflow.nodes[1].parameters;assert.equal(adapter.url,'http://localhost:37620/preview');
  assert.deepEqual(JSON.parse(adapter.body),{synthetic:true,operation:'journey'});
  assert.equal(adapter.options.redirect.redirect.followRedirects,false);
  assert.equal(callable.inputSchema.additionalProperties,false);assert.equal(callable.inputSchema.properties.synthetic.const,true);
  assert.equal(callable.runtime.productionAvailable,false);assert.equal(callable.runtime.modelProviderAccess,'none');assert.deepEqual(callable.runtime.credentials,[]);
});
test('expiry turn caps budgets takeover and revocation refuse fresh work',async t=>{
  const {store}=await storage(t);const recipe=new AgentRecipe(recipeScope,store,now);
  const event=await verifyFixtureReply();await recipe.verifiedReply(event);
  assert.equal((await recipe.verifiedReply({...event,eventId:'second'})).state,'expired_or_turn_limit');
  await recipe.taskCompletion('one',outbound);await recipe.taskCompletion('two',outbound);
  assert.equal((await recipe.taskCompletion('three',outbound)).state,'budget_exhausted');
  assert.equal((await new AgentRecipe(recipeScope,store,()=>recipeScope.expiresAt).ownerProposal('expired')).state,'expired');
  await store.transact(async checkpoint=>{checkpoint.takeover=true;});assert.equal((await recipe.ownerProposal('takeover')).state,'owner_takeover');
  await store.transact(async checkpoint=>{checkpoint.revoked=true;});assert.equal((await recipe.ownerProposal('revoked')).state,'revoked');
});
test('checkpoint lock prevents concurrent consumption and interrupted writes fail closed',async t=>{
  const {directory,store}=await storage(t);let release;const hold=new Promise(resolve=>{release=resolve;});let entered;const ready=new Promise(resolve=>{entered=resolve;});
  const first=store.transact(async()=>{entered();await hold;});await ready;
  await assert.rejects(new FileRecipeStore(directory).transact(async()=>{}),/checkpoint_busy/);release();await first;
  await writeFile(join(directory,'checkpoint.pending'),'interrupted');
  await assert.rejects(store.transact(async state=>{state.used++;}));
  assert.equal(JSON.parse(await readFile(join(directory,'checkpoint.json'),'utf8')).used,0);
});
test('malformed checkpoints and prototype identities cannot widen counters or scope',async t=>{
  const {directory,store}=await storage(t);const recipe=new AgentRecipe(recipeScope,store,now);
  for(const id of ['__proto__','constructor','prototype'])assert.equal((await recipe.taskCompletion(id,outbound)).state,'invalid_action');
  await recipe.ownerProposal('initial');const file=join(directory,'checkpoint.json');const state=JSON.parse(await readFile(file,'utf8'));state.used=-1;
  await writeFile(file,JSON.stringify(state));await assert.rejects(recipe.taskCompletion('later',outbound),/checkpoint_unavailable/);
});
test('actual local HTTP preview rejects credentials and returns only synthetic metadata',async t=>{
  const {store}=await storage(t);const server=previewServer(store);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}/preview`;
  const response=await fetch(url,{method:'POST',body:JSON.stringify({synthetic:true,operation:'journey'})});
  assert.equal(response.status,200);assert.equal(response.headers.get('cache-control'),'no-store');
  const body=await response.json();assert.equal(body.available,false);assert.equal(body.modelProviderAccess,'none');assert.equal(body.results.length,3);
  for(const input of [null,[],{synthetic:false,operation:'journey'},{synthetic:true,operation:'journey',credential:'refused'}]){
    const invalid=await fetch(url,{method:'POST',body:JSON.stringify(input)});assert.equal(invalid.status,400);
  }
  assert.equal((await callableRecipe('task_completion',store,'missing_grant')).state,'missing_grant');
});
