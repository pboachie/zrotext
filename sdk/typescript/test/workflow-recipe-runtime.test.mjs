// SPDX-License-Identifier: AGPL-3.0-only
// Real HTTPS into a synthetic shared-service policy fixture, not gateway acceptance.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer, request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { webcrypto, createHmac } from 'node:crypto';
import { WorkflowRecipe, createWorkflowRecipeServer } from '../../recipes/workflow-runtime.mjs';
import { ReplyEventAdapter } from '../../replies/reply-events.mjs';
import { workflowTools } from '../dist/workflow-tools.js';
import { workflowActionDigest } from '../dist/workflow-decisions.js';
globalThis.crypto ??= webcrypto;
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const descriptor = { account_id:id(1), action_id:id(2), revision:1, line_id:id(3), recipient_id:id(4),
  purpose_id:'00000000-0000-0000-0000-000000000001', content_ref:id(5), content_digest:'ab'.repeat(32),
  content_version:1, not_before:10, expires_at:100, timezone:'UTC', window_id:'immediate-v1',
  routine_id:id(6), authority_generation:1, commitment:'informational' };
const credential = `ztw_${Buffer.alloc(32,7).toString('base64url')}`;

async function fixture(run) {
  const directory = await mkdtemp(join(tmpdir(),'zrotext-recipe-https-'));
  let server, adapter;
  try {
    const openssl = process.platform === 'win32' ? join('C:','Program Files','Git','usr','bin','openssl.exe') : 'openssl';
    execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
      '-addext','subjectAltName=DNS:localhost','-keyout','key.pem','-out','cert.pem'],{cwd:directory,stdio:'pipe',timeout:15000});
    const cert = await readFile(join(directory,'cert.pem'));
    const key = { account_id:id(1), action_id:id(2), revision:1, binding_digest:await workflowActionDigest(descriptor) };
    let permission=true, sendPermission=true, active=true, approved=false, disconnect=false, calls=[], time=1_700_000_000_000, readinessWait;
    server=createServer({key:await readFile(join(directory,'key.pem')),cert},async(req,res)=>{
      res.setHeader('content-type','application/json');
      if(!active || req.headers.authorization!==`Bearer ${credential}`){res.statusCode=401;res.end(JSON.stringify({error:{code:'unauthorized'}}));return;}
      if(req.method==='GET'){
        if(readinessWait) await readinessWait;
        res.end(JSON.stringify({available:true,methods:workflowTools.map(tool=>({method:tool.name,
          operation:tool.name==='workflow.action.cancel'?'send':tool.name.replace('workflow.','').replace('action.','').replaceAll('.','_'),
          read_only_hint:tool.annotations.readOnlyHint,destructive_hint:tool.annotations.destructiveHint,
          idempotent_hint:true,implementation:'library_candidate',transport_mounted:true,permission_granted:permission && (tool.name!=='workflow.action.send' || sendPermission)})),
          scope:{context_id:id(5),device_id:id(7),line_id:id(3)},send_semantics:'owner_bound_prepared_only'}));return;
      }
      let raw='';for await(const part of req)raw+=part;
      const body=JSON.parse(raw);calls.push(body);
      if(disconnect){req.socket.destroy();return;}
      if(!permission || (body.method==='workflow.action.send' && !sendPermission)){res.statusCode=403;res.end(JSON.stringify({error:{code:'forbidden'}}));return;}
      if(body.method==='workflow.context.metadata')res.end(JSON.stringify({kind:'context_metadata',result:{context_id:id(5),source_content_digest:descriptor.content_digest,revision:1,kind:1,expires_at_ms:time+60000,binding_generation:1,trust_generation:1,manifest_version:1}}));
      else if(body.method==='workflow.action.send')res.end(JSON.stringify({kind:'send',result:approved?{state:'prepared',message_id:id(8),dispatch_id:id(9)}:{state:'waiting_owner_binding'}}));
      else res.end(JSON.stringify({kind:'action',result:{key,record_version:1,phase:approved?'approved':'proposed'}}));
    });
    await new Promise(done=>server.listen(0,'localhost',done));
    // Trusted transport uses real TLS validation against this isolated fixture CA.
    const fetchImpl=(url,options)=>new Promise((resolveResult,reject)=>{
      const req=request(url,{method:options.method,headers:options.headers,ca:cert,signal:options.signal},res=>{
        const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolveResult(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
      });req.on('error',reject);req.end(options.body);
    });
    const eventKey=Buffer.alloc(32,1);
    adapter=new ReplyEventAdapter({path:join(directory,'replies.sqlite'),accountId:id(1),lineId:id(3),webhookSecret:eventKey,cursorSecret:Buffer.alloc(32,2),
      clock:()=>time,authority:()=>({active,accountId:id(1),lineId:id(3),deviceId:id(7),revision:'synthetic_policy',expiresAtMs:time+60000,
        canReadContent:true,readerId:id(10)}),readerId:id(10),reader:async()=>({kind:'decrypted',text:'Synthetic reply'})});
    adapter.registerRequest({id:id(11),messageId:id(8),attemptId:id(12),deviceId:id(7),startsAtMs:time-1000,expiresAtMs:time+30000,maxTurns:1});
    const recipe=new WorkflowRecipe({origin:`https://localhost:${server.address().port}`,credential,descriptor,fetchImpl,replyAdapter:adapter,consumerId:id(13)});
    const signed=(eventId=id(14),classification='captured_local')=>{
      const event={v:1,type:'inbound.message',event_id:eventId,delivery_id:id(15),account_id:id(1),device_id:id(7),message_id:id(8),attempt_id:id(12),
        classification,observed_at_ms:time,part_count:1,content_kind:'metadata_only',content_ciphertext_b64:null,event_digest_b64:Buffer.alloc(32,3).toString('base64'),device_signature_der_b64:Buffer.alloc(8,4).toString('base64')};
      const raw=Buffer.from(JSON.stringify(event)),timestamp=String(time/1000);
      return [raw,{'x-zrotext-timestamp':timestamp,'x-zrotext-signature':'v1='+createHmac('sha256',eventKey).update(timestamp).update('.').update(raw).digest('hex')}];
    };
    await run({recipe,key,signed,adapter,calls,holdReadiness:()=>{let release;readinessWait=new Promise(done=>release=done);return ()=>{readinessWait=undefined;release();};},revoke:()=>{active=false;},deny:()=>{permission=false;},denySend:()=>{sendPermission=false;},approve:()=>{approved=true;},disconnect:()=>{disconnect=true;}});
  }finally{
    if(server){server.closeAllConnections();await new Promise(done=>server.close(done));}
    adapter?.close();assert.equal(dirname(resolve(directory)),resolve(tmpdir()));await rm(directory,{recursive:true,force:true});
  }
}

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
    const response=await fetch(url,{method:'POST',headers,body:JSON.stringify({operation:'verified_reply',params:{event_id:id(14),request_id:id(32),verified:true}})});
    assert.equal(response.status,400);
    assert.equal(f.calls.length,0);
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