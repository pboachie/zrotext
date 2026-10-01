// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {SealedLifecycleClient,SealedLifecycleError} from '../dist/sealed-lifecycle-client.js';
const id='00000000-0000-0000-0000-000000000001';
const row={message_id:id,device_id:id,state:'queued',state_version:1,created_at_ms:1,updated_at_ms:1,expires_at_ms:2};
const options={baseUrl:'https://sealed.example.invalid',apiToken:['synthetic','credential'].join('-')};
test('lifecycle sends metadata-only canonical requests and preserves uncertainty',async()=>{
  const calls=[];
  const client=new SealedLifecycleClient({...options,fetchImpl:async(url,init)=>{calls.push([url,init]);return Response.json({...row,state:init.method==='POST'?'cancelled':'unknown'});}});
  assert.equal((await client.status(id)).state,'unknown');
  assert.equal((await client.cancel(id)).state,'cancelled');
  assert.equal(calls[1][0],`${options.baseUrl}/v1/sealed/messages/${id}/cancel`);
  for(const [,init]of calls){assert.equal(init.body,undefined);assert.equal(init.headers['content-type'],undefined);assert.equal(init.redirect,'error');}
});
test('grant refusal is terminal and cancellation never retries',async()=>{
  let count=0;
  const client=new SealedLifecycleClient({...options,fetchImpl:async()=>{count++;return Response.json({code:'cancellation_conflict'},{status:409});}});
  await assert.rejects(client.cancel(id),error=>error instanceof SealedLifecycleError&&error.code==='cancellation_conflict');
  assert.equal(count,1);
});
test('lifecycle refuses extra content, identity mismatch, inflated pages and false cancellation',async()=>{
  for(const body of [{...row,plaintext:'untrusted'}, {...row,message_id:'00000000-0000-0000-0000-000000000002'}, {...row,state:'submitted'}]){
    const client=new SealedLifecycleClient({...options,fetchImpl:async()=>Response.json(body)});
    await assert.rejects(client.cancel(id));
  }
  const client=new SealedLifecycleClient({...options,fetchImpl:async()=>Response.json({messages:Array(21).fill(row),next_cursor:null})});
  await assert.rejects(client.list());
  await assert.rejects(client.status('../messages'));
});
test('bound page cursor and UUID validation prevent path or token routing',async()=>{
  const client=new SealedLifecycleClient({...options,fetchImpl:async(url)=>{assert.equal(url,`${options.baseUrl}/v1/sealed/messages?cursor=${id}`);return Response.json({messages:[row],next_cursor:null});}});
  assert.equal((await client.list(id)).messages.length,1);
  assert.throws(()=>new SealedLifecycleClient({...options,baseUrl:'https://sealed.example.invalid/path'}));
});
test('response stream is cancelled at its byte cap before unbounded allocation',async()=>{
  let cancelled=false;
  const stream=new ReadableStream({pull(controller){controller.enqueue(new Uint8Array(9000));},cancel(){cancelled=true;}});
  const client=new SealedLifecycleClient({...options,fetchImpl:async()=>new Response(stream)});
  await assert.rejects(client.status(id),/Oversized/);
  assert.equal(cancelled,true);
});
