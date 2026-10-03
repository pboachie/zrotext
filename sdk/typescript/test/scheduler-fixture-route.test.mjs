// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { fixtureRequest } from '../../scheduler/service-fixture-route.mjs';

test('controlled scheduler proxy keeps the reserved loopback destination and exact tool route',()=>{
  for(const method of ['GET','POST'])assert.deepEqual(fixtureRequest('http://127.0.0.1:12345/',method,'/v1/workflow/tools'),
    {hostname:'127.0.0.1',port:12345,method,path:'/v1/workflow/tools'});
});

test('an absolute incoming request cannot reach an alternate loopback server',async()=>{
  let selectedHits=0,alternateHits=0;
  const selected=createServer((req,res)=>{selectedHits++;res.end('selected');});
  const alternate=createServer((req,res)=>{alternateHits++;res.end('alternate');});
  const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  await listen(selected);await listen(alternate);
  const upstream=`http://127.0.0.1:${selected.address().port}/`;
  const proxy=createServer((incoming,outgoing)=>{
    let destination;
    try{destination=fixtureRequest(upstream,incoming.method,incoming.url);}
    catch{outgoing.writeHead(400);outgoing.end();return;}
    const forwarded=request(destination,response=>{outgoing.writeHead(response.statusCode);response.pipe(outgoing);});
    forwarded.on('error',()=>outgoing.destroy());incoming.pipe(forwarded);
  });
  await listen(proxy);
  const send=path=>new Promise((resolve,reject)=>{
    const sent=request({hostname:'127.0.0.1',port:proxy.address().port,path,method:'POST'},response=>{
      response.resume();response.on('end',()=>resolve(response.statusCode));
    });sent.on('error',reject);sent.end();
  });
  try{
    assert.equal(await send('/v1/workflow/tools'),200);
    assert.equal(await send(`http://127.0.0.1:${alternate.address().port}/v1/workflow/tools`),400);
    assert.equal(selectedHits,1);assert.equal(alternateHits,0);
  }finally{
    await Promise.all([proxy,selected,alternate].map(server=>new Promise(resolve=>{
      server.closeAllConnections();server.close(resolve);
    })));
  }
});
test('controlled scheduler proxy refuses foreign URLs and alternate paths before forwarding',()=>{
  for(const target of ['https://foreign.example/v1/workflow/tools','//foreign.example/v1/workflow/tools',
    '/v1/workflow/tools?destination=foreign','/v1/workflow/tools#fragment','/v1/workflow/../tools','/other'])
    assert.throws(()=>fixtureRequest('http://127.0.0.1:12345/','POST',target),/refused/);
  for(const upstream of ['http://foreign.example:12345/','https://127.0.0.1:12345/',
    'http://127.0.0.1:12345/?x=1','http://127.0.0.1:12345/#fragment','http://127.0.0.1/'])
    assert.throws(()=>fixtureRequest(upstream,'POST','/v1/workflow/tools'),/refused/);
  assert.throws(()=>fixtureRequest('http://127.0.0.1:12345/','DELETE','/v1/workflow/tools'),/refused/);
});
