// SPDX-License-Identifier: AGPL-3.0-only
// Invoked by the ignored Rust integration test against its disposable router.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, request as tlsRequest } from 'node:https';
import { request as plainRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { WorkflowRecipe } from './workflow-runtime.mjs';

let input=''; for await (const part of process.stdin) input+=part;
const fixture=JSON.parse(input);
const directory=await mkdtemp(join(tmpdir(),'zrotext-recipe-service-'));
let server;
try {
  const openssl=process.platform==='win32'?join('C:','Program Files','Git','usr','bin','openssl.exe'):'/usr/bin/openssl';
  execFileSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout','key.pem','-out','cert.pem'],{cwd:directory,stdio:'pipe',timeout:15000});
  const cert=await readFile(join(directory,'cert.pem'));
  server=createServer({cert,key:await readFile(join(directory,'key.pem'))},(req,res)=>{
    const upstream=plainRequest(fixture.upstream+req.url,{method:req.method,headers:req.headers},reply=>{
      res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);
    });
    upstream.on('error',()=>{res.destroy();});req.pipe(upstream);
  });
  await new Promise(resolve=>server.listen(0,'localhost',resolve));
  const fetchImpl=(url,options)=>new Promise((resolve,reject)=>{
    const req=tlsRequest(url,{method:options.method,headers:options.headers,ca:cert,signal:options.signal},res=>{
      const chunks=[];res.on('data',part=>chunks.push(part));res.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
    });req.on('error',reject);req.end(options.body);
  });
  const recipe=new WorkflowRecipe({origin:`https://localhost:${server.address().port}`,credential:fixture.credential,descriptor:fixture.descriptor,fetchImpl});
  assert.equal((await recipe.setup()).installed_state,'disabled');
  await recipe.enable();
  let result;
  if(fixture.phase==='propose'){
    const preview=await recipe.preview(randomUUID());assert.equal(preview.approval,false);
    result=await recipe.call({operation:'owner_proposal',request_id:fixture.request_id});
    assert.equal(result.result.phase,'proposed');
  }else{
    result=await recipe.prepare({request_id:fixture.request_id,key:fixture.key});
    assert.equal(result.result.state,fixture.expected_state);
    if(result.result.state==='prepared')assert.equal(result.result.message_id,fixture.message_id);
    assert.deepEqual(await recipe.prepare({request_id:fixture.request_id,key:fixture.key}),result);
    const status=await recipe.call({operation:'status',request_id:randomUUID()});assert.equal(status.result.key.action_id,fixture.key.action_id);
  }
  process.stdout.write(JSON.stringify(result));
}finally{
  if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  await rm(directory,{recursive:true,force:true});
}

