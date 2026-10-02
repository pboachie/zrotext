// SPDX-License-Identifier: AGPL-3.0-only
// Private stdin fixture supplied by the actual Rust/router/PostgreSQL test.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, request as tlsRequest } from 'node:https';
import { request as plainRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WorkflowToolClient } from '../typescript/dist/workflow-tool-client.js';
import { ScheduledRunner } from './runner.mjs';
let input='';for await(const chunk of process.stdin){input+=chunk;if(Buffer.byteLength(input)>65536)throw new Error('fixture too large');}
const fixture=JSON.parse(input),directory=await mkdtemp(join(tmpdir(),'zrotext-scheduler-tls-'));
let server,runner;
try{
  const upstream=new URL(fixture.upstream);
  assert.equal(upstream.protocol,'http:');assert.equal(upstream.hostname,'127.0.0.1');assert.equal(upstream.pathname,'/');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout','key.pem','-out','cert.pem'],{cwd:directory,stdio:'pipe',timeout:15000});
  const cert=await readFile(join(directory,'cert.pem'));
  server=createServer({cert,key:await readFile(join(directory,'key.pem'))},async(req,res)=>{
    let body='';for await(const chunk of req)body+=chunk;
    const sent=body?JSON.parse(body).method==='workflow.action.send':false;
    const forwarded=plainRequest(new URL(req.url,upstream),{method:req.method,headers:req.headers},reply=>{
      if(sent&&fixture.drop_send){reply.resume();reply.on('end',()=>res.destroy());}
      else{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);}
    });forwarded.on('error',()=>res.destroy());forwarded.end(body);
  });
  await new Promise(resolve=>server.listen(0,'localhost',resolve));
  const fetchImpl=(url,options)=>new Promise((resolve,reject)=>{
    const req=tlsRequest(url,{method:options.method,headers:options.headers,ca:cert,signal:options.signal},res=>{
      const chunks=[];res.on('data',chunk=>chunks.push(chunk));res.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));
    });req.on('error',reject);req.end(options.body);
  });
  const client=new WorkflowToolClient({origin:`https://localhost:${server.address().port}`,credential:fixture.credential,fetchImpl});
  runner=new ScheduledRunner({client,filename:fixture.journal,enabled:true});
  let result;
  if(fixture.phase==='enqueue')result=await runner.enqueue(fixture.params);
  else if(fixture.phase==='cancel')result=await runner.cancel(fixture.action_id,fixture.request_id);
  else if(fixture.drop_send){await assert.rejects(runner.advance(fixture.action_id),error=>error.state==='unknown');result=runner.inspect(fixture.action_id);assert.equal(result.state,'unknown');}
  else result=await runner.advance(fixture.action_id);
  assert.equal(result.state,fixture.expected_state);
  if(fixture.expected_message)assert.equal(result.result.message_id,fixture.expected_message);
  process.stdout.write(JSON.stringify(result));
}catch{process.stderr.write('scheduler service fixture refused\n');process.exitCode=1;}
finally{
  runner?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  await rm(directory,{recursive:true,force:true});
}
