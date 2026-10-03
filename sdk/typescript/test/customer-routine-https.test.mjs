// SPDX-License-Identifier: AGPL-3.0-only
// Certificate-validated HTTPS fixture; service authority is synthetic here.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer, request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CustomerRoutineService } from '../../assistant/routine-service.mjs';
const id=n=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const input='ztw_'+Buffer.alloc(32,7).toString('base64url'),output='ztw_'+Buffer.alloc(32,8).toString('base64url');
const call={call_id:id(5),assigned_output_context_id:id(5),execute_once:false,policy_id:id(2),phase:'published',output_context_id:id(5),output_revision:1,action_id:null,binding_digest:null};
test('actual HTTPS dual credential resume and owner publication never delegate owner cookies to routine calls',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-customer-tls-'));let server;const sockets=new Set();
  try {
    // The test runner must provide OpenSSL through PATH; missing tooling fails
    // this real TLS test rather than substituting an unverified transport.
    const run=args=>execFileSync('openssl',args,{cwd:directory,timeout:15000,stdio:'pipe'});
    run(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Synthetic Routine CA','-keyout','ca.key','-out','ca.pem']);
    run(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout','leaf.key','-out','leaf.csr']);
    await writeFile(join(directory,'leaf.ext'),'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    run(['x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','leaf.ext','-out','leaf.pem']);
    const captured=[];
    server=createServer({key:await readFile(join(directory,'leaf.key')),cert:await readFile(join(directory,'leaf.pem'))},async(req,res)=>{
      const chunks=[];for await(const b of req)chunks.push(b);
      captured.push({path:req.url,headers:req.headers,body:Buffer.concat(chunks)});
      // Real successful credential issuance belongs to the Rust/PG fixture;
      // this synthetic policy only proves the exact route and closed refusal.
      res.writeHead(req.url==='/v1/auth/workflow-grants'?403:200,{'content-type':'application/json','cache-control':'no-store'});
      res.end(JSON.stringify(req.url==='/v1/auth/workflow-grants'?{error:{code:'forbidden'}}:req.url==='/v1/owner/workflow/contexts'?{revision:1}:{kind:'call',result:call}));
    });
    server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
    await new Promise(resolve=>server.listen(0,'localhost',resolve));const origin=`https://localhost:${server.address().port}`;
    const ca=await readFile(join(directory,'ca.pem'));
    const fetchImpl=(url,init)=>new Promise((resolve,reject)=>{
      const r=request(url,{method:init.method,headers:init.headers,ca,signal:init.signal},res=>{
        const chunks=[];res.on('data',b=>chunks.push(b));res.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:res.statusCode,headers:res.headers})));res.on('error',reject);
      });r.on('error',reject);r.end(init.body);
    });
    const service=new CustomerRoutineService({origin,inputCredential:input,outputCredential:output,fetchImpl,owner:{cookie:'synthetic-owner-session',csrf:'synthetic-csrf'}});
    assert.equal((await service.resume(id(5))).call_id,id(5));
    assert.equal(captured[0].headers.authorization,`Bearer ${output}`);assert.equal(captured[0].headers['x-zrotext-routine-input'],input);assert.equal(captured[0].headers.cookie,undefined);
    await assert.rejects(service.admit({request_id:id(6),policy_id:id(2),context_id:id(3),input_revision:1,input_source_digest:'ab'.repeat(32),direction:'owner_declared'}),e=>e.code==='response_unknown'&&e.state==='unknown');
    assert.equal(captured.length,2);
    await service.publishArchive(id(6),new Uint8Array(308).fill(7));
    assert.equal(captured[2].headers.authorization,undefined);assert.equal(captured[2].headers.cookie,'synthetic-owner-session');assert.equal(captured[2].headers['x-zrotext-csrf'],'synthetic-csrf');
    assert.equal(captured[2].headers['x-zrotext-context-revision'],'0');assert.equal(captured[2].body.length,308);
    await assert.rejects(service.issueOutputGrant({current_password:'example',code:'synthetic factor',connector_id:id(7),context_id:id(5),contact_id:id(8),purpose:'transactional',permissions:['context_content','propose'],signer_key_id:null,expires_at_ms:100000,content_envelope_base64url:'YWJj'}),e=>e.code==='forbidden'&&e.state==='refused');
    assert.equal(captured[3].path,'/v1/auth/workflow-grants');assert.equal(captured[3].headers.authorization,undefined);assert.equal(captured[3].headers['x-zrotext-csrf'],'synthetic-csrf');
    const untrusted=new CustomerRoutineService({origin,inputCredential:input,outputCredential:output});
    await assert.rejects(untrusted.resume(id(5)),e=>e.code==='response_unknown'&&e.state==='unknown');assert.equal(captured.length,4);
  }finally{for(const socket of sockets)socket.destroy();if(server)await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});}
});
