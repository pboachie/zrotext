// SPDX-License-Identifier: AGPL-3.0-only
// Real HTTPS into a synthetic shared-service policy fixture, not gateway acceptance.
import assert from 'node:assert/strict';
import { createServer, request } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { webcrypto, createHmac } from 'node:crypto';
import { WorkflowRecipe } from '../workflow-runtime.mjs';
import { ReplyEventAdapter } from '../../replies/reply-events.mjs';
import { workflowTools } from '../../typescript/dist/workflow-tools.js';
import { workflowActionDigest } from '../../typescript/dist/workflow-decisions.js';
globalThis.crypto ??= webcrypto;
export const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const descriptor = { account_id:id(1), action_id:id(2), revision:1, line_id:id(3), recipient_id:id(4),
  purpose_id:'00000000-0000-0000-0000-000000000001', content_ref:id(5), content_digest:'ab'.repeat(32),
  content_version:1, not_before:10, expires_at:100, timezone:'UTC', window_id:'immediate-v1',
  routine_id:id(6), authority_generation:1, commitment:'informational' };
const credential = `ztw_${Buffer.alloc(32,7).toString('base64url')}`;

export async function fixture(run) {
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
    const openReplies=()=>new ReplyEventAdapter({path:join(directory,'replies.sqlite'),accountId:id(1),lineId:id(3),webhookSecret:eventKey,cursorSecret:Buffer.alloc(32,2),
      clock:()=>time,authority:()=>({active,accountId:id(1),lineId:id(3),deviceId:id(7),revision:'synthetic_policy',expiresAtMs:time+60000,
        canReadContent:true,readerId:id(10)}),readerId:id(10),reader:async()=>({kind:'decrypted',text:'Synthetic reply'})});
    adapter=openReplies();
    adapter.registerRequest({id:id(11),messageId:id(8),attemptId:id(12),deviceId:id(7),startsAtMs:time-1000,expiresAtMs:time+30000,maxTurns:1});
    const recipe=new WorkflowRecipe({origin:`https://localhost:${server.address().port}`,credential,descriptor,fetchImpl,replyAdapter:adapter,consumerId:id(13)});
    const signed=(eventId=id(14),classification='captured_local')=>{
      const event={v:1,type:'inbound.message',event_id:eventId,delivery_id:id(15),account_id:id(1),device_id:id(7),message_id:id(8),attempt_id:id(12),
        classification,observed_at_ms:time,part_count:1,content_kind:'metadata_only',content_ciphertext_b64:null,event_digest_b64:Buffer.alloc(32,3).toString('base64'),device_signature_der_b64:Buffer.alloc(8,4).toString('base64')};
      const raw=Buffer.from(JSON.stringify(event)),timestamp=String(time/1000);
      return [raw,{'x-zrotext-timestamp':timestamp,'x-zrotext-signature':'v1='+createHmac('sha256',eventKey).update(timestamp).update('.').update(raw).digest('hex')}];
    };
    await run({recipe,key,signed,adapter,calls,
      restartReplies:()=>{
        adapter.close();adapter=openReplies();
        return new WorkflowRecipe({origin:`https://localhost:${server.address().port}`,credential,descriptor,fetchImpl,replyAdapter:adapter,consumerId:id(13)});
      },
      holdReadiness:()=>{let release;readinessWait=new Promise(done=>release=done);return ()=>{readinessWait=undefined;release();};},
      revoke:()=>{active=false;},deny:()=>{permission=false;},denySend:()=>{sendPermission=false;},
      approve:()=>{approved=true;},disconnect:()=>{disconnect=true;},advance:ms=>{time+=ms;}});

  }finally{
    if(server){server.closeAllConnections();await new Promise(done=>server.close(done));}
    adapter?.close();assert.equal(dirname(resolve(directory)),resolve(tmpdir()));await rm(directory,{recursive:true,force:true});
  }
}

