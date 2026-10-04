// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';import {fileURLToPath} from 'node:url';
const script=fileURLToPath(new URL('../../mcp/secret-broker.mjs',import.meta.url));
function child(input){return new Promise((resolve,reject)=>{const process=spawn(globalThis.process.execPath,[script],{env:{},stdio:['pipe','pipe','pipe']});let output='',errors='';
 const timer=setTimeout(()=>{process.kill('SIGKILL');reject(Error('broker test timeout'));},10000);
 process.stdout.on('data',v=>output+=v);process.stderr.on('data',v=>errors+=v);process.on('error',reject);
 process.on('close',code=>{clearTimeout(timer);resolve({code,output,errors});});process.stdin.end(input);});}
test('private startup credential is consumed before actual MCP initialization and never echoed',async()=>{
 const generatedCredential='ztw_'+Buffer.alloc(32,13).toString('base64url');
 const start=JSON.stringify({v:1,origin:'https://gateway.example',credential:generatedCredential});
 const request=JSON.stringify({jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'synthetic-setup',version:'1'}}});
 const result=await child(start+'\n'+request+'\n');assert.equal(result.code,0);const reply=JSON.parse(result.output.trim());assert.equal(reply.id,1);
 assert.ok(reply.result);assert.equal(result.output.includes(generatedCredential),false);assert.equal(result.errors.includes(generatedCredential),false);
});
test('missing malformed or oversized private bootstrap refuses without processing model bytes',async()=>{
 for(const input of ['{}\n','a'.repeat(1025)+'\n',JSON.stringify({v:1,origin:'http://gateway.example',credential:'synthetic-private-canary'})+'\n']){
  const result=await child(input);assert.equal(result.code,2);assert.equal(result.output,'');assert.equal(result.errors,'Workflow broker refused.\n');
 }
});
