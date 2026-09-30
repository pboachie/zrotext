// SPDX-License-Identifier: AGPL-3.0-only
// Standalone fixture verifier for the dormant Room adapter; no production credentials.
import assert from "node:assert/strict";
import { openConfirmedFixture } from "./conversation-simulator-send.mjs";
let input="";
for await(const chunk of process.stdin){input+=chunk;if(input.length>200000)throw Error("fixture input bound");}
const {ready,evidencePacket,expectedScope,closeAfterDecrypt=false}=JSON.parse(input);
assert.ok(Number.isInteger(ready.port)&&ready.port>0&&ready.port<=65535);
async function command(op){
 const response=await fetch(`http://localhost:${ready.port}/fixture`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:ready.token,op}),signal:AbortSignal.timeout(10000)});
 return response.json();
}
const authority=await command("browser_authority");assert.equal(authority.ok,true);
for(const [field,value] of Object.entries(expectedScope))assert.equal(authority.scope[field],value);
const body=await openConfirmedFixture({ready,scope:authority.scope,current:authority.manifest,packet:evidencePacket});
if(closeAfterDecrypt)assert.equal((await command("pause")).ok,true);
const final=await command("browser_authority");assert.equal(final.ok,true);
assert.deepEqual(final.scope,authority.scope);assert.equal(final.manifest,authority.manifest);
const proof=Buffer.from(evidencePacket.confirmation,"base64"),deadline=proof.readBigUInt64BE(125);
assert.ok(BigInt(Date.now())<deadline);
process.stdout.write(JSON.stringify({body,message:evidencePacket.message,deadline:deadline.toString(),scope:final.scope}));
