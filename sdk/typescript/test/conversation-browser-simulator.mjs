// SPDX-License-Identifier: AGPL-3.0-only
// Explicit cross-client harness: the actual browser controller plus synthetic adapters.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { prepareConfirmedFixture, openConfirmedFixture, signFixtureConfirmation } from "./conversation-simulator-send.mjs";
const require = createRequire(import.meta.url);
const { create } = require("../../../web/owner/conversation-core.js");
let input = "";
for await (const chunk of process.stdin) { input += chunk; if (input.length > 100000) throw Error("fixture input bound"); }
const { ready, event, inbound, closeDuringDecrypt = false } = JSON.parse(input);
assert.ok(Number.isInteger(ready.port) && ready.port > 0 && ready.port <= 65535);
async function command(op, values = {}) {
  const response = await fetch(`http://localhost:${ready.port}/fixture`, { method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:ready.token,op,...values}),signal:AbortSignal.timeout(10000) });
  return response.json();
}
let current, selected, packet, signed = 0, delivered = 0;
const adapter = {
  authority: async () => { const value = await command("browser_authority"); assert.equal(value.ok,true); current=value.manifest; selected=value.scope; return value; },
  read: async ({scope,event}) => {
    const value=await command("history",{event});assert.equal(value.ok,true);
    const process=spawnSync("node",[ready.sdkTool],{input:JSON.stringify({op:"open",ready,envelope:value.envelope,device:scope.device,line:scope.line,peer:scope.peer}),encoding:"utf8",timeout:20000,maxBuffer:150000});
    assert.equal(process.status,0,"fixture inbound reader failed");return JSON.parse(process.stdout).opened;
  },
  prepare: async ({scope,body}) => {
    const candidate=await prepareConfirmedFixture({ready,scope,body,current});
    return { confirm: async (guard) => {
      guard(); const signature=await candidate.sign(); signed++;
      packet={envelope:candidate.envelope,confirmation:candidate.confirmation,signature,message:candidate.message};
      // Bind every encrypted byte and every account/peer/session field. Rejections
      // must not consume the legitimate intent or hand content to the fake phone.
      for (const offset of [5,21,37,53,69,85,101,134,packet.confirmation.length]) {
        const proof=Buffer.from(packet.confirmation,"base64");proof[offset%proof.length]^=1;
        const rejected=await command("send",{data:packet.envelope,confirmation:proof.toString("base64"),signature});assert.equal(rejected.ok,false);
      }
      const altered=Buffer.from(packet.envelope,"base64");altered[altered.length-70]^=1;
      assert.equal((await command("send",{data:altered.toString("base64"),confirmation:packet.confirmation,signature})).ok,false);
      for (const offset of [5,21,37,53,69,108,116,124,128,135]) {
        const proof=Buffer.from(packet.confirmation,"base64");proof[offset]^=1;
        const confirmation=proof.toString("base64"), signature=await signFixtureConfirmation(ready,confirmation);
        assert.equal((await command("send",{data:packet.envelope,confirmation,signature})).ok,false,"validly signed wrong scope/TTL refused");
      }
      const wrongPeer=await prepareConfirmedFixture({ready,scope:{...scope,peer:"+13"},body,current});
      assert.equal((await command("send",{data:wrongPeer.envelope,confirmation:wrongPeer.confirmation,signature:await wrongPeer.sign()})).ok,false,"valid envelope outside exact approved conversation refused");
      const wrongBody=Buffer.from(packet.confirmation,"base64");wrongBody[wrongBody.length-1]^=1;
      const wrongBodyPacket={...packet,confirmation:wrongBody.toString("base64"),signature:await signFixtureConfirmation(ready,wrongBody.toString("base64"))};
      await assert.rejects(openConfirmedFixture({ready,scope,current,packet:wrongBodyPacket}),"phone must check actual decrypted body digest");
      const expiring=await prepareConfirmedFixture({ready,scope,body,current,lifetimeMs:1000});
      const expired=await command("send_expiry_wait",{data:expiring.envelope,confirmation:expiring.confirmation,signature:await expiring.sign()});
      assert.equal(expired.ok,true);assert.equal(expired.rejected,true);
      // This final local guard runs immediately before network admission.
      guard();
      const accepted=await command("send",{data:packet.envelope,confirmation:packet.confirmation,signature});
      assert.equal(accepted.ok,true);assert.equal(accepted.created,true);
      const fresh=await command("browser_authority");assert.equal(fresh.ok,true);assert.deepEqual(fresh.scope,scope);
      guard();
      // Distinct fixture phone KEM key decrypts and verifies the exact approved
      // body digest before recording a simulated phone acceptance. No SMS API.
      const decoding=openConfirmedFixture({ready,scope,current,packet});
      if(closeDuringDecrypt) {assert.equal((await command("pause")).ok,true);controller.clear();}
      assert.equal(await decoding,body);
      guard();
      const final=await command("browser_authority");assert.equal(final.ok,true);assert.deepEqual(final.scope,scope);
      guard();assert.ok(BigInt(Date.now())<BigInt(candidate.expiresMs));delivered++;
      const replay=await command("send",{data:packet.envelope,confirmation:packet.confirmation,signature});
      assert.equal(replay.ok,true);assert.equal(replay.created,false);
      return {status:"simulator_accepted"};
    } };
  },
};
const controller=create(adapter);
await controller.authorize();assert.equal(await controller.read(event),inbound);
const reply="Synthetic browser reply Ω\nExact trailing spaces  ";controller.edit(reply);
const review=await controller.prepare();assert.equal(review.body,reply);assert.equal(signed,0);assert.equal(delivered,0);
if(closeDuringDecrypt) {await assert.rejects(controller.confirm());assert.equal(delivered,0);}
else {await controller.confirm();await assert.rejects(controller.confirm());assert.equal(delivered,1);assert.equal(controller.state().messages.at(-1).body,reply);}
assert.equal(signed,1);
controller.clear();assert.equal(controller.state().messages.length,0);assert.equal(controller.state().draft,"");
process.stdout.write(JSON.stringify({signed,verified:delivered,closedDuringDecrypt:closeDuringDecrypt,packet}));
