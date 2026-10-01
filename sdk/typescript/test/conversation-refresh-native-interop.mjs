// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic public SDK file -> existing reduced-token native console -> SDK verification.
// This supplemental Windows test never invokes the production CLI with override flags.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {refreshFixture} from './conversation-refresh-fixture.mjs';
import {encodeConversationRefreshProposal02} from '../dist/conversation-refresh-proposal.js';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
const executable=process.env.ZT_CONVERSATION_REFRESH_NATIVE_TEST;
if(!executable)throw Error('An explicitly selected fixture test executable is required');
{
 const now=BigInt(Date.now()),input=await refreshFixture(now),proposal=await encodeConversationRefreshProposal02(input);
 const run=spawnSync(executable,['--exact','windows::conversation_refresh::native_tests::native_console_refresh_uses_existing_bundle_once','--nocapture','--test-threads=1'],{encoding:'utf8',timeout:120000,env:{...process.env,ZT_REFRESH_INTEROP_PROPOSAL_HEX:Buffer.from(proposal).toString("hex"),ZT_REFRESH_INTEROP_NOW:String(now)}});
 if(run.error)throw run.error;
 process.stdout.write((run.stdout??'').replace(/ZT_REFRESH_INTEROP_SIGNED=[0-9a-f]+/g,'[synthetic public signed successor received]'));process.stderr.write(run.stderr??'');assert.equal(run.status,0,'Reduced-token native fixture ceremony failed');
 const markers=[...run.stdout.matchAll(/(?:^|\.\.\. )ZT_REFRESH_INTEROP_SIGNED=([0-9a-f]+)\r?$/gm)];assert.equal(markers.length,1,'Exactly one public signed fixture result required');const encoded=markers[0][1];assert(encoded.length<=40960&&encoded.length%2===0,'Canonical bounded public signed fixture result required');
 const signed=new Uint8Array(Buffer.from(encoded,'hex'));assert.deepEqual(signed.subarray(0,-64),input.review.unsigned);
 const manifest=await verifyManifest02(signed,verifiedManifestTrust02(input.predecessor,now),BigInt(Date.now()));
 assert.equal(manifest.version,input.predecessor.version+1n);assert.equal(manifest.keys.length,input.predecessor.keys.length+1);
 for(const old of input.predecessor.keys)assert(manifest.keys.some(k=>k.role===old.role&&Buffer.from(k.keyId).equals(Buffer.from(old.keyId))));
 console.log('PASS actual SDK ZTCF01 -> reduced-token offline CLI fixture -> verified exact successor; archive unchanged');
}
