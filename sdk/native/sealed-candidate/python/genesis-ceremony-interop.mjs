// Actual maintained one-shot genesis lifecycle and independent native signature reader.
import {webcrypto} from 'node:crypto';
import {genesisFixture} from '../../../typescript/test/conversation-genesis-fixture.mjs';
import {signFixtureSuccessor02} from '../../../typescript/test/conversation-refresh-fixture.mjs';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {encodeConversationGenesisProposal02} from '../../../typescript/dist/conversation-genesis-proposal.js';
globalThis.crypto??=webcrypto;
const b64=x=>Buffer.from(x).toString('base64'),dec=x=>new Uint8Array(Buffer.from(x,'base64'));
const json=x=>x instanceof Uint8Array?b64(x):typeof x==='bigint'?Number(x):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,json(v)])):x;
if(process.argv[2]==='--consume'){
 let text='';for await(const part of process.stdin)text+=part;const {input,signed}=JSON.parse(text);
 const verifiedManifest=await verifyManifest02(dec(signed),await enrollRootPin02(dec(input.rootPin),dec(input.comparedRootFingerprint)),BigInt(input.nowMs));
 if(verifiedManifest.version!==1n||verifiedManifest.previousDigest.some(x=>x!==0)||verifiedManifest.keys.map(k=>k.role).join(',')!=='1,2,4,6')throw Error('native genesis shape');
 process.stdout.write(JSON.stringify({verified:true,digest:b64(verifiedManifest.digest)}));
}else if(process.argv[2]==='--cases'){
 let text='';for await(const part of process.stdin)text+=part;const cases=JSON.parse(text),results=[];
 for(const c of cases){const f=await genesisFixture(),events=[];
  const change=()=>{if(c.field.endsWith('Live'))f.state.current={...f.state.current,[c.field]:false};else if(c.field==='nowMs')f.state.current={...f.state.current,nowMs:f.input.expiresMs};else if(c.field==='version')f.state.current={...f.state.current,version:1n};else f.state.current={...f.state.current,selection:{...f.state.current.selection,[c.field]:c.field==='generation'?2n:new Uint8Array(c.field==='phoneSigningFingerprint'?32:16).fill(9)}};};
  const flow=f.create({read:async()=>{events.push('current');return f.state.current;},decide:async()=>{events.push('decision');if(c.decline)throw Error('declined');if(c.stage==='decision')change();return c.decisionValue;},
   sign:async review=>{events.push('sign');const sig=c.badSignature?new Uint8Array(64):(await signFixtureSuccessor02(f.f,review.unsigned)).slice(-64);if(c.stage==='sign')change();return sig;},
   install:async signed=>{events.push('install');if(c.installThrows)throw Error('uncertain');if(!c.missing)f.state.current={...f.state.current,version:1n,manifest:c.fork?f.f.predecessor.bytes:signed};if(c.stage==='install')change();}});
  try{await flow.provision();results.push({accepted:true,events});}catch(error){results.push({accepted:false,events});}
 }
 process.stdout.write(JSON.stringify(results));
}else{
 const f=await genesisFixture();
 if(process.argv[2]==='--root-point'){
  const point=new Uint8Array(Buffer.from(process.argv[3],'hex'));await crypto.subtle.importKey('raw',point,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  f.input.rootPin.set(point,29);f.input.comparedRootFingerprint=new Uint8Array(await crypto.subtle.digest('SHA-256',Buffer.concat([Buffer.from('ZTSE/root-pin/v2\0'),Buffer.from(f.input.rootPin)])));
 }
 const review=await encodeConversationGenesisProposal02(f.input);
 process.stdout.write(JSON.stringify({input:json(f.input),review:json(review),...(process.argv[2]?{}:{scalar:b64(Uint8Array.from({length:32},(_,n)=>n===31?1:0))})}));
}
