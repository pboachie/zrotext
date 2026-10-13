import assert from 'node:assert/strict';
import {test} from 'node:test';
import {execFileSync,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {key,enrollRootPin02,verifyManifest02,verifyManifest03From02,verifyAcceptedPayloadProfileElection03,
  composeSealedOutboundEnvelope03} from './fixtures/profile03-outbound-fixture.mjs';

const cli=fileURLToPath(new URL('./fixtures/profile03-time-cli.mjs',import.meta.url));
const bytes=b=>new Uint8Array(Buffer.from(b,'base64'));
const decode=r=>Object.fromEntries(Object.entries(r).map(([k,v])=>[k,typeof v==='number'?
  (k==='profile'||k==='manifestProfile'?v:BigInt(v)):bytes(v)]));
const call=(args,input)=>JSON.parse(execFileSync(process.execPath,[cli,...args],{encoding:'utf8',input:input&&JSON.stringify(input),maxBuffer:4*1024*1024}));

test('shared CLI signs all policy cases around an injected signer and independently opens accepted envelopes',async()=>{
  const signer=await key(),fixtures=call(['--signer-point',Buffer.from(signer.point).toString('hex')]).cases;
  assert.equal(fixtures.length,14);assert.equal(new Set(fixtures.map(f=>f.name)).size,14);
  let acceptedCount=0;
  for(const f of fixtures){
    assert.equal(Object.hasOwn(f,'signerScalar'),false);
    const accepted=decode(f.accepted),authority=decode(f.authority);
    const pin=await enrollRootPin02(bytes(f.rootPin),bytes(f.fingerprint));
    const prior=await verifyManifest02(bytes(f.signed02),pin,accepted.acceptedAtMs);
    const manifest=await verifyManifest03From02(bytes(f.signed03),prior,bytes(f.signed02),accepted.acceptedAtMs);
    const proof=await verifyAcceptedPayloadProfileElection03({bundle:bytes(f.bundle),expectedCore:bytes(f.core),acceptedRecord:accepted,
      predecessor02:prior,priorSignedManifest02:bytes(f.signed02),acceptedSignedManifest03:bytes(f.signed03),
      deviceSigningPointAtAcceptance:bytes(f.deviceSigningPoint),ownerApprovalPointAtAcceptance:bytes(f.ownerApprovalPoint)});
    const input={manifest,acceptedElection:proof,currentAuthority:authority,nowMs:BigInt(f.now),observedMs:BigInt(f.observed),
      expiresMs:BigInt(f.expires),messageId:bytes(f.message),peer:new TextEncoder().encode('+12'),content:f.bodyText,
      signerPrivateKey:signer.pair.privateKey,signerPublicPoint:signer.point,recipients:f.recipients.map(r=>({role:r.role,keyId:bytes(r.keyId)}))};
    if(!f.accept){await assert.rejects(composeSealedOutboundEnvelope03(input));continue;}
    const result=await composeSealedOutboundEnvelope03(input),request={fixture:f,envelope:Buffer.from(result.envelope).toString('base64'),expectedText:f.bodyText};
    assert.deepEqual(call(['--consume'],request),{verified:true,name:f.name,recipients:3});acceptedCount++;
    if(acceptedCount===1){
      const corrupt=structuredClone(request),signature=bytes(corrupt.fixture.bundle);signature[signature.length-1]^=1;
      corrupt.fixture.bundle=Buffer.from(signature).toString('base64');
      assert.notEqual(spawnSync(process.execPath,[cli,'--consume'],{input:JSON.stringify(corrupt),encoding:'utf8'}).status,0);
      const changed=structuredClone(request);changed.expectedText+=' changed';
      assert.notEqual(spawnSync(process.execPath,[cli,'--consume'],{input:JSON.stringify(changed),encoding:'utf8'}).status,0);
    }
  }
  assert.equal(acceptedCount,6);
});

test('shared CLI supports synthetic software fixtures and refuses unsupported selectors',()=>{
  const f=call(['--case','current-active-lifetime']).cases;
  assert.equal(f.length,1);assert.equal(bytes(f[0].signerScalar).length,32);
  for(const args of [['--case','missing'],['--signer-point','00'],['--case'],['--unknown','value']])
    assert.notEqual(spawnSync(process.execPath,[cli,...args],{encoding:'utf8'}).status,0);
});
