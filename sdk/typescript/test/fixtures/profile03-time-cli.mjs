// Test-only signed fixtures; never load this module into an application.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fixture, inputFor, keyId, enrollRootPin02, verifyManifest02,
  verifyManifest03From02, verifyAcceptedPayloadProfileElection03, requireCurrentElection03,
  verifyAndOpen, parseOutput, sha } from './profile03-outbound-fixture.mjs';
import { authorizeOutbound03 } from '../../dist/draft03-manifest.js';

const corpus = JSON.parse(readFileSync(new URL('../../../../protocol/v1/vectors/sealed-profile03-outbound-time-policy.json', import.meta.url)));
const b64 = value => Buffer.from(value).toString('base64');
const bytes = value => new Uint8Array(Buffer.from(value, 'base64'));
const encodeRecord = record => Object.fromEntries(Object.entries(record).map(([k,v]) =>
  [k, v instanceof Uint8Array ? b64(v) : typeof v === 'bigint' ? Number(v) : v]));
const decodeRecord = record => Object.fromEntries(Object.entries(record).map(([k,v]) =>
  [k, typeof v === 'number' ? (k === 'profile' || k === 'manifestProfile' ? v : BigInt(v)) : bytes(v)]));

async function produce(scenario, signerPoint) {
  const policy = { ...corpus.defaults, ...scenario }, f = await fixture(policy, signerPoint), input = inputFor(f);
  f.authority.comparedAtMs = BigInt(policy.now_ms);
  const recipients = await Promise.all(f.records.filter(r => r.role <= 3).map(async r => {
    const jwk = await crypto.subtle.exportKey('jwk', r.k.pair.privateKey);
    return {role:r.role,keyId:b64(r.id),point:b64(r.k.point),scalar:b64(Buffer.from(jwk.d,'base64url'))};
  }));
  const signer = f.records.find(r => r.role === 5);
  const signerScalar = signerPoint ? undefined : b64(Buffer.from((await crypto.subtle.exportKey('jwk',signer.k.pair.privateKey)).d,'base64url'));
  return { name:scenario.name, accept:scenario.accept, policy, rootPin:b64(f.pinBytes), fingerprint:b64(f.fingerprint),
    signed02:b64(f.old.bytes),signed03:b64(f.first.bytes),core:b64(f.core),bundle:b64(f.bundle),
    deviceSigningPoint:b64(f.enrollment.point),ownerApprovalPoint:b64(f.approval.point),
    accepted:encodeRecord(f.accepted),authority:encodeRecord(f.authority),message:b64(input.messageId),
    signerPoint:b64(signer.k.point),...(signerScalar ? {signerScalar} : {}),recipients,
    readerScalar:recipients.find(r=>r.role===1).scalar,archiveScalar:recipients.find(r=>r.role===2).scalar,
    observed:policy.observed_ms,now:policy.now_ms,expires:policy.expires_ms,bodyText:input.content };
}

async function consume(input) {
  const f = input.fixture, scenario = corpus.cases.find(c => c.name === f.name);
  assert.ok(scenario?.accept, 'only accepted policy cases can produce envelopes');
  assert.deepEqual(f.policy, {...corpus.defaults,...scenario});
  assert.equal(input.expectedText, f.bodyText);
  const now = BigInt(f.policy.now_ms), observed = BigInt(f.policy.observed_ms), expires = BigInt(f.policy.expires_ms);
  const pin = await enrollRootPin02(bytes(f.rootPin),bytes(f.fingerprint));
  const accepted = decodeRecord(f.accepted), authority = decodeRecord(f.authority);
  const prior = await verifyManifest02(bytes(f.signed02),pin,accepted.acceptedAtMs);
  const manifest = await verifyManifest03From02(bytes(f.signed03),prior,bytes(f.signed02),accepted.acceptedAtMs);
  const proof = await verifyAcceptedPayloadProfileElection03({bundle:bytes(f.bundle),expectedCore:bytes(f.core),acceptedRecord:accepted,
    predecessor02:prior,priorSignedManifest02:bytes(f.signed02),acceptedSignedManifest03:bytes(f.signed03),
    deviceSigningPointAtAcceptance:bytes(f.deviceSigningPoint),ownerApprovalPointAtAcceptance:bytes(f.ownerApprovalPoint)});
  requireCurrentElection03(proof,manifest,authority,now);
  const envelope = bytes(input.envelope), parsed = parseOutput(envelope), protectedView = new DataView(parsed.protectedBytes.buffer);
  assert.equal(protectedView.getBigUint64(136), observed); assert.equal(protectedView.getBigUint64(144), expires);
  assert.deepEqual(parsed.protectedBytes.slice(16,32),bytes(f.message));
  const authorization = authorizeOutbound03(manifest,{accountId:authority.accountId,deviceId:authority.deviceId,lineId:authority.lineId,
    generation:authority.vaultGeneration,version:authority.manifestVersion,digest:authority.manifestDigest,
    signerKeyId:await keyId(0x101,bytes(f.signerPoint)),wraps:parsed.wraps.map(w=>({role:w.role,keyId:w.id}))},now);
  assert.ok(authorization.validFromMs<=observed && observed<=now && now<expires && expires<=authorization.expiresMs &&
    expires<=authority.permissionExpiresAtMs && expires-observed<=900000n);
  assert.deepEqual(parsed.protectedBytes.slice(104,136),await keyId(0x101,bytes(f.signerPoint)));
  const records = await Promise.all(f.recipients.map(async r => {
    const point=bytes(r.point),jwk={kty:'EC',crv:'P-256',x:Buffer.from(point.slice(1,33)).toString('base64url'),
      y:Buffer.from(point.slice(33)).toString('base64url'),d:Buffer.from(bytes(r.scalar)).toString('base64url'),ext:true,key_ops:['sign']};
    return {role:r.role,id:bytes(r.keyId),k:{point,pair:{privateKey:await crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},true,['sign'])}}};
  }));
  records.push({role:4});
  records[4] = {role:5,k:{pair:{publicKey:await crypto.subtle.importKey('raw',bytes(f.signerPoint),{name:'ECDSA',namedCurve:'P-256'},false,['verify'])}}};
  await verifyAndOpen({authority,records},{envelope,unsignedDigest:await sha(parsed.unsigned),envelopeDigest:await sha(envelope)},input.expectedText);
  return {verified:true,name:f.name,recipients:3};
}

const args=process.argv.slice(2);
if (args.length===1 && args[0]==='--consume') {
  let text='';for await(const chunk of process.stdin)text+=chunk;
  process.stdout.write(JSON.stringify(await consume(JSON.parse(text))));
} else {
  let name,point;
  for(let i=0;i<args.length;i+=2) {
    if(args[i]==='--case' && name===undefined)name=args[i+1];
    else if(args[i]==='--signer-point' && point===undefined && /^04[0-9a-f]{128}$/.test(args[i+1]??'')) point=new Uint8Array(Buffer.from(args[i+1],'hex'));
    else throw Error('fixture arguments');
    if(args[i+1]===undefined)throw Error('fixture argument missing');
  }
  const cases=name===undefined?corpus.cases:corpus.cases.filter(c=>c.name===name);
  assert.ok(cases.length>0,'unknown fixture case');
  const output=[];for(const scenario of cases)output.push(await produce(scenario,point));
  process.stdout.write(JSON.stringify({cases:output}));
}
