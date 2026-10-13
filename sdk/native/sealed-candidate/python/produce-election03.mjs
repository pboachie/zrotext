// Actual maintained TS election verifier/composer; synthetic keys and authority.
import { createECDH, webcrypto } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import { canonicalSignature02, enrollRootPin02, verifyManifest02 } from '../../../typescript/dist/draft02-manifest.js';
import { verifyManifest03From02 } from '../../../typescript/dist/draft03-manifest.js';
import { verifyAcceptedPayloadProfileElection03, requireCurrentElection03 } from '../../../typescript/dist/payload-profile-election03.js';
import { composeSealedOutboundEnvelope03 } from '../../../typescript/dist/sealed-envelope03.js';
import { keyId } from '../../../typescript/dist/draft01.js';
globalThis.crypto ??= webcrypto;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const bytes = (n, size) => new Uint8Array(size).fill(n);
const join = (...parts) => new Uint8Array(Buffer.concat(parts.map(p => Buffer.from(p))));
const text = s => new TextEncoder().encode(s);
const integer = (n, size) => { const b = Buffer.alloc(size); size === 8 ? b.writeBigUInt64BE(BigInt(n)) : b.writeUIntBE(n, 0, size); return b; };
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const b64 = b => Buffer.from(b).toString('base64');
const frame = (domain, b) => join(text(domain + '\0'), integer(b.length, 4), b);
async function signing(n) {
  const scalar = Buffer.alloc(32); scalar[31] = n;
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(scalar);
  const point = new Uint8Array(ecdh.getPublicKey());
  const privateKey = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256',
    x: Buffer.from(point.slice(1,33)).toString('base64url'), y: Buffer.from(point.slice(33)).toString('base64url'),
    d: scalar.toString('base64url'), ext:true, key_ops:['sign'] }, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  return { point, privateKey };
}
async function sign(key, domain, payload) {
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'}, key.privateKey, frame(domain,payload))));
}
async function kem(n) {
  const pair = await suite.kem.deriveKeyPair(bytes(n,32));
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { pair, point, id: await keyId(16,point) };
}
const root=await signing(7), origin=await signing(6), outbound=await signing(5), enrollment=await signing(8), approval=await signing(9);
const archive=await kem(34);
let device;
if (process.argv[2] === '--recipient-point') {
  const hex=process.argv[3];
  if (!/^04[0-9a-f]{128}$/.test(hex ?? '') || process.argv.length!==4) throw Error('public recipient point');
  const point=new Uint8Array(Buffer.from(hex,'hex'));
  await suite.kem.deserializePublicKey(point); device={point,id:await keyId(16,point)};
} else {
  if (process.argv.length!==2) throw Error('unsupported fixture arguments');
  device=await kem(17);
}
const accountId=bytes(161,16),deviceId=bytes(209,16),lineId=bytes(177,16),messageId=bytes(49,16);
const zero16=bytes(0,16),zero32=bytes(0,32),acceptedAt=10000n,present=30000n;
const rootPin=join(text('ZTRP'),[2],accountId,integer(1,8),root.point);
const fingerprint=await sha(join(text('ZTSE/root-pin/v2\0'),rootPin));
const pin=await enrollRootPin02(rootPin,fingerprint);
const keys=[
  [1,device.id,device.point,deviceId,lineId,4], [2,archive.id,archive.point,zero16,zero16,12],
  [4,await keyId(257,origin.point),origin.point,deviceId,lineId,2],
  [5,await keyId(257,outbound.point),outbound.point,zero16,lineId,1],
  [6,await keyId(257,root.point),root.point,zero16,zero16,0],
];
async function manifest(profile,version,previous) {
  const unsigned=join(text('ZTMA'),[profile],...(profile===3?[[3,2]]:[]),accountId,integer(1,8),integer(version,8),
    integer(9000,8),integer(100000,8),previous,root.point,[keys.length],...keys.map(([role,id,point,device,line,scope])=>
      join([role],id,point,device,line,integer(scope,2),integer(9000,8),integer(100000,8),[1])));
  return {bytes:join(unsigned,await sign(root,`ZTSE/manifest/v${profile}`,unsigned)),digest:await sha(unsigned)};
}
const old=await manifest(2,1,zero32),first=await manifest(3,2,old.digest);
const prior=await verifyManifest02(old.bytes,pin,acceptedAt);
const currentManifest=await verifyManifest03From02(first.bytes,prior,old.bytes,acceptedAt);
const oldBinding=bytes(98,16),newBinding=bytes(99,16);
const core=join(text('ZTPE'),[3,1,2,3],accountId,deviceId,lineId,bytes(97,16),oldBinding,integer(4,8),integer(7,8),bytes(1,32),
  fingerprint,integer(1,8),integer(1,8),old.digest,integer(2,8),first.digest,device.id,
  await keyId(257,enrollment.point),await keyId(257,approval.point),bytes(2,32),integer(9000,8),integer(20000,8),
  bytes(3,32),bytes(4,32),bytes(5,32),bytes(0,4));
const deviceSignature=await sign(enrollment,'ZTSE/line/payload-profile/device/v1',core);
const bundle=join(core,deviceSignature,await sign(approval,'ZTSE/line/payload-profile/owner/v1',join(core,await sha(deviceSignature))));
const accepted={accountId,deviceId,lineId,rootFingerprint:fingerprint,vaultGeneration:1n,oldBindingId:oldBinding,
  oldBindingGeneration:4n,newBindingGeneration:7n,oldBindingProofDigest:bytes(1,32),newBindingId:newBinding,
  selectedReaderKeyId:device.id,priorManifestVersion:1n,priorManifestDigest:old.digest,priorSignedManifestSha256:await sha(old.bytes),
  acceptedManifestVersion:2n,acceptedManifestDigest:first.digest,acceptedSignedManifestSha256:await sha(first.bytes),
  electionCoreSha256:await sha(core),electionCommitment:await sha(frame('ZTSE/line/payload-profile/commitment/v1',core)),
  electionBundleSha256:await sha(bundle),acceptedAtMs:acceptedAt};
const authority={profile:3,manifestProfile:3,accountId,deviceId,lineId,bindingId:newBinding,bindingGeneration:7n,
  selectedReaderKeyId:device.id,rootFingerprint:fingerprint,vaultGeneration:1n,manifestVersion:2n,manifestDigest:first.digest,
  electionCommitment:accepted.electionCommitment,electionBundleSha256:accepted.electionBundleSha256,comparedAtMs:present,permissionExpiresAtMs:60000n};
const proof=await verifyAcceptedPayloadProfileElection03({bundle,expectedCore:core,acceptedRecord:accepted,predecessor02:prior,
  priorSignedManifest02:old.bytes,acceptedSignedManifest03:first.bytes,deviceSigningPointAtAcceptance:enrollment.point,
  ownerApprovalPointAtAcceptance:approval.point});
requireCurrentElection03(proof,currentManifest,authority,present);
const bodyText='Native elected profile03 ✓';
const envelope=await composeSealedOutboundEnvelope03({manifest:currentManifest,acceptedElection:proof,currentAuthority:authority,nowMs:present,
  messageId,observedMs:present,expiresMs:40000n,peer:text('+12'),content:bodyText,signerPrivateKey:outbound.privateKey,
  signerPublicPoint:outbound.point,recipients:[{role:1,keyId:device.id},{role:2,keyId:archive.id}]});
const record=obj=>Object.fromEntries(Object.entries(obj).map(([k,v])=>[k,v instanceof Uint8Array?b64(v):typeof v==='bigint'?Number(v):v]));
process.stdout.write(JSON.stringify({rootPin:b64(rootPin),fingerprint:b64(fingerprint),signed02:b64(old.bytes),signed03:b64(first.bytes),
  core:b64(core),bundle:b64(bundle),deviceSigningPoint:b64(enrollment.point),ownerApprovalPoint:b64(approval.point),
  accepted:record(accepted),authority:record(authority),envelope:b64(envelope.envelope),message:b64(messageId),bodyText,
  ...(device.pair?{readerScalar:b64(new Uint8Array(await suite.kem.serializePrivateKey(device.pair.privateKey)))}:{})}));
