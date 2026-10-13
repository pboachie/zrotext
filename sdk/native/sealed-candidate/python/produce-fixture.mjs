// Synthetic independent TypeScript producer. No service or device interaction.
import { createECDH, webcrypto } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import { canonicalSignature02, enrollRootPin02, verifyManifest02 } from '../../../typescript/dist/draft02-manifest.js';
import { prepareInboundEnvelope02, prepareOutboundEnvelope02 } from '../../../typescript/dist/draft02-envelope-prep.js';
import { keyId } from '../../../typescript/dist/draft01.js';
globalThis.crypto ??= webcrypto;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const bytes = (n, size) => new Uint8Array(size).fill(n);
const join = (...parts) => new Uint8Array(Buffer.concat(parts.map(p => Buffer.from(p))));
const text = s => new TextEncoder().encode(s);
const integer = (n, size) => { const b = Buffer.alloc(size); size === 8 ? b.writeBigUInt64BE(BigInt(n)) : b.writeUIntBE(n, 0, size); return b; };
const sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const b64 = b => Buffer.from(b).toString('base64');
async function signing(n) {
  const scalar = Buffer.alloc(32); scalar[31] = n;
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(scalar);
  const point = new Uint8Array(ecdh.getPublicKey());
  const privateKey = await crypto.subtle.importKey('jwk', { kty:'EC', crv:'P-256',
    x: Buffer.from(point.slice(1,33)).toString('base64url'), y: Buffer.from(point.slice(33)).toString('base64url'),
    d: scalar.toString('base64url'), ext:true, key_ops:['sign'] }, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
  return { point, privateKey };
}
async function kem(n) {
  const pair = await suite.kem.deriveKeyPair(bytes(n,32));
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { pair, point, id: await keyId(16,point) };
}
const root = await signing(7), origin = await signing(6), outbound = await signing(5);
const device = await kem(17);
let archive;
if (process.argv[2] === '--recipient-point') {
  const hex = process.argv[3];
  if (!/^04[0-9a-f]{128}$/.test(hex ?? '') || process.argv.length !== 4) throw Error('public recipient point');
  const point = new Uint8Array(Buffer.from(hex, 'hex'));
  await suite.kem.deserializePublicKey(point);
  archive = {point, id:await keyId(16,point)};
} else {
  if (process.argv.length !== 2) throw Error('unsupported fixture arguments');
  archive = await kem(34);
}
const accountId=bytes(161,16), deviceId=bytes(209,16), lineId=bytes(177,16), messageId=bytes(49,16);
const now=10000n, start=9000n, end=100000n;
const rootPin=join(text('ZTRP'),[2],accountId,integer(1,8),root.point);
const fingerprint=await sha(join(text('ZTSE/root-pin/v2\0'),rootPin));
const pin=await enrollRootPin02(rootPin,fingerprint);
const keys=[
  [1,device.id,device.point,deviceId,lineId,4],
  [2,archive.id,archive.point,bytes(0,16),bytes(0,16),12],
  [4,await keyId(257,origin.point),origin.point,deviceId,lineId,2],
  [5,await keyId(257,outbound.point),outbound.point,bytes(0,16),lineId,1],
  [6,await keyId(257,root.point),root.point,bytes(0,16),bytes(0,16),0],
];
const unsigned=join(text('ZTMA'),[2],accountId,integer(1,8),integer(1,8),integer(start,8),integer(end,8),
  bytes(0,32),root.point,[keys.length],...keys.map(([role,id,point,device,line,scope])=>
    join([role],id,point,device,line,integer(scope,2),integer(start,8),integer(end,8),[1])));
const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root.privateKey,
  join(text('ZTSE/manifest/v2\0'),integer(unsigned.length,4),unsigned))));
const manifestBytes=join(unsigned,signature), manifest=await verifyManifest02(manifestBytes,pin,now);
const shared={manifest,nowMs:now,messageId,deviceId,lineId,peer:text('+12'),observedMs:now,
  content:'Native cross-client ✓',cek:bytes(193,32),nonce:bytes(165,12)};
const inbound=await prepareInboundEnvelope02({...shared,kind:2,eventId:messageId,localSequence:7n,
  signer:{privateKey:origin.privateKey,publicPoint:origin.point},
  recipients:[{role:2,keyId:archive.id,point:archive.point,ekm:bytes(82,32)}]});
const outgoing=await prepareOutboundEnvelope02({...shared,kind:1,expiresMs:20000n,
  signer:{privateKey:outbound.privateKey,publicPoint:outbound.point},
  recipients:[{role:1,keyId:device.id,point:device.point,ekm:bytes(81,32)},
    {role:2,keyId:archive.id,point:archive.point,ekm:bytes(82,32)}]});
process.stdout.write(JSON.stringify({rootPin:b64(rootPin),fingerprint:b64(fingerprint),manifest:b64(manifestBytes),
  inbound:b64(inbound.envelope),outbound:b64(outgoing.envelope),
  ...(archive.pair ? {archiveScalar:b64(new Uint8Array(await suite.kem.serializePrivateKey(archive.pair.privateKey)))} : {}),
  reader:b64(archive.id),account:b64(accountId),device:b64(deviceId),line:b64(lineId),now:Number(now),text:shared.content}));
