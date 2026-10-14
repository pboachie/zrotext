// Genuine shared custody corpus and maintained verifier differential oracle.
import {readFileSync} from 'node:fs';
import {createHash,createPrivateKey,sign} from 'node:crypto';
import {verifyPublishedRootBundle} from '../../../typescript/dist/root-custody.js';
import {canonicalSignature02} from '../../../typescript/dist/draft02-manifest.js';
const read=name=>JSON.parse(readFileSync(new URL(`../../../../protocol/v1/vectors/${name}.json`,import.meta.url)));
const kit=read('recovery-kit-01'),backup=read('root-backup-01'),custody=read('root-custody-01');
const hex=s=>Buffer.from(s,'hex'),hash=b=>createHash('sha256').update(b).digest();
function fixture(){return {pin:hex(kit.rootPinHex),fingerprint:hex(kit.fingerprintHex),origin:'https://example.test',published:{rootPin:hex(kit.rootPinHex),encryptedBackup:hex(backup.ciphertextHex),publicCard:hex(kit.cardHex),unsignedEnrollment:hex(custody.unsignedHex),custodySignature:hex(custody.signatureHex)}};}
function resign(f){
  const p=f.published,n=Buffer.byteLength(f.origin),scalar=hash(Buffer.from('ZROtext synthetic root-backup test root'));
  const key=createPrivateKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:f.pin.subarray(30,62).toString('base64url'),y:f.pin.subarray(62,94).toString('base64url'),d:scalar.toString('base64url')}});scalar.fill(0);
  hash(p.encryptedBackup).copy(p.publicCard,101+n);
  const length=Buffer.alloc(4);length.writeUInt32BE(p.unsignedEnrollment.length);
  p.custodySignature=canonicalSignature02(sign('sha256',Buffer.concat([Buffer.from('ZTSE/root-custody/v1\0'),length,p.unsignedEnrollment,hash(p.encryptedBackup),hash(p.publicCard),f.fingerprint]),{key,dsaEncoding:'ieee-p1363'}));
}
const cases=[];
async function add(name,edit=()=>{},signed=false){const f=fixture();edit(f);if(signed)resign(f);let accept=false;
  try{await verifyPublishedRootBundle(f.pin,f.fingerprint,f.origin,f.published);accept=true;}catch{}
  cases.push({name,accept,pin:f.pin.toString('hex'),fingerprint:f.fingerprint.toString('hex'),origin:f.origin,published:Object.fromEntries(Object.entries(f.published).map(([k,v])=>[k,Buffer.from(v).toString('hex')]))});}
await add('shared-valid');
await add('opaque-backup-is-not-AEAD-verified',f=>f.published.encryptedBackup[170]^=1,true);
await add('historical-not-current',f=>{f.published.unsignedEnrollment.writeBigUInt64BE(1n,133);f.published.unsignedEnrollment.writeBigUInt64BE(2n,141);},true);
for(const key of ['pin','fingerprint'])await add(`wrong-${key}`,f=>f[key][0]^=1);
for(const field of Object.keys(fixture().published)){
  await add(`tamper-${field}`,f=>f.published[field][0]^=1);
  await add(`truncated-${field}`,f=>f.published[field]=f.published[field].subarray(1));
  await add(`extended-${field}`,f=>f.published[field]=Buffer.concat([f.published[field],Buffer.alloc(1)]));
}
for(const origin of ['http://example.test','https://example.test/','https://foreign.test','https://EXAMPLE.test','https://example.test:443','https://example.test?','https://example.test#'])await add(`origin-${origin}`,f=>f.origin=origin);
for(const offset of [5,21,37,53])await add(`zero-enrollment-${offset}`,f=>f.published.unsignedEnrollment.fill(0,offset,offset+16),true);
for(const [name,issued,expires] of [['zero-issued',0n,1n],['equal-time',10n,10n],['oversized-window',1n,300002n],['overflow-time',1n,1n<<63n]])await add(name,f=>{f.published.unsignedEnrollment.writeBigUInt64BE(issued,133);f.published.unsignedEnrollment.writeBigUInt64BE(expires,141);},true);
await add('zero-backup-id',f=>f.published.encryptedBackup.fill(0,6,22),true);
await add('wrong-backup-generation',f=>f.published.encryptedBackup.writeBigUInt64BE(2n,38),true);
await add('wrong-ciphertext-length',f=>f.published.encryptedBackup.writeUInt32BE(47,184+Buffer.byteLength(f.origin)),true);
await add('rewritten-public-digest',f=>{f.published.encryptedBackup[200]^=1;hash(f.published.encryptedBackup).copy(f.published.publicCard,101+Buffer.byteLength(f.origin));});
await add('high-s',f=>{const raw=f.published.custodySignature,order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');hex((order-BigInt('0x'+raw.subarray(32).toString('hex'))).toString(16).padStart(64,'0')).copy(raw,32);});
await add('zero-r',f=>f.published.custodySignature.fill(0,0,32));
console.log(JSON.stringify({cases}));

