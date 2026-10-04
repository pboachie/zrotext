// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic signed statements only. No custody, current permission or installed reader.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import {refreshFixture,join,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {canonicalSignature02,enrollRootPin02,verifyManifest02,verifyRootTransition02,verifiedAccountArchiveStatementRecords02 as records} from '../dist/draft02-manifest.js';
import {encodeContactReaderStatementUnsigned01 as encode,parseContactReaderStatement01 as parse,
  verifyContactReaderStatement01 as verify,verifiedContactReaderStatementIdentity01 as identity} from '../dist/contact-reader-statement.js';
const enc=new TextEncoder();
test('shared public vector preserves exact binary signature and complete signed digest',async()=>{
  const vector=JSON.parse(await readFile(new URL('../../../protocol/v1/contact-reader-statement-vectors.json',import.meta.url)));
  const unhex=s=>new Uint8Array(Buffer.from(s,'hex')),root=await enrollRootPin02(unhex(vector.root_pin_hex),unhex(vector.expected_root_fingerprint_hex));
  const manifest=await verifyManifest02(unhex(vector.accepted_manifest_hex),{...root,version:BigInt(vector.accepted_previous_version),digest:unhex(vector.accepted_previous_digest_hex)},BigInt(vector.declared_issued_ms));
  const result=await verify({bytes:unhex(vector.statement_hex),acceptedManifest:manifest,expectedAccountId:unhex(vector.account_hex),expectedOrigin:vector.origin,expectedRootFingerprint:unhex(vector.expected_root_fingerprint_hex),comparison:vector.comparison});
  const id=identity(result);assert.deepEqual(id.unsigned,unhex(vector.unsigned_hex));assert.deepEqual(id.digest,unhex(vector.statement_digest_hex));assert.equal(id.untilMs,BigInt(vector.declared_until_ms));
});
async function fixture(){
  const f=await refreshFixture(),reader=f.predecessor.keys.find(k=>k.role===2),rootPoint=f.predecessor.rootPoint;
  const s={authorizationId:new Uint8Array(16).fill(7),accountId:f.review.binding.account,origin:f.origin,trustGeneration:1n,
    manifestVersion:f.predecessor.version,readerGeneration:1n,rootFingerprint:f.comparedRootFingerprint,
    manifestDigest:f.predecessor.digest,readerId:reader.keyId,readerPoint:reader.point,issuedMs:2000n,untilMs:3000n,capability:3};
  const scalar=new Uint8Array(32);scalar[31]=1;const b64=b=>Buffer.from(b).toString('base64url');
  const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(rootPoint.slice(1,33)),y:b64(rootPoint.slice(33)),d:b64(scalar)}, {name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
  async function sign(value=s,domain='ZT/contact-reader/authorization/v1\0'){
    const unsigned=encode(value),n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,unsigned.length);
    return join(unsigned,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,join(enc.encode(domain),n,unsigned)))));
  }
  const bytes=await sign();return {f,s,bytes,sign,input:{bytes,acceptedManifest:f.predecessor,expectedAccountId:s.accountId,expectedOrigin:s.origin,expectedRootFingerprint:s.rootFingerprint,comparison:'declared_issued_ms'}};
}
test('authentic genesis statement yields historical integrity only with defensive identity',async()=>{
  const f=await fixture(),parsed=await parse(f.bytes),v=await verify(f.input),id=identity(v);
  assert.equal(f.bytes.length,305+f.s.origin.length);assert.deepEqual(parsed.unsigned,encode(f.s));
  assert.deepEqual(v,{kind:'historical_integrity'});assert.equal(v.current,undefined);assert.equal(v.allowed,undefined);
  assert.equal(id.untilMs,3000n);assert.equal(id.manifestVersion,7n);assert.equal(id.digest.length,32);
  id.readerPoint.fill(0);id.bytes.fill(0);assert.deepEqual(identity(v).bytes,f.bytes);assert.deepEqual(identity(v).readerPoint,f.s.readerPoint);
  assert.throws(()=>identity({...v}));assert.throws(()=>identity({kind:'historical_integrity'}));
});
test('unbranded manifests and mutated public projections cannot replace accepted records',async()=>{
  const f=await fixture();await assert.rejects(verify({...f.input,acceptedManifest:{...f.f.predecessor}}));
  f.f.predecessor.keys.length=0;f.f.predecessor.rootPoint.fill(0);f.f.predecessor.digest.fill(0);
  assert.equal((await verify(f.input)).kind,'historical_integrity');
});
test('caller bytes and expected identity are captured before asynchronous verification',async()=>{
  const f=await fixture(),bytes=f.bytes.slice(),account=f.s.accountId.slice(),pin=f.s.rootFingerprint.slice();
  const pending=verify({...f.input,bytes,expectedAccountId:account,expectedRootFingerprint:pin});bytes.fill(0);account.fill(0);pin.fill(0);
  assert.equal((await pending).kind,'historical_integrity');
});
test('new public historical record inspector refuses invalid comparison range',async()=>{
  const f=await fixture();for(const ms of [0n,-1n,1n<<63n,2000])assert.throws(()=>records(f.f.predecessor,f.s.readerId,ms));
  assert.equal(records(f.f.predecessor,f.s.readerId,2000n).version,7n);
});
test('signed pre-issued comparison at zero cannot exploit ordinary manifest skew allowance',async()=>{
  const f=await fixture(),unsigned=f.f.predecessor.bytes.slice(0,-64),v=new DataView(unsigned.buffer);v.setBigUint64(37,1n);
  for(let at=151;at<unsigned.length;at+=149)v.setBigUint64(at+132,0n);
  const pin=join(enc.encode('ZTRP'),Uint8Array.of(2),f.s.accountId,Uint8Array.of(0,0,0,0,0,0,0,1),f.f.predecessor.rootPoint),root=await enrollRootPin02(pin,f.s.rootFingerprint);
  const m=await verifyManifest02(await signFixtureSuccessor02(f.f,unsigned),{...root,version:6n,digest:new Uint8Array(32).fill(9)},2000n);
  assert.equal(records(m,f.s.readerId,1n).version,7n);assert.throws(()=>records(m,f.s.readerId,0n));
});
test('canonical framing origin generation and low-s aliases refuse',async()=>{
  const f=await fixture();for(const value of [f.bytes.slice(1),join(f.bytes,Uint8Array.of(0)),new Uint8Array(818),
    f.bytes.map((v,i)=>i===4?2:v),f.bytes.map((v,i)=>i===5?1:v)])await assert.rejects(parse(value));
  for(const origin of ['http://owner.invalid','https://OWNER.invalid','https://owner.invalid:443','https://owner.invalid/','https://owner.invalid?q=1','https://a.invalid#x'])assert.throws(()=>encode({...f.s,origin}));
  for(const change of [{trustGeneration:2n},{readerGeneration:0n},{untilMs:2000n},{untilMs:86402001n},{capability:1},{extra:true}])assert.throws(()=>encode({...f.s,...change}));
  const order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const high=f.bytes.slice(),offset=high.length-32;let scalar=order-BigInt('0x'+Buffer.from(high.slice(offset)).toString('hex'));
  for(let i=31;i>=0;i--){high[offset+i]=Number(scalar&255n);scalar>>=8n;}await assert.rejects(parse(high));
});
test('framing encoder does not claim curve validity; async parser rejects off-curve and key aliases',async()=>{
  const f=await fixture(),point=new Uint8Array(65);point[0]=4;assert.equal(encode({...f.s,readerPoint:point}).length,241+f.s.origin.length);
  await assert.rejects(parse(await f.sign({...f.s,readerPoint:point})));
  await assert.rejects(parse(await f.sign({...f.s,readerId:new Uint8Array(32).fill(9)})));
});
test('signed scope domain and declared validity cannot substitute expected accepted history',async()=>{
  const f=await fixture();for(const change of [{accountId:new Uint8Array(16).fill(9)},{origin:'https://other.invalid'},
    {manifestVersion:8n},{manifestDigest:new Uint8Array(32).fill(9)},{rootFingerprint:new Uint8Array(32).fill(9)},
    {issuedMs:999n},{untilMs:f.f.predecessor.expiresMs+1n}])await assert.rejects(verify({...f.input,bytes:await f.sign({...f.s,...change})}));
  await assert.rejects(verify({...f.input,bytes:await f.sign(f.s,'ZTSE/manifest/v2\0')}));
  const changed=f.bytes.slice();changed[changed.length-1]^=1;await assert.rejects(verify({...f.input,bytes:changed}));
  await assert.rejects(verify({...f.input,comparison:'current'}));
  await assert.rejects(verify({...f.input,expectedRootFingerprint:new Uint8Array(32).fill(9)}));
});
test('actual signed reader intervals bind declared history with exact expiry boundary',async()=>{
  const f=await fixture(),unsigned=f.f.predecessor.bytes.slice(0,-64),at=151+149;
  const root=await enrollRootPin02(join(enc.encode('ZTRP'),Uint8Array.of(2),f.s.accountId,Uint8Array.of(0,0,0,0,0,0,0,1),f.f.predecessor.rootPoint),f.s.rootFingerprint);
  for(const [from,until] of [[1000n,2500n],[2001n,3602000n]]){
    const changed=unsigned.slice(),view=new DataView(changed.buffer);view.setBigUint64(at+132,from);view.setBigUint64(at+140,until);
    const m=await verifyManifest02(await signFixtureSuccessor02(f.f,changed),{...root,version:6n,digest:new Uint8Array(32).fill(9)},2000n),s={...f.s,manifestDigest:m.digest};
    await assert.rejects(verify({...f.input,acceptedManifest:m,bytes:await f.sign(s)}));
    if(from===1000n){
      assert.equal((await verify({...f.input,acceptedManifest:m,bytes:await f.sign({...s,untilMs:until})})).kind,'historical_integrity');
      await assert.rejects(verify({...f.input,acceptedManifest:m,bytes:await f.sign({...s,issuedMs:until,untilMs:until+1n})}));
    }
  }
  const phone=f.f.predecessor.keys.find(k=>k.role===1);
  await assert.rejects(verify({...f.input,bytes:await f.sign({...f.s,readerId:phone.keyId,readerPoint:phone.point})}));
});
test('genuinely accepted replacement reader does not revive retired statement reader',async()=>{
  const f=await fixture(),unsigned=f.f.predecessor.bytes.slice(0,-64),rs=[];
  for(let at=151;at<unsigned.length;at+=149)rs.push(unsigned.slice(at,at+149));
  rs[1][148]=2;const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),point=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey)),replacement=rs[1].slice();
  replacement[148]=1;replacement.set(point,33);replacement.set(new Uint8Array(await crypto.subtle.digest('SHA-256',join(enc.encode('ZTSE/key/v1\0'),Uint8Array.of(0,16),point))),1);
  rs.push(replacement);rs.sort((a,b)=>Buffer.compare(a.slice(0,33),b.slice(0,33)));const header=unsigned.slice(0,151);header[150]=5;
  const pin=join(enc.encode('ZTRP'),Uint8Array.of(2),f.s.accountId,Uint8Array.of(0,0,0,0,0,0,0,1),f.f.predecessor.rootPoint),root=await enrollRootPin02(pin,f.s.rootFingerprint);
  const m=await verifyManifest02(await signFixtureSuccessor02(f.f,join(header,...rs)),{...root,version:6n,digest:new Uint8Array(32).fill(9)},2000n);
  await assert.rejects(verify({...f.input,acceptedManifest:m,bytes:await f.sign({...f.s,manifestDigest:m.digest})}));
});
test('genuinely verified generation-two history remains outside the genesis-only inspector',async()=>{
  const v=JSON.parse(await readFile(new URL('./vectors/draft02-rotation.json',import.meta.url),'utf8')),b64=n=>new Uint8Array(Buffer.from(v[n],'base64')),now=BigInt(v.now_ms);
  const old=await verifyManifest02(b64('old_manifest_b64'),await enrollRootPin02(b64('old_root_pin_b64'),b64('old_root_fingerprint_b64')),now);
  const next=await verifyRootTransition02(b64('transition_b64'),{...await enrollRootPin02(b64('old_root_pin_b64'),b64('old_root_fingerprint_b64')),version:old.version,digest:old.digest},now,b64('new_root_point_b64'));
  const m=await verifyManifest02(b64('new_manifest_b64'),next,now);assert.equal(m.generation,2n);
  assert.throws(()=>records(m,m.keys.find(k=>k.role===2).keyId,now));
});
