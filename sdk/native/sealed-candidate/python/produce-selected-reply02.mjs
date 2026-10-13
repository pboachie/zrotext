// Synthetic independent TypeScript producer. No service or device interaction.
import { createECDH, webcrypto } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import { canonicalSignature02, enrollRootPin02, verifyManifest02, advanceManifestTrust02, verifiedManifestIdentity02 } from '../../../typescript/dist/draft02-manifest.js';
import { prepareInboundEnvelope02 } from '../../../typescript/dist/draft02-envelope-prep.js';
import { keyId } from '../../../typescript/dist/draft01.js';
import { verifyArchiveReplySelection02, verifyOriginalReplySelection02 } from '../../../typescript/dist/original-reply-selection.js';
import { openOriginalReply02 } from '../../../typescript/dist/original-reply-reader.js';
import { openConversationInbound02 } from '../../../typescript/dist/conversation-reader.js';
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
const root=await signing(7), origin=await signing(6), archive=await kem(34), extra=await kem(35);
const readerFlag=process.argv.indexOf('--reader-point');
if(readerFlag>=0){
 const encoded=process.argv[readerFlag+1];if(!/^[0-9a-f]{130}$/.test(encoded??''))throw Error('reader point');
 extra.point=new Uint8Array(Buffer.from(encoded,'hex'));await suite.kem.deserializePublicKey(extra.point);
 extra.id=await keyId(16,extra.point);
}
const accountId=bytes(161,16),deviceId=bytes(209,16),lineId=bytes(177,16),interval=bytes(42,16),messageId=bytes(49,16);
const rootPin=join(text('ZTRP'),[2],accountId,integer(1,8),root.point);
const fingerprint=await sha(join(text('ZTSE/root-pin/v2\0'),rootPin));
const pin=await enrollRootPin02(rootPin,fingerprint),now=10000n,start=9000n,end=100000n;
const signer=await keyId(257,origin.point);
const keys=[[2,archive.id,archive.point,bytes(0,16),bytes(0,16),12],
 [3,extra.id,extra.point,bytes(0,16),bytes(0,16),8],
 [4,signer,origin.point,deviceId,lineId,2],
 [6,await keyId(257,root.point),root.point,bytes(0,16),bytes(0,16),0]];
async function sign(domain,payload,key=origin.privateKey){return canonicalSignature02(new Uint8Array(await crypto.subtle.sign(
 {name:'ECDSA',hash:'SHA-256'},key,join(text(domain+'\0'),integer(payload.length,4),payload))));}
async function manifest(version,previous,trust,records=keys){
 const unsigned=join(text('ZTMA'),[2],accountId,integer(1,8),integer(version,8),integer(start,8),integer(end,8),previous,
  root.point,[records.length],...records.map(([role,id,point,device,line,scope,state=1])=>join([role],id,point,device,line,integer(scope,2),integer(start,8),integer(end,8),[state])));
 const raw=join(unsigned,await sign('ZTSE/manifest/v2',unsigned,root.privateKey));
 return {raw,value:await verifyManifest02(raw,trust,now)};
}
const predecessor=await manifest(1,bytes(0,32),pin);
const oldIdentity=verifiedManifestIdentity02(predecessor.value,now);
const activation=await manifest(2,oldIdentity.digest,await advanceManifestTrust02(pin,predecessor.value));
const identity=verifiedManifestIdentity02(activation.value,now);
const successorTrust=await advanceManifestTrust02(await advanceManifestTrust02(pin,predecessor.value),activation.value);
const successor=await manifest(3,identity.digest,successorTrust);
const revoked=await manifest(3,identity.digest,successorTrust,keys.map(row=>row[0]===3?[...row,2]:row));
const disclosure='With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.';
const str=s=>join([text(s).length],text(s));
const selection=join(text('ZTCA'),[2],accountId,deviceId,lineId,integer(1,8),interval,bytes(43,16),bytes(44,16),bytes(45,32),
 integer(20000,8),str('+12'),str('conversation-content-v1'),await sha(text(disclosure)),archive.id,signer,integer(1,8),integer(1,8),
 oldIdentity.digest,integer(2,8),identity.digest,integer(1,8),integer(1,8),str('synthetic-site'),str('synthetic-instance'),
 [1],bytes(46,16),bytes(47,16),extra.id);
const approval=await sign('zrotext/conversation/approve/v2',selection),installation=await sign('zrotext/conversation/install/v2',selection);
const scope={account:accountId,device:deviceId,line:lineId,interval,peer:'+12',archiveReader:archive.id};
const accepted=await verifyArchiveReplySelection02(selection,approval,installation,activation.value,now,scope);
const shared={manifest:activation.value,nowMs:now,messageId,deviceId,lineId,peer:text('+12'),observedMs:now,
 content:'Selected native reply ✓',cek:bytes(193,32),nonce:bytes(165,12),kind:2,eventId:messageId,localSequence:7n,
 signer:{privateKey:origin.privateKey,publicPoint:origin.point}};
const recipients=[{role:2,keyId:archive.id,point:archive.point,ekm:bytes(82,32)},
 {role:3,keyId:extra.id,point:extra.point,ekm:bytes(83,32)}];
const inbound=await prepareInboundEnvelope02({...shared,recipients});
const archiveOnly=await prepareInboundEnvelope02({...shared,recipients:recipients.slice(0,1)});
const opened=await openConversationInbound02(inbound.envelope,{...scope,archivePrivateKey:archive.pair.privateKey,
 historical:activation.value,current:activation.value,nowMs:now,selection:accepted});
if(opened!==shared.content)throw Error('independent selected archive opening');
const originalScope={account:accountId,device:deviceId,line:lineId,interval,peer:'+12',connector:bytes(46,16),readGrant:bytes(47,16),reader:extra.id};
const originalSelection=await verifyOriginalReplySelection02(selection,approval,installation,activation.value,now,originalScope);
if(readerFlag<0){
 const originalPrivate=await crypto.subtle.importKey('jwk',await crypto.subtle.exportKey('jwk',extra.pair.privateKey),{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const originalText=await openOriginalReply02(inbound.envelope,{scope:originalScope,event:messageId,privateKey:originalPrivate,historical:activation.value,
  selection:originalSelection,readCurrent:async()=>({...originalScope,revision:'1',expiresMs:20000n,nowMs:now,manifest:activation.value})});
 if(originalText!==shared.content)throw Error('independent original role3 opening');
}
process.stdout.write(JSON.stringify({rootPin:b64(rootPin),fingerprint:b64(fingerprint),predecessor:b64(predecessor.raw),activation:b64(activation.raw),successor:b64(successor.raw),revoked:b64(revoked.raw),
 selection:b64(selection),approval:b64(approval),installation:b64(installation),inbound:b64(inbound.envelope),archiveOnly:b64(archiveOnly.envelope),
 archiveScalar:b64(new Uint8Array(await suite.kem.serializePrivateKey(archive.pair.privateKey))),reader:b64(archive.id),
 ...(readerFlag<0?{originalScalar:b64(new Uint8Array(await suite.kem.serializePrivateKey(extra.pair.privateKey)))}:{}),originalReader:b64(extra.id),
 connector:b64(originalScope.connector),readGrant:b64(originalScope.readGrant),event:b64(messageId),
 account:b64(accountId),device:b64(deviceId),line:b64(lineId),interval:b64(interval),now:Number(now),text:opened}));
