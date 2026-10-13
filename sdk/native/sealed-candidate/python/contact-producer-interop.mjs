// Independent maintained TypeScript verification and synthetic TPM enrollment framing.
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02,advanceManifestTrust02} from '../../../typescript/dist/draft02-manifest.js';
import {keyId} from '../../../typescript/dist/draft01.js';
import * as statements from '../../../typescript/dist/contact-reader-statement.js';
import * as contacts from '../../../typescript/dist/contact-content-contract.js';
globalThis.crypto??=webcrypto;
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>1000000)throw Error('fixture bound');}
const request=JSON.parse(input),f=request.fixture;
const d=v=>new Uint8Array(Buffer.from(v,'base64')),b64=v=>Buffer.from(v).toString('base64');
const join=(...parts)=>new Uint8Array(Buffer.concat(parts.map(p=>Buffer.from(p))));
const integer=(n,size)=>{const b=Buffer.alloc(size);size===8?b.writeBigUInt64BE(BigInt(n)):b.writeUIntBE(n,0,size);return b;};
const text=v=>new TextEncoder().encode(v),sha=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const trust=await enrollRootPin02(d(f.rootPin),d(f.fingerprint));
const first=await verifyManifest02(d(f.manifest),trust,10000n);
if(process.argv[2]==='--root-template'){
 const point=d(request.point);await crypto.subtle.importKey('raw',point,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const pin=join(text('ZTRP'),[2],first.accountId,integer(1,8),point);
 const keys=await Promise.all(first.keys.map(async k=>k.role===6?{...k,point,keyId:await keyId(257,point)}:k));
 const unsigned=join(text('ZTMA'),[2],first.accountId,integer(1,8),integer(1,8),integer(first.issuedMs,8),integer(first.expiresMs,8),
  new Uint8Array(32),point,[keys.length],...keys.map(k=>join([k.role],k.keyId,k.point,k.deviceId,k.lineId,integer(k.scope,2),integer(k.fromMs,8),integer(k.untilMs,8),[k.state])));
 process.stdout.write(JSON.stringify({rootPin:b64(pin),fingerprint:b64(await sha(join(text('ZTSE/root-pin/v2\0'),pin))),manifestUnsigned:b64(unsigned)}));
}else{
 const next=await verifyManifest02(d(f.nextManifest),advanceManifestTrust02(trust,first),10000n);
 if(process.argv[2]==='--statement-template'){
  const frame=(manifest,generation)=>{const reader=manifest.keys.find(k=>k.role===2);return statements.encodeContactReaderStatementUnsigned01({authorizationId:new Uint8Array(16).fill(Number(generation)),
   accountId:manifest.accountId,origin:f.origin,trustGeneration:1n,manifestVersion:manifest.version,readerGeneration:generation,rootFingerprint:d(f.fingerprint),manifestDigest:manifest.digest,
   readerId:reader.keyId,readerPoint:reader.point,issuedMs:10000n,untilMs:20000n,capability:3});};
  process.stdout.write(JSON.stringify({statementUnsigned:b64(frame(first,1n)),nextStatementUnsigned:b64(frame(next,2n))}));
 }else{
  if(process.argv.length!==2)throw Error('fixture mode');
  const scope={expectedAccountId:d(f.account),expectedOrigin:f.origin,expectedRootFingerprint:d(f.fingerprint),comparison:'declared_issued_ms'};
  const old=await statements.verifyContactReaderStatement01({bytes:d(f.statement),acceptedManifest:first,...scope});
  const newer=await statements.verifyContactReaderStatement01({bytes:d(f.nextStatement),acceptedManifest:next,...scope});
  const bound={expectedContactId:d(f.contact),expectedRoutingDigest:d(f.routing)},fields={};
  for(const key of ['name','notes','replacement'])fields[key]=await contacts.verifyContactField01({bytes:d(request.fields[key]),statement:key==='replacement'?newer:old,...bound});
  const mutations={};
  for(const key of ['create','update','clear','converted'])mutations[key]=await contacts.verifyContactMutation01({bytes:d(request.mutations[key]),statement:['update','clear'].includes(key)?newer:old,
    ...bound,expectedLegacyGeneration:key==='converted'?7n:0n});
  const initial=contacts.verifyContactTransition01({previous:null,next:mutations.create,replacementFields:[fields.name,fields.notes]});
  const changed=contacts.verifyContactTransition01({previous:initial,next:mutations.update,replacementFields:[fields.replacement]});
  const final=contacts.verifyContactTransition01({previous:changed,next:mutations.clear,replacementFields:[]});
  contacts.verifyContactTransition01({previous:null,next:mutations.converted,replacementFields:[fields.name,fields.notes]});
  process.stdout.write(JSON.stringify({verified:true,fields:3,transitions:4,finalDigest:b64(contacts.verifiedContactTransitionIdentity01(final).digest)}));
 }
}
