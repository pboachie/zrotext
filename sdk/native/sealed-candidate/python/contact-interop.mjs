// Fresh synthetic root chain and actual signed historical contact commitments.
// Ciphertexts are opaque fixture payloads, not a production contact writer.
import {execFileSync} from 'node:child_process';
import {webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {canonicalSignature02,enrollRootPin02,verifyManifest02,advanceManifestTrust02} from '../../../typescript/dist/draft02-manifest.js';
import * as statements from '../../../typescript/dist/contact-reader-statement.js';
import * as contacts from '../../../typescript/dist/contact-content-contract.js';
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
globalThis.crypto??=webcrypto;
const b64=b=>Buffer.from(b).toString('base64'),decode=b=>new Uint8Array(Buffer.from(b,'base64'));
const fill=(n,size)=>new Uint8Array(size).fill(n),join=(...parts)=>new Uint8Array(Buffer.concat(parts.map(p=>Buffer.from(p))));
const text=x=>new TextEncoder().encode(x),sha=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url))],{encoding:'utf8'}));
const trust=await enrollRootPin02(decode(f.rootPin),decode(f.fingerprint));
const first=await verifyManifest02(decode(f.manifest),trust,10000n);
const scalar=new Uint8Array(32);scalar[31]=7;
const root=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:Buffer.from(first.rootPoint.slice(1,33)).toString('base64url'),
 y:Buffer.from(first.rootPoint.slice(33)).toString('base64url'),d:Buffer.from(scalar).toString('base64url'),ext:true,key_ops:['sign']},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
const sign=async(domain,unsigned)=>{const n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,unsigned.length);return join(unsigned,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root,join(text(domain+'\0'),n,unsigned)))));};
const nextUnsigned=first.bytes.slice(0,-64);new DataView(nextUnsigned.buffer).setBigUint64(29,2n);nextUnsigned.set(first.digest,53);
const nextBytes=await sign('ZTSE/manifest/v2',nextUnsigned),next=await verifyManifest02(nextBytes,await advanceManifestTrust02(trust,first),10000n);
const origin='https://xn--fa-hia.invalid',scope={expectedAccountId:decode(f.account),expectedOrigin:origin,expectedRootFingerprint:decode(f.fingerprint),comparison:'declared_issued_ms'};
async function statement(manifest,generation){
 const reader=manifest.keys.find(k=>k.role===2);
 const raw=await sign('ZT/contact-reader/authorization/v1',statements.encodeContactReaderStatementUnsigned01({authorizationId:fill(Number(generation),16),accountId:manifest.accountId,origin,
  trustGeneration:1n,manifestVersion:manifest.version,readerGeneration:generation,rootFingerprint:decode(f.fingerprint),manifestDigest:manifest.digest,
  readerId:reader.keyId,readerPoint:reader.point,issuedMs:10000n,untilMs:20000n,capability:3}));
 const verified=await statements.verifyContactReaderStatement01({bytes:raw,acceptedManifest:manifest,...scope});return {raw,verified,id:statements.verifiedContactReaderStatementIdentity01(verified)};
}
const oldStatement=await statement(first,1n),newStatement=await statement(next,2n),contact=fill(31,16),routing=fill(32,32);
const bound={expectedContactId:contact,expectedRoutingDigest:routing};
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
async function field(st,kind,revision,request){
 const sender=await suite.createSenderContext({recipientPublicKey:await suite.kem.deserializePublicKey(st.id.readerPoint),info:text('synthetic contact fixture')});
 const ciphertext=new Uint8Array(await sender.seal(text('Synthetic encrypted field'),new Uint8Array()));
 const raw=await sign('ZT/contact-field/commitment/v1',contacts.encodeContactFieldUnsigned01({kind,accountId:first.accountId,contactId:contact,sealRevision:revision,
  trustGeneration:1n,manifestVersion:st.id.manifestVersion,readerGeneration:st.id.readerGeneration,readerId:st.id.readerId,manifestDigest:st.id.manifestDigest,
  statementDigest:st.id.digest,routingDigest:routing,requestId:request,rootWriterId:st.id.rootWriterId,encapsulation:new Uint8Array(sender.enc),ciphertext}));
 const verified=await contacts.verifyContactField01({bytes:raw,statement:st.verified,...bound});return {raw,verified,id:contacts.verifiedContactFieldIdentity01(verified)};
}
const request=fill(33,16),updateRequest=fill(34,16),name=await field(oldStatement,1,1n,request),notes=await field(oldStatement,2,1n,request),replacement=await field(newStatement,2,2n,updateRequest);
const slot=f=>({tag:1,sealRevision:f.id.sealRevision,digest:f.id.digest}),empty={tag:0,sealRevision:0n,digest:new Uint8Array(32)};
async function mutation(st,operation,revision,previous,requestId,name,notes,legacyGeneration=0n){
 const raw=await sign('ZT/contact-field/mutation/v1',contacts.encodeContactMutationUnsigned01({operation,accountId:first.accountId,contactId:contact,
  expectedRevision:revision-1n,revision,requestId,previousDigest:previous,trustGeneration:1n,manifestVersion:st.id.manifestVersion,manifestDigest:st.id.manifestDigest,
  statementDigest:st.id.digest,routingDigest:routing,legacyGeneration,name,notes}));
 const verified=await contacts.verifyContactMutation01({bytes:raw,statement:st.verified,...bound,expectedLegacyGeneration:legacyGeneration});return {raw,verified,id:contacts.verifiedContactMutationIdentity01(verified)};
}
const create=await mutation(oldStatement,1,1n,new Uint8Array(32),request,slot(name),slot(notes));
const update=await mutation(newStatement,2,2n,create.id.digest,updateRequest,slot(name),slot(replacement));
const clear=await mutation(newStatement,2,3n,update.id.digest,fill(35,16),empty,slot(replacement));
const converted=await mutation(oldStatement,3,1n,new Uint8Array(32),request,slot(name),slot(notes),7n);
const initial=contacts.verifyContactTransition01({previous:null,next:create.verified,replacementFields:[name.verified,notes.verified]});
const changed=contacts.verifyContactTransition01({previous:initial,next:update.verified,replacementFields:[replacement.verified]});
const final=contacts.verifyContactTransition01({previous:changed,next:clear.verified,replacementFields:[]});
const origins=['https://synthetic.invalid','https://synthetic.invalid:8443','https://synthetic.invalid:443','https://SYNTHETIC.invalid','https://synthetic.invalid/',
 'https://synthetic.invalid/path','https://user@synthetic.invalid','https://xn--fa-hia.invalid','https://a!b.invalid','https://a^b.invalid','https://xn--.invalid'];
origins.push(...Array.from({length:94},(_,i)=>'https://a'+String.fromCharCode(33+i)+'b.invalid'), 'https://'+[127,0,0,1].join('.'),'https://'+[127,1].join('.'),'https://'+['0x7f',1].join('.'),'https://a.0x','https://[::1]','https://[0:0:0:0:0:0:0:1]','https://synthetic.invalid:00080','https://synthetic.invalid:0');
if(process.argv.length>2){
 if(process.argv.length!==3||process.argv[2]!=='--origins')throw Error('fixture arguments');
 let input='';for await(const chunk of process.stdin)input+=chunk;
 const extra=JSON.parse(input);if(!Array.isArray(extra)||extra.length>10000||extra.some(v=>typeof v!=='string'))throw Error('origin cases');origins.push(...extra);
}
const statementNames=['authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration','rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability'];
const unsignedBase=Object.fromEntries(statementNames.map(k=>[k,oldStatement.id[k]]));
const originCases=origins.map(origin=>{try{const unsigned=statements.encodeContactReaderStatementUnsigned01({...unsignedBase,origin});return {origin,accepted:true,unsigned:b64(unsigned)};}catch{return {origin,accepted:false};}});
process.stdout.write(JSON.stringify({rootPin:f.rootPin,fingerprint:f.fingerprint,manifest:f.manifest,nextManifest:b64(nextBytes),account:f.account,origin,
 statement:b64(oldStatement.raw),nextStatement:b64(newStatement.raw),contact:b64(contact),routing:b64(routing),name:b64(name.raw),notes:b64(notes.raw),replacement:b64(replacement.raw),
 create:b64(create.raw),update:b64(update.raw),clear:b64(clear.raw),converted:b64(converted.raw),finalDigest:b64(contacts.verifiedContactTransitionIdentity01(final).digest),originCases}));
