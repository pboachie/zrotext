// Independent maintained ZTWC01 acceptance with synthetic signed manifest authority.
import {execFileSync} from 'node:child_process';
import {createECDH,webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {canonicalSignature02,enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {keyId} from '../../../typescript/dist/draft01.js';
import {workflowContextAad,sealWorkflowContext,sealIntegrationWorkflowContext,openWorkflowContext,openIntegrationWorkflowContext} from '../../../typescript/dist/workflow-context.js';
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
globalThis.crypto??=webcrypto;
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
const b64=b=>Buffer.from(b).toString('base64'),dec=b=>new Uint8Array(Buffer.from(b,'base64'));
const join=(...p)=>new Uint8Array(Buffer.concat(p.map(b=>Buffer.from(b))));
const number=(v,n=8)=>{const b=Buffer.alloc(n);n===8?b.writeBigUInt64BE(BigInt(v)):b.writeUIntBE(v,0,n);return b;};
const numeric=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
const scopeOf=f=>Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,k==='kind'?v:numeric.includes(k)?BigInt(v):dec(v)]));
const manifestOf=async f=>verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));
if(process.argv[2]==='--consume'){
 let text='';for await(const part of process.stdin){text+=part;if(text.length>200000)throw Error('fixture bound');}
 const {fixture:f,envelope,plaintext}=JSON.parse(text),manifest=await manifestOf(f),scope=scopeOf(f);
 const open=f.role===2?openWorkflowContext:openIntegrationWorkflowContext;
 const key=await suite.kem.deserializePrivateKey(dec(f.selectedScalar));
 const opened=await open(manifest,scope,BigInt(f.now),key,dec(envelope));
 if(b64(opened)!==plaintext)throw Error('native context mismatch');
 process.stdout.write(JSON.stringify({verified:true,role:f.role,length:opened.length}));
}else{
 const role=Number(process.argv[2]??2);if(![2,3].includes(role)||![3,4].includes(process.argv.length)&&process.argv.length!==2)throw Error('fixture args');
 const publicHex=process.argv[3];if(publicHex&&!/^04[0-9a-f]{128}$/.test(publicHex))throw Error('public point');
 const args=role===2&&publicHex?['--recipient-point',publicHex]:[];
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url)),...args],{encoding:'utf8'}));
 const pair=await suite.kem.deriveKeyPair(new Uint8Array(32).fill(55));
 const point=role===3&&publicHex?new Uint8Array(Buffer.from(publicHex,'hex')):new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
 await suite.kem.deserializePublicKey(point);const id=await keyId(16,point);
 const record=join([3],id,point,new Uint8Array(32),number(8,2),number(9000),number(100000),[1]);
 const old=dec(f.manifest).slice(0,-64),header=old.slice(0,151);header[150]++;
 const unsigned=join(header,old.slice(151,449),record,old.slice(449));
 const scalar=Buffer.alloc(32);scalar[31]=7;const ecdh=createECDH('prime256v1');ecdh.setPrivateKey(scalar);const root=ecdh.getPublicKey();
 const signing=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:root.subarray(1,33).toString('base64url'),y:root.subarray(33).toString('base64url'),d:scalar.toString('base64url'),ext:true,key_ops:['sign']},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const sig=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signing,join(new TextEncoder().encode('ZTSE/manifest/v2\0'),number(unsigned.length,4),unsigned))));
 f.manifest=b64(join(unsigned,sig));f.role=role;
 if(!publicHex)f.selectedScalar=role===2?f.archiveScalar:b64(await suite.kem.serializePrivateKey(pair.privateKey));
 const fill=(n,size)=>new Uint8Array(size).fill(n);
 const scope={kind:3,accountId:dec(f.account),deviceId:dec(f.device),lineId:dec(f.line),intervalId:fill(21,16),contextId:fill(22,16),bindingGeneration:1n,revision:1n,expiresMs:20000n,trustGeneration:1n,manifestVersion:1n,peerDigest:fill(23,32),readerId:role===2?dec(f.reader):id,manifestDigest:new Uint8Array(await crypto.subtle.digest('SHA-256',unsigned))};
 f.scope=Object.fromEntries(Object.entries(scope).map(([k,v])=>[k,typeof v==='bigint'?Number(v):typeof v==='number'?v:b64(v)]));
 const manifest=await manifestOf(f),plaintext=new Uint8Array([0,255,1,128,10]);
 const seal=role===2?sealWorkflowContext:sealIntegrationWorkflowContext,open=role===2?openWorkflowContext:openIntegrationWorkflowContext;
 const envelope=await seal(manifest,scope,BigInt(f.now),plaintext);
 if(f.selectedScalar){const opened=await open(manifest,scope,BigInt(f.now),await suite.kem.deserializePrivateKey(dec(f.selectedScalar)),envelope);if(b64(opened)!==b64(plaintext))throw Error('TS self-open');}
 process.stdout.write(JSON.stringify({...f,aad:b64(workflowContextAad(scope)),envelope:b64(envelope),plaintext:b64(plaintext)}));
}
