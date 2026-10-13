// Actual maintained public proposal producers; genuine profile02 predecessor.
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {createConversationEnrollment02} from '../../../typescript/dist/conversation-enrollment.js';
import {encodeConversationGenesisProposal02,verifyPhoneKeyExport02,verifyArchivePublicHeader02} from '../../../typescript/dist/conversation-genesis-proposal.js';
import {encodeConversationActivationProposal02} from '../../../typescript/dist/conversation-activation-proposal.js';
import {encodeConversationRefreshProposal02} from '../../../typescript/dist/conversation-refresh-proposal.js';
globalThis.crypto??=webcrypto;
const enc=new TextEncoder(),b64=x=>Buffer.from(x).toString('base64'),dec=x=>new Uint8Array(Buffer.from(x,'base64'));
const hash=async x=>new Uint8Array(await crypto.subtle.digest('SHA-256',x)),join=(...parts)=>new Uint8Array(Buffer.concat(parts.map(Buffer.from))),u64=n=>{const x=new Uint8Array(8);new DataView(x.buffer).setBigUint64(0,BigInt(n));return x;};
const json=x=>x instanceof Uint8Array?b64(x):typeof x==='bigint'?Number(x):Array.isArray(x)?x.map(json):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).map(([k,v])=>[k,json(v)])):x;
function decodeObject(x){const numeric=new Set(['generation','nowMs','expiresMs','successorVersion','untilMs']);return Object.fromEntries(Object.entries(x).map(([k,v])=>[k,numeric.has(k)?BigInt(v):k==='origin'||k==='peer'?v:typeof v==='object'?decodeObject(v):dec(v)]));}
async function inputs(f){const pin=await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint));return {genesis:decodeObject(f.genesis),activation:{...decodeObject(f.activation),predecessor:await verifyManifest02(dec(f.manifest),pin,BigInt(f.now))},refresh:{...decodeObject(f.refresh),predecessor:await verifyManifest02(dec(f.manifest),pin,BigInt(f.now))}};}
if(process.argv[2]==='--public-cases'){
 let text='';for await(const part of process.stdin)text+=part;const {fixture:f,cases}=JSON.parse(text),out=[];
 for(const c of cases){const raw=dec(f[c.operation]),g=decodeObject(f.genesis);if(c.mutate!==undefined)raw[c.mutate]^=1;if(c.irrelevant){g.selection.session=new Uint8Array(16);g.selection.peer='not-a-peer';g.selection.extra=true;}
  try{const result=c.operation==='phone'?await verifyPhoneKeyExport02(raw,g.selection,dec(f.phoneFingerprint)):await verifyArchivePublicHeader02(raw,g.selection.account,g.comparedRootFingerprint,g.origin,dec(f.activation.selection.archiveReader));out.push({accepted:true,result:json(result)});}catch(error){out.push({accepted:false});}
 }
 process.stdout.write(JSON.stringify(out));
}else if(process.argv[2]==='--cases'){
 let text='';for await(const part of process.stdin)text+=part;const {fixture:f,cases}=JSON.parse(text),out=[];
 for(const item of cases){const values=await inputs(f),input=values[item.operation];
  if(item.path){const path=item.path.split('.');let target=input;for(const key of path.slice(0,-1))target=target[key];const key=path.at(-1),old=target[key];if(item.mutate!==undefined){target[key]=Uint8Array.from(old);target[key][item.mutate]^=1;}else target[key]=typeof old==='bigint'?BigInt(item.value):item.value;}
  if(item.forged)input.predecessor={...input.predecessor};
  try{const result=await ({genesis:encodeConversationGenesisProposal02,activation:encodeConversationActivationProposal02,refresh:encodeConversationRefreshProposal02}[item.operation])(input);out.push({accepted:true,result:json(result)});}catch(error){out.push({accepted:false});}
 }
 process.stdout.write(JSON.stringify(out));
}else{
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url))],{encoding:'utf8'}));
 const pin=await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),manifest=await verifyManifest02(dec(f.manifest),pin,BigInt(f.now)),key=role=>manifest.keys.find(k=>k.role===role);
 const shared={account:dec(f.account),session:new Uint8Array(16).fill(31),device:dec(f.device),line:dec(f.line),generation:1n,peer:'+12'};
 const origin='https://owner.invalid',fp=dec(f.fingerprint),nowMs=BigInt(f.now);
 const genesis={selection:{...shared,phoneSigningFingerprint:await hash(key(4).point)},rootPin:dec(f.rootPin),comparedRootFingerprint:fp,origin,phoneReaderPoint:key(1).point,archiveReaderPoint:key(2).point,phoneSignerPoint:key(4).point,nowMs,expiresMs:nowMs+10000n};
 const activation={selection:{...shared,phoneReader:key(1).keyId,archiveReader:key(2).keyId,phoneSigner:key(4).keyId},origin,comparedRootFingerprint:fp,nowMs};
 const binding={...shared,interval:new Uint8Array(16).fill(32),phoneReader:key(1).keyId,archiveReader:key(2).keyId},newKey=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const point=new Uint8Array(await crypto.subtle.exportKey('raw',newKey.publicKey));let review;
 const enrollment=createConversationEnrollment02(binding,point,async()=>({binding,manifest,nowMs,ownerSessionLive:true,consentLive:true}),async()=>{},async value=>{review=value;throw Error('fixture pause');},async()=>{throw Error('must not install');});
 try{await enrollment.enroll();}catch(error){if(error.message!=='fixture pause')throw error;}
 const refresh={review,origin,comparedRootFingerprint:fp,nowMs};
 const phone=join(enc.encode('ZTPK'),[1],shared.account,shared.device,shared.line,genesis.selection.phoneSigningFingerprint,u64(1),key(1).point,key(4).point),phoneFingerprint=await hash(join(enc.encode('ZTSE/phone-keys/v1\0'),phone));
 const site=enc.encode(origin),archive=new Uint8Array(333+site.length);archive.set([90,84,65,66,1,1]);archive.set(shared.account,22);archive.set(u64(1),38);archive.set(fp,46);archive.set(key(2).keyId,78);archive.set(key(2).point,110);new DataView(archive.buffer).setUint16(175,site.length);archive.set(site,177);archive.set([0,0,0,48],177+site.length+104);
 const verifiedPhone=await verifyPhoneKeyExport02(phone,genesis.selection,phoneFingerprint),verifiedArchive=await verifyArchivePublicHeader02(archive,shared.account,fp,origin,key(2).keyId);
 process.stdout.write(JSON.stringify({...f,genesis:json(genesis),activation:json(activation),refresh:json(refresh),phone:b64(phone),phoneFingerprint:b64(phoneFingerprint),archive:b64(archive),verifiedPhone:json(verifiedPhone),verifiedArchive:b64(verifiedArchive),expected:{genesis:json(await encodeConversationGenesisProposal02(genesis)),activation:json(await encodeConversationActivationProposal02({...activation,predecessor:manifest})),refresh:json(await encodeConversationRefreshProposal02({...refresh,predecessor:manifest}))}}));
}
