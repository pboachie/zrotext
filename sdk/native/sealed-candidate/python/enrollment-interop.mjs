// Maintained enrollment lifecycle oracle using genuinely verified genesis evidence.
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {webcrypto,createECDH} from 'node:crypto';
import {enrollRootPin02,verifyManifest02,advanceManifestTrust02,canonicalSignature02,authorizeOutbound02} from '../../../typescript/dist/draft02-manifest.js';
import {createConversationEnrollment02} from '../../../typescript/dist/conversation-enrollment.js';
globalThis.crypto??=webcrypto;
const b64=v=>Buffer.from(v).toString('base64'),dec=v=>new Uint8Array(Buffer.from(v,'base64'));
const join=(...v)=>new Uint8Array(Buffer.concat(v.map(Buffer.from))),enc=new TextEncoder(),hash=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const json=v=>v instanceof Uint8Array?b64(v):typeof v==='bigint'?Number(v):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,json(x)])):v;
const decodeBinding=b=>Object.fromEntries(Object.entries(b).map(([k,v])=>[k,k==='peer'?v:k==='generation'?BigInt(v):dec(v)]));
async function stdin(){let text='';for await(const part of process.stdin)text+=part;return JSON.parse(text);}
async function material(f){const pin=await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),manifest=await verifyManifest02(dec(f.manifest),pin,BigInt(f.now));return {pin,manifest};}
async function fixture(f){
 const {manifest}=await material(f),binding={account:manifest.accountId,device:manifest.keys.find(k=>k.role===1).deviceId,line:manifest.keys.find(k=>k.role===1).lineId,interval:new Uint8Array(16).fill(31),session:new Uint8Array(16).fill(32),generation:1n,peer:'+12',phoneReader:manifest.keys.find(k=>k.role===1).keyId,archiveReader:manifest.keys.find(k=>k.role===2).keyId};
 const ecdh=createECDH('prime256v1'),scalar=new Uint8Array(32);scalar[31]=13;ecdh.setPrivateKey(scalar);const point=new Uint8Array(ecdh.getPublicKey());scalar.fill(0);let review;
 const flow=createConversationEnrollment02(binding,point,async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:true,consentLive:true}),async()=>{},async r=>{review=r;throw Error('fixture pause');},async()=>{throw Error('unexpected install');});
 try{await flow.enroll();}catch(error){if(error.message!=='fixture pause')throw error;}
 if(!review)throw Error('missing review');return {...f,binding:json(binding),point:b64(point),review:json(review)};
}
async function sign(unsigned){
 const scalar=new Uint8Array(32);scalar[31]=7;const ecdh=createECDH('prime256v1');ecdh.setPrivateKey(scalar);const point=ecdh.getPublicKey(),url=v=>Buffer.from(v).toString('base64url');
 const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:url(point.subarray(1,33)),y:url(point.subarray(33)),d:url(scalar)},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
 const size=new Uint8Array(4);new DataView(size.buffer).setUint32(0,unsigned.length);return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,join(enc.encode('ZTSE/manifest/v2\0'),size,unsigned))));
}
if(process.argv[2]==='--consume'){
 const {fixture:f,signed}=await stdin(),{pin,manifest}=await material(f),accepted=await verifyManifest02(dec(signed),advanceManifestTrust02(pin,manifest),BigInt(f.now)),b=decodeBinding(f.binding);
 authorizeOutbound02(accepted,{accountId:b.account,deviceId:b.device,lineId:b.line,manifestDigest:accepted.digest,keysetVersion:accepted.version,signerKeyId:dec(f.review.keyId),wraps:[{role:1,keyId:b.phoneReader},{role:2,keyId:b.archiveReader}]},BigInt(f.now));
 if(b64(accepted.bytes.slice(0,-64))!==f.review.unsigned)throw Error('different enrollment');process.stdout.write(JSON.stringify({verified:true}));
}else if(process.argv[2]==='--fixture'){
 const f=await stdin();process.stdout.write(JSON.stringify(await fixture(f)));
}else if(process.argv[2]==='--cases'){
 const {fixture:f,cases}=await stdin(),results=[];
 for(const c of cases){const {manifest}=await material(f),binding=decodeBinding(f.binding),events=[];let current={binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:true,consentLive:true};
  const change=()=>{if(c.field.endsWith('Live'))current={...current,[c.field]:false};else if(c.field==='nowMs')current={...current,nowMs:BigInt(f.review.untilMs)};else current={...current,binding:{...binding,[c.field]:c.field==='generation'?2n:c.field==='peer'?'+13':new Uint8Array(c.field.endsWith('Reader')?32:16).fill(9)}};};
  const flow=createConversationEnrollment02(binding,dec(f.point),async()=>{events.push('current');return current;},async()=>{events.push('decision');if(c.decline)throw Error('declined');if(c.stage==='decision')change();return c.decisionValue;},async r=>{events.push('sign');const result=c.badSignature?new Uint8Array(64):await sign(r.unsigned);if(c.stage==='sign')change();return result;},async()=>{events.push('install');if(c.installThrows)throw Error('uncertain');});
  try{await flow.enroll();results.push({accepted:true,events});}catch(error){results.push({accepted:false,events});}
 }
 process.stdout.write(JSON.stringify(results));
}else{
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url))],{encoding:'utf8'}));
 const base={rootPin:f.rootPin,fingerprint:f.fingerprint,manifest:f.manifest,now:f.now};
 if(process.argv[2]==='--root-point'){
  const point=new Uint8Array(Buffer.from(process.argv[3],'hex'));await crypto.subtle.importKey('raw',point,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const pin=dec(f.rootPin),unsigned=dec(f.manifest).slice(0,-64);pin.set(point,29);unsigned.set(point,85);
  const id=await hash(join(enc.encode('ZTSE/key/v1\0'),[1,1],point));for(let n=0;n<unsigned[150];n++){const at=151+n*149;if(unsigned[at]===6){unsigned.set(id,at+1);unsigned.set(point,at+33);}}
  process.stdout.write(JSON.stringify({...base,rootPin:b64(pin),fingerprint:b64(await hash(join(enc.encode('ZTSE/root-pin/v2\0'),pin))),unsigned:b64(unsigned),manifest:null}));
 }else if(process.argv.length===2)process.stdout.write(JSON.stringify(await fixture(base)));else throw Error('unsupported arguments');
}
