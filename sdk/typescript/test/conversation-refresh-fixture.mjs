// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic synthetic public context shared by codec/native interoperability fixtures.
import {webcrypto,createECDH,createHash} from "node:crypto";
import {canonicalSignature02,enrollRootPin02,verifyManifest02} from "../dist/draft02-manifest.js";
import {createConversationEnrollment02} from "../dist/conversation-enrollment.js";
globalThis.crypto??=webcrypto;
const enc=new TextEncoder();
export const join=(...p)=>new Uint8Array(Buffer.concat(p.map(v=>Buffer.from(v))));
const u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
const hash=b=>new Uint8Array(createHash("sha256").update(b).digest());
function point(n){const scalar=Buffer.alloc(32);scalar[31]=n;const key=createECDH("prime256v1");key.setPrivateKey(scalar);scalar.fill(0);return new Uint8Array(key.getPublicKey(undefined,"uncompressed"));}
const id=(role,p)=>hash(join(enc.encode("ZTSE/key/v1\0"),Uint8Array.of(role<=3?0:1,role<=3?16:1),p));
export async function refreshFixture(nowMs=2000n){
 if(nowMs<=1000n)throw Error("Synthetic fixture clock");
 const account=new Uint8Array(16).fill(1),device=new Uint8Array(16).fill(4),line=new Uint8Array(16).fill(5),zero=new Uint8Array(16),rootPoint=point(1),issued=nowMs-1000n,expires=nowMs+3600000n;
 const pin=join(enc.encode("ZTRP"),Uint8Array.of(2),account,u64(1n),rootPoint),fingerprint=hash(join(enc.encode("ZTSE/root-pin/v2\0"),pin));
 const records=[{role:1,n:2,device,line,scope:4},{role:2,n:3,device:zero,line:zero,scope:12},{role:4,n:4,device,line,scope:2},{role:6,n:1,device:zero,line:zero,scope:0}].map(r=>({...r,point:point(r.n),id:id(r.role,point(r.n))}));
 const unsigned=join(enc.encode("ZTMA"),Uint8Array.of(2),account,u64(1n),u64(7n),u64(issued),u64(expires),new Uint8Array(32).fill(9),rootPoint,Uint8Array.of(4),...records.map(r=>join(Uint8Array.of(r.role),r.id,r.point,r.device,r.line,Uint8Array.of(0,r.scope),u64(issued),u64(expires),Uint8Array.of(1))));
 const scalar=new Uint8Array(32);scalar[31]=1;const base64=b=>Buffer.from(b).toString("base64url");
 const root=await crypto.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:base64(rootPoint.subarray(1,33)),y:base64(rootPoint.subarray(33)),d:base64(scalar)}, {name:"ECDSA",namedCurve:"P-256"},false,["sign"]);scalar.fill(0);
 const length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,unsigned.length);
 const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},root,join(enc.encode("ZTSE/manifest/v2\0"),length,unsigned))));
 // Independently defined synthetic durable high-water, never copied from a projection.
 const trust={...await enrollRootPin02(pin,fingerprint),version:6n,digest:new Uint8Array(32).fill(9)};
 const predecessor=await verifyManifest02(join(unsigned,signature),trust,nowMs);
 const binding={account,device,line,session:new Uint8Array(16).fill(2),interval:new Uint8Array(16).fill(3),generation:1n,peer:"+12",phoneReader:records[0].id,archiveReader:records[1].id};
 let review;
 const enrollment=createConversationEnrollment02(binding,point(5),async()=>({binding,manifest:predecessor,nowMs,ownerSessionLive:true,consentLive:true}),async()=>{},async r=>{review=r;throw Error("Synthetic offline file pause");},async()=>{throw Error("Unexpected fixture installation");});
 try{await enrollment.enroll();}catch(error){if(error.message!=="Synthetic offline file pause")throw error;}
 if(!review)throw Error("Synthetic review unavailable");
 return {review,predecessor,origin:"https://owner.invalid",comparedRootFingerprint:fingerprint,nowMs};
}

export async function signFixtureSuccessor02(f,unsigned=f.review.unsigned){
 const rootPoint=point(1),scalar=new Uint8Array(32);scalar[31]=1;const b64=b=>Buffer.from(b).toString("base64url"),key=await crypto.subtle.importKey("jwk",{kty:"EC",crv:"P-256",x:b64(rootPoint.subarray(1,33)),y:b64(rootPoint.subarray(33)),d:b64(scalar)},{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);scalar.fill(0);const n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,unsigned.length);return join(unsigned,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,join(enc.encode("ZTSE/manifest/v2\0"),n,unsigned)))));
}
