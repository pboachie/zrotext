// SPDX-License-Identifier: AGPL-3.0-only
/** Public ZTCF01 exchange for the existing, default-off offline role-5 ceremony.
 * A trusted predecessor and independently compared fingerprint are mandatory.
 * This creates no root/reader keys and never signs or installs anything.
 */
import {browserSignerKeyId02,verifiedManifestIdentity02,verifiedManifestTrust02,verifyManifest02,type Manifest02} from "./draft02-manifest.js";
import type {ConversationEnrollmentReview02} from "./conversation-enrollment.js";
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const join=(...p:Uint8Array[])=>{const b=new Uint8Array(p.reduce((n,v)=>n+v.length,0));let at=0;for(const v of p){b.set(v,at);at+=v.length;}return b;};
const u64=(n:bigint)=>{if(n<=0n||n>=(1n<<63n))throw Error("Offline proposal number refused");const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
const sized=(b:Uint8Array)=>{if(b.length>65535)throw Error("Offline proposal length refused");const n=new Uint8Array(2);new DataView(n.buffer).setUint16(0,b.length);return join(n,b);};
function origin(value:string){const u=new URL(value);if(value.length>512||!/^https:\/\/[\x21-\x7e]+$/.test(value)||u.protocol!=="https:"||u.username||u.password||u.pathname!=="/"||u.search||u.hash||u.origin!==value)throw Error("Offline proposal origin refused");return new TextEncoder().encode(value);}
export async function encodeConversationRefreshProposal02(input:Readonly<{review:ConversationEnrollmentReview02;predecessor:Manifest02;origin:string;comparedRootFingerprint:Uint8Array;nowMs:bigint}>):Promise<Uint8Array>{
 const {nowMs}=input,source=input.review,b=source.binding;
 const binding={...b,account:Uint8Array.from(b.account),session:Uint8Array.from(b.session),interval:Uint8Array.from(b.interval),device:Uint8Array.from(b.device),line:Uint8Array.from(b.line),phoneReader:Uint8Array.from(b.phoneReader),archiveReader:Uint8Array.from(b.archiveReader)};
 const point=Uint8Array.from(source.publicPoint),signer=Uint8Array.from(source.keyId),previous=Uint8Array.from(source.predecessorDigest),unsigned=Uint8Array.from(source.unsigned),fingerprint=Uint8Array.from(input.comparedRootFingerprint),peer=new TextEncoder().encode(binding.peer),ownerOrigin=origin(input.origin),version=source.successorVersion,until=source.untilMs;
 if((["account","session","interval","device","line","phoneReader","archiveReader"] as const).some(k=>binding[k].length!==(k.endsWith("Reader")?32:16)||binding[k].every(v=>v===0))||!/^\+[1-9][0-9]{1,14}$/.test(binding.peer)||point.length!==65||point[0]!==4||signer.length!==32||previous.length!==32||fingerprint.length!==32||fingerprint.every(v=>v===0)||unsigned.length<151||unsigned.length>9687)throw Error("Offline proposal scope refused");
 u64(binding.generation);u64(nowMs);u64(version);u64(until);
 const identity=verifiedManifestIdentity02(input.predecessor,nowMs),trust=verifiedManifestTrust02(input.predecessor,nowMs);
 const predecessor=await verifyManifest02(Uint8Array.from(input.predecessor.bytes),trust,nowMs);
 if(identity.generation!==1n||!same(identity.accountId,binding.account)||version!==identity.version+1n||!same(previous,identity.digest)||!same(signer,await browserSignerKeyId02(point)))throw Error("Offline proposal predecessor refused");
 const pin=join(Uint8Array.of(90,84,82,80,2),identity.accountId,u64(identity.generation),identity.rootPoint);
 const actual=new Uint8Array(await crypto.subtle.digest("SHA-256",join(new TextEncoder().encode("ZTSE/root-pin/v2\0"),pin).buffer));
 if(!same(fingerprint,actual))throw Error("Offline proposal compared root refused");
 const issued=new DataView(unsigned.buffer,unsigned.byteOffset,unsigned.byteLength).getBigUint64(37);
 if(issued<predecessor.issuedMs||issued>nowMs||until<=nowMs||until>predecessor.expiresMs||until-issued>1800000n||predecessor.keys.length>=64||predecessor.keys.some(k=>same(k.keyId,signer)||same(k.point,point)))throw Error("Offline proposal lifetime refused");
 for(const [role,id] of [[1,binding.phoneReader],[2,binding.archiveReader]] as const){const r=predecessor.keys.find(k=>k.role===role&&same(k.keyId,id));if(!r||r.state!==1||r.fromMs>nowMs||r.untilMs<=nowMs||role===1&&(!same(r.deviceId,binding.device)||!same(r.lineId,binding.line)))throw Error("Offline proposal existing reader refused");}
 const records=predecessor.keys.map((_,n)=>Uint8Array.from(predecessor.bytes.subarray(151+n*149,151+(n+1)*149)));
 records.push(join(Uint8Array.of(5),signer,point,new Uint8Array(16),binding.line,Uint8Array.of(0,1),u64(issued),u64(until),Uint8Array.of(1)));
 records.sort((a,c)=>{for(let n=0;n<33;n++){if(a[n]!==c[n])return a[n]-c[n];}return 0;});
 const header=Uint8Array.from(predecessor.bytes.subarray(0,151));header.set(u64(version),29);header.set(u64(issued),37);header.set(previous,53);header[150]=records.length;
 if(!same(unsigned,join(header,...records)))throw Error("Offline proposal modifies existing authority");
 const result=join(Uint8Array.of(90,84,67,70,1),binding.account,binding.session,binding.interval,binding.device,binding.line,u64(binding.generation),Uint8Array.of(peer.length),peer,sized(ownerOrigin),fingerprint,u64(identity.version),previous,binding.phoneReader,binding.archiveReader,signer,point,u64(until),sized(predecessor.bytes),sized(unsigned));
 if(result.length>20480)throw Error("Offline proposal length refused");return result;
}
