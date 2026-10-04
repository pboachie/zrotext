// SPDX-License-Identifier: AGPL-3.0-only
/** Bounded profile-02 inbound opening. Historical authority must come from an accepted manifest. */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { decodeBodyText, keyId, parseDraftEnvelope, type DraftEnvelope } from "./draft01.js";
import { authorizeInbound02, canonicalSignature02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02 } from "./draft02-manifest.js";
import { acceptedOriginalReplySelection, type OriginalReplySelection } from "./original-reply-selection.js";
const enc=new TextEncoder();
const ab=(b:Uint8Array):ArrayBuffer=>Uint8Array.from(b).buffer;
const same=(a:Uint8Array,b:Uint8Array)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const join=(...p:Uint8Array[])=>{const out=new Uint8Array(p.reduce((n,b)=>n+b.length,0));let at=0;for(const b of p){out.set(b,at);at+=b.length;}return out;};
const label=(s:string)=>enc.encode(s+"\0");
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
/** Reuse the identical bounded wire grammar, restoring the actual authenticated profile bytes. */
export function parseConversationInbound02(input:Uint8Array):DraftEnvelope {
 const bytes=Uint8Array.from(input);
 if(bytes.length>34082||bytes[4]!==2||bytes[5]!==2)throw Error("Conversation inbound profile");
 const grammar=Uint8Array.from(bytes);grammar[4]=1;
 const parsed=parseDraftEnvelope(grammar);
 if(!same(parsed.signature,canonicalSignature02(parsed.signature)))throw Error("Conversation signature canonicality");
 return {...parsed,bytes,unsigned:bytes.subarray(0,parsed.unsigned.length)};
}
export type ConversationReadContext02=Readonly<{
 account:Uint8Array;device:Uint8Array;line:Uint8Array;peer:string;archiveReader:Uint8Array;
 archivePrivateKey:CryptoKey;historical:Manifest02;current:Manifest02;nowMs:bigint;
 /** Required for captures with explicitly phone-approved integration wraps. */
 interval?:Uint8Array;selection?:OriginalReplySelection;
}>;
/** Verifies historic signer/wrap authority at receipt time and CURRENT reader authority before opening.
 * The historical manifest must already have accepted chain provenance; this function never pins a root.
 */
export async function openConversationInbound02(input:Uint8Array,context:ConversationReadContext02):Promise<string>{
 const c={...context,account:Uint8Array.from(context.account),device:Uint8Array.from(context.device),line:Uint8Array.from(context.line),archiveReader:Uint8Array.from(context.archiveReader),interval:context.interval?Uint8Array.from(context.interval):undefined};
 const p=parseConversationInbound02(input),identity=verifiedManifestIdentity02(c.current,c.nowMs);
 if(!same(p.accountId,c.account)||!same(p.deviceId,c.device)||!same(p.lineId,c.line)||p.peer!==c.peer||p.observedMs<=0n||p.observedMs>c.nowMs)throw Error("Conversation inbound scope");
 // Reparse from the verifier's immutable snapshot, never authorize mutable caller-held records.
 const current=await verifyManifest02(Uint8Array.from(c.current.bytes),verifiedManifestTrust02(c.current,c.nowMs),c.nowMs);
 const historical=await verifyManifest02(Uint8Array.from(c.historical.bytes),verifiedManifestTrust02(c.historical,p.observedMs),p.observedMs);
 const old=verifiedManifestIdentity02(historical,p.observedMs);
 if(!same(identity.accountId,c.account)||identity.generation!==old.generation||!same(identity.rootPoint,old.rootPoint)||old.version>identity.version)throw Error("Conversation history root");
 if(c.selection){
  const selection=acceptedOriginalReplySelection(c.selection);
  if(!c.interval||!same(selection.account,c.account)||!same(selection.device,c.device)||!same(selection.line,c.line)||!same(selection.interval,c.interval)||selection.peer!==c.peer||!same(selection.archiveReader,c.archiveReader)||selection.rootGeneration!==identity.generation||old.version<selection.activationVersion)throw Error("Conversation selected readers");
  const expected=[{role:2,keyId:selection.archiveReader},...selection.readers.map(r=>({role:3,keyId:r.reader}))];
  if(p.wraps.length!==expected.length||!expected.every(e=>p.wraps.some(w=>w.role===e.role&&same(w.keyId,e.keyId))))throw Error("Conversation selected wraps");
 }else if(p.wraps.length!==1||p.wraps[0].role!==2||!same(p.wraps[0].keyId,c.archiveReader))throw Error("Conversation archive-only wraps");
 const reader=current.keys.find(k=>k.role===2&&same(k.keyId,c.archiveReader));
 if(!reader||reader.state!==1||!(reader.scope&8)||reader.fromMs>c.nowMs||c.nowMs>=reader.untilMs)throw Error("Conversation current reader revoked");
 authorizeInbound02(historical,{kind:2,accountId:p.accountId,deviceId:p.deviceId,lineId:p.lineId,messageId:p.messageId,eventId:p.eventId!,localSequence:p.localSequence!,manifestDigest:p.manifestDigest,keysetVersion:p.keysetVersion,signerKeyId:p.signerKeyId,wraps:p.wraps},p.observedMs);
 const signer=historical.keys.find(k=>k.role===4&&same(k.keyId,p.signerKeyId));
 if(!signer||!same(await keyId(0x0101,signer.point),p.signerKeyId))throw Error("Conversation inbound signer");
 const publicKey=await crypto.subtle.importKey("raw",ab(signer.point),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
 const length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,p.unsigned.length);
 if(!await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},publicKey,ab(p.signature),ab(join(label("ZTSE/sign/v2"),length,p.unsigned))))throw Error("Conversation origin signature");
 for(const w of p.wraps)await suite.kem.deserializePublicKey(ab(w.enc));
 const wrap=p.wraps.find(w=>w.role===2&&same(w.keyId,c.archiveReader));
 if(!wrap)throw Error("Conversation archive wrap missing");
 const info=join(label("ZTSE/wrap/v2"),p.bytes.subarray(0,10),p.protected,Uint8Array.of(2),wrap.keyId);
 const archivePublic=await crypto.subtle.importKey("raw",ab(reader.point),{name:"ECDH",namedCurve:"P-256"},true,[]);
 // Supply the manifest-authenticated point as well as the existing nonextractable private key:
 // reconstructing a public point from bare ECDH custody can lose its actual Y parity.
 const recipient=await suite.createRecipientContext({recipientKey:{privateKey:c.archivePrivateKey,publicKey:archivePublic},enc:ab(wrap.enc),info:ab(info)});
 let cek:Uint8Array|null=null,body:Uint8Array|null=null;
 try {
  cek=new Uint8Array(await recipient.open(ab(wrap.ct),new ArrayBuffer(0)));if(cek.length!==32)throw Error("Conversation content key");
  const key=await crypto.subtle.importKey("raw",ab(cek),"AES-GCM",false,["decrypt"]);
  body=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:ab(p.nonce),additionalData:ab(join(label("ZTSE/body/v2"),p.bytes.subarray(0,10),p.protected)),tagLength:128},key,ab(p.bodyCt)));
  return decodeBodyText(body);
 }finally{cek?.fill(0);body?.fill(0);}
}
