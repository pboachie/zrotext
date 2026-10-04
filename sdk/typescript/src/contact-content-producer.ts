// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant historical commitment production. No recovery, custody, storage or current authority. */
import {canonicalSignature02} from './draft02-manifest.js';
import {verifiedContactReaderStatementIdentity01,type VerifiedContactReaderStatement,type ContactReaderStatementIdentity01} from './contact-reader-statement.js';
import {encodeContactFieldUnsigned01,encodeContactMutationUnsigned01,verifyContactField01,verifyContactMutation01,verifyContactTransition01,verifiedContactFieldIdentity01,verifiedContactTransitionIdentity01,type ContactMutationUnsigned01,type ContactSlot01,type VerifiedHistoricalField,type VerifiedHistoricalTransition} from './contact-content-contract.js';

type Expected=Readonly<{accountId:Uint8Array;origin:string;rootFingerprint:Uint8Array;contactId:Uint8Array;routingDigest:Uint8Array}>;
type Field=Readonly<{kind:1|2;sealRevision:bigint;requestId:Uint8Array;encapsulation:Uint8Array;ciphertext:Uint8Array}>;
type Common=Readonly<{rootPrivateKey:CryptoKey;statement:VerifiedContactReaderStatement;expected:Expected;signal:AbortSignal}>;
export type ContactFieldProduction01=Common&Readonly<{field:Field}>;
export type ContactMutationProduction01=Omit<Common,'expected'>&Readonly<{expected:Expected&Readonly<{legacyGeneration:bigint}>;mutation:ContactMutationUnsigned01;previous:VerifiedHistoricalTransition|null;previousStatement:VerifiedContactReaderStatement|null;replacementFields:readonly VerifiedHistoricalField[]}>;
const enc=new TextEncoder(),max=(1n<<63n)-1n;
let outstanding=0;
function fail():never{throw Error('Contact producer refused');}
function same(a:Uint8Array,b:Uint8Array){return a.length===b.length&&a.every((v,i)=>v===b[i]);}
function data(v:unknown,names:readonly string[]):Record<string,any>{
 if(!v||Object.getPrototypeOf(v)!==Object.prototype)fail();const ks=Reflect.ownKeys(v);
 if(ks.length!==names.length||ks.some(k=>typeof k!=='string'||!names.includes(k)))fail();
 const out:Record<string,any>={};for(const k of names){const d=Object.getOwnPropertyDescriptor(v,k);if(!d||!Object.hasOwn(d,'value'))fail();out[k]=d.value;}return out;
}
function bytes(v:unknown,n:number,zero=false){if(!(v instanceof Uint8Array)||v.length!==n||!zero&&v.every(x=>x===0))fail();return Uint8Array.from(v);}
function integer(v:unknown,zero=false):bigint{if(typeof v!=='bigint'||v<(zero?0n:1n)||v>max)fail();return v;}
function origin(v:unknown):string{if(typeof v!=='string'||v.length<9||v.length>512||/[^\x21-\x7e]/.test(v))fail();let u:URL;try{u=new URL(v);}catch{return fail();}if(u.protocol!=='https:'||u.origin!==v||u.username||u.password||u.pathname!=='/'||u.search||u.hash)fail();return v;}
function expected(v:unknown,legacy=false){const e=data(v,['accountId','origin','rootFingerprint','contactId','routingDigest',...(legacy?['legacyGeneration']:[])]);return {accountId:bytes(e.accountId,16),origin:origin(e.origin),rootFingerprint:bytes(e.rootFingerprint,32),contactId:bytes(e.contactId,16),routingDigest:bytes(e.routingDigest,32),legacyGeneration:legacy?integer(e.legacyGeneration,true):0n};}
function key(v:unknown):CryptoKey{
 // Native getters perform their runtime CryptoKey brand checks without invoking
 // properties supplied by an arbitrary object or a caller-owned override.
 try{const get=(n:string)=>Object.getOwnPropertyDescriptor(CryptoKey.prototype,n)!.get!.call(v);
  const a=data(get('algorithm'),['name','namedCurve']),usages=get('usages');
  if(get('type')!=='private'||get('extractable')!==false||a.name!=='ECDSA'||a.namedCurve!=='P-256'||usages.length!==1||usages[0]!=='sign')fail();
 }catch{return fail();}return v as CryptoKey;
}
function aborted(v:AbortSignal):boolean{return Object.getOwnPropertyDescriptor(AbortSignal.prototype,'aborted')!.get!.call(v);}
function signal(v:unknown):AbortSignal{try{if(aborted(v as AbortSignal))fail();}catch{return fail();}return v as AbortSignal;}
function scoped(s:ContactReaderStatementIdentity01,e:ReturnType<typeof expected>){if(!same(s.accountId,e.accountId)||s.origin!==e.origin||!same(s.rootFingerprint,e.rootFingerprint)||s.trustGeneration!==1n)fail();}
function join(...parts:Uint8Array[]){const b=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){b.set(p,at);at+=p.length;}return b;}
function buffer(b:Uint8Array){return Uint8Array.from(b).buffer;}
function transcript(domain:string,unsigned:Uint8Array){const length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,unsigned.length);return join(enc.encode(domain+'\0'),length,unsigned);}
function slot(v:unknown):ContactSlot01{const s=data(v,['tag','sealRevision','digest']);if(s.tag!==0&&s.tag!==1)fail();return {tag:s.tag,sealRevision:integer(s.sealRevision,true),digest:bytes(s.digest,32,true)};}
function equalSlot(a:ContactSlot01,b:ContactSlot01){return a.tag===b.tag&&a.sealRevision===b.sealRevision&&same(a.digest,b.digest);}
const mutationNames=['operation','accountId','contactId','expectedRevision','revision','requestId','previousDigest','trustGeneration','manifestVersion','manifestDigest','statementDigest','routingDigest','legacyGeneration','name','notes'];
function mutation(v:unknown):ContactMutationUnsigned01{const m=data(v,mutationNames);return {operation:m.operation,accountId:bytes(m.accountId,16),contactId:bytes(m.contactId,16),expectedRevision:integer(m.expectedRevision,true),revision:integer(m.revision),requestId:bytes(m.requestId,16),previousDigest:bytes(m.previousDigest,32,true),trustGeneration:integer(m.trustGeneration) as 1n,manifestVersion:integer(m.manifestVersion),manifestDigest:bytes(m.manifestDigest,32),statementDigest:bytes(m.statementDigest,32),routingDigest:bytes(m.routingDigest,32),legacyGeneration:integer(m.legacyGeneration,true),name:slot(m.name),notes:slot(m.notes)};}
function replacements(v:unknown):VerifiedHistoricalField[]{
 if(!Array.isArray(v)||Object.getPrototypeOf(v)!==Array.prototype||v.length>2||Reflect.ownKeys(v).length!==v.length+1)fail();
 const out:VerifiedHistoricalField[]=[];for(let at=0;at<v.length;at++){const d=Object.getOwnPropertyDescriptor(v,String(at));if(!d||!Object.hasOwn(d,'value'))fail();verifiedContactFieldIdentity01(d.value);out.push(d.value);}return out;
}
type Work={live:()=>void;step:<T>(p:Promise<T>)=>Promise<T>;own:(b:Uint8Array)=>Uint8Array};
function operation<T>(abort:AbortSignal,initial:Uint8Array,run:(work:Work)=>Promise<T>):Promise<T>{
 if(outstanding>=4||aborted(abort)){initial.fill(0);return Promise.reject(Error('Contact producer refused'));}
 outstanding++;const deadline=performance.now()+10000;let closed=false,timer:ReturnType<typeof setTimeout>;const held:Uint8Array[]=[initial];
 let refuse!:()=>void;const stopped=new Promise<never>((_,reject)=>{refuse=()=>{if(closed)return;closed=true;for(const b of held)b.fill(0);reject(Error('Contact producer refused'));};});
 const live=()=>{if(closed||aborted(abort)||performance.now()>=deadline)fail();};
 const onAbort=()=>refuse();EventTarget.prototype.addEventListener.call(abort,'abort',onAbort,{once:true});timer=setTimeout(refuse,10000);
 const work:Work={live,own:b=>{held.push(b);return b;},step:async p=>{const result=await p;live();return result;}};
 // Racing outward settlement never releases the unresolved work's admission.
 const pending=Promise.resolve().then(()=>{live();return run(work);});
 const cleanup=()=>{closed=true;clearTimeout(timer);EventTarget.prototype.removeEventListener.call(abort,'abort',onAbort);for(const b of held)b.fill(0);held.length=0;outstanding--;};
 pending.then(cleanup,cleanup);return Promise.race([pending,stopped]);
}
async function sign(k:CryptoKey,unsigned:Uint8Array,domain:string,w:Work){w.live();const t=w.own(transcript(domain,unsigned));const raw=new Uint8Array(await w.step(crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k,buffer(t))));w.own(raw);const canonical=w.own(canonicalSignature02(raw));return w.own(join(unsigned,canonical));}

/** Already encrypted bytes only. Historical matching-key integrity, not custody or current permission. */
export async function produceContactFieldCommitment01(input:ContactFieldProduction01){
 const i=data(input,['rootPrivateKey','statement','expected','field','signal']),k=key(i.rootPrivateKey),abort=signal(i.signal),s=verifiedContactReaderStatementIdentity01(i.statement),e=expected(i.expected);scoped(s,e);
 const f=data(i.field,['kind','sealRevision','requestId','encapsulation','ciphertext']);if(!(f.ciphertext instanceof Uint8Array)||f.ciphertext.length<17||f.ciphertext.length>(f.kind===1?272:2064))fail();
 const unsigned=encodeContactFieldUnsigned01({kind:f.kind,accountId:e.accountId,contactId:e.contactId,sealRevision:integer(f.sealRevision),trustGeneration:1n,manifestVersion:s.manifestVersion,readerGeneration:s.readerGeneration,readerId:s.readerId,manifestDigest:s.manifestDigest,statementDigest:s.digest,routingDigest:e.routingDigest,requestId:bytes(f.requestId,16),rootWriterId:s.rootWriterId,encapsulation:bytes(f.encapsulation,65),ciphertext:Uint8Array.from(f.ciphertext)});
 const statement=i.statement as VerifiedContactReaderStatement;
 return operation(abort,unsigned,async w=>{await w.step(crypto.subtle.importKey('raw',buffer(unsigned.slice(246,311)),{name:'ECDSA',namedCurve:'P-256'},false,['verify']));const signed=await sign(k,unsigned,'ZT/contact-field/commitment/v1',w);
  const verified=await w.step(verifyContactField01({bytes:signed,statement,expectedContactId:e.contactId,expectedRoutingDigest:e.routingDigest}));w.live();return Object.freeze({kind:'produced_historical_integrity' as const,bytes:Uint8Array.from(signed),verified});});
}
/** Exact genuine predecessor and statements only; no structural restoration or stored-history query. */
export async function produceContactMutationTransition01(input:ContactMutationProduction01){
 const i=data(input,['rootPrivateKey','statement','expected','mutation','previous','previousStatement','replacementFields','signal']),k=key(i.rootPrivateKey),abort=signal(i.signal),s=verifiedContactReaderStatementIdentity01(i.statement),e=expected(i.expected,true);scoped(s,e);
 const m=mutation(i.mutation),unsigned=encodeContactMutationUnsigned01(m),fs=replacements(i.replacementFields),ids=fs.map(verifiedContactFieldIdentity01);
 if(!same(m.accountId,e.accountId)||!same(m.contactId,e.contactId)||!same(m.routingDigest,e.routingDigest)||m.legacyGeneration!==e.legacyGeneration||m.trustGeneration!==s.trustGeneration||m.manifestVersion!==s.manifestVersion||!same(m.manifestDigest,s.manifestDigest)||!same(m.statementDigest,s.digest))fail();
 let prior:ReturnType<typeof verifiedContactTransitionIdentity01>|null=null;
 if(i.previous===null){if(i.previousStatement!==null||m.operation===2)fail();}
 else{prior=verifiedContactTransitionIdentity01(i.previous);const ps=verifiedContactReaderStatementIdentity01(i.previousStatement);scoped(ps,e);
  if(m.operation!==2||m.expectedRevision!==prior.revision||!same(m.previousDigest,prior.digest)||!same(prior.accountId,ps.accountId)||!same(prior.contactId,e.contactId)||!same(prior.routingDigest,e.routingDigest)||prior.trustGeneration!==ps.trustGeneration||prior.manifestVersion!==ps.manifestVersion||!same(prior.manifestDigest,ps.manifestDigest)||!same(prior.statementDigest,ps.digest)||s.manifestVersion<ps.manifestVersion||s.manifestVersion===ps.manifestVersion&&!same(s.manifestDigest,ps.manifestDigest)||s.readerGeneration<ps.readerGeneration||s.readerGeneration===ps.readerGeneration&&(!same(s.readerId,ps.readerId)||!same(s.readerPoint,ps.readerPoint)))fail();
 }
 if(new Set(ids.map(f=>f.kind)).size!==ids.length)fail();let used=0;
 for(const[kind,name]of [[1,'name'],[2,'notes']] as const){const sl=m[name];if(sl.tag===0)continue;
  if(sl.sealRevision!==m.revision){if(!prior||!equalSlot(sl,prior[name]))fail();continue;}
  const f=ids.find(f=>f.kind===kind);if(!f||!same(f.accountId,e.accountId)||!same(f.contactId,e.contactId)||!same(f.routingDigest,e.routingDigest)||!same(f.digest,sl.digest)||f.sealRevision!==m.revision||!same(f.requestId,m.requestId)||f.trustGeneration!==s.trustGeneration||f.manifestVersion!==s.manifestVersion||!same(f.manifestDigest,s.manifestDigest)||!same(f.statementDigest,s.digest)||f.readerGeneration!==s.readerGeneration||!same(f.readerId,s.readerId)||!same(f.rootWriterId,s.rootWriterId))fail();used++;
 }
 if(used!==fs.length)fail();const statement=i.statement as VerifiedContactReaderStatement,previous=i.previous as VerifiedHistoricalTransition|null;
 return operation(abort,unsigned,async w=>{const signed=await sign(k,unsigned,'ZT/contact-field/mutation/v1',w);const next=await w.step(verifyContactMutation01({bytes:signed,statement,expectedContactId:e.contactId,expectedRoutingDigest:e.routingDigest,expectedLegacyGeneration:e.legacyGeneration}));
  const verified=verifyContactTransition01({previous,next,replacementFields:fs});w.live();return Object.freeze({kind:'produced_historical_integrity' as const,bytes:Uint8Array.from(signed),verified});});
}
