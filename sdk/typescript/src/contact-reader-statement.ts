// SPDX-License-Identifier: AGPL-3.0-only
/** Dormant historical signed-statement integrity. No installed access or custody. */
import {canonicalSignature02, verifiedAccountArchiveStatementRecords02, type Manifest02} from './draft02-manifest.js';
const encoder = new TextEncoder(), max = (1n << 63n) - 1n;
const names = ['authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration',
  'rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability'] as const;
export type ContactReaderStatementUnsigned01 = Readonly<{
  authorizationId: Uint8Array; accountId: Uint8Array; origin: string; trustGeneration: bigint;
  manifestVersion: bigint; readerGeneration: bigint; rootFingerprint: Uint8Array;
  manifestDigest: Uint8Array; readerId: Uint8Array; readerPoint: Uint8Array;
  issuedMs: bigint; untilMs: bigint; capability: 3;
}>;
export type ParsedContactReaderStatement01 = ContactReaderStatementUnsigned01 & Readonly<{
  bytes: Uint8Array; unsigned: Uint8Array; signature: Uint8Array;
}>;
export type VerifiedContactReaderStatement = Readonly<{kind: 'historical_integrity'}>;
export type ContactReaderStatementIdentity01 = ParsedContactReaderStatement01 & Readonly<{
  digest: Uint8Array; rootWriterId: Uint8Array; rootPoint: Uint8Array;
  readerFromMs: bigint; readerUntilMs: bigint; rootFromMs: bigint; rootUntilMs: bigint;
}>;
const accepted = new WeakMap<VerifiedContactReaderStatement, ContactReaderStatementIdentity01>();
function fail(): never {throw Error('Contact reader statement refused');}
function same(a: Uint8Array,b: Uint8Array): boolean {return a.length===b.length&&a.every((v,i)=>v===b[i]);}
function copy(b: Uint8Array): ArrayBuffer {return Uint8Array.from(b).buffer;}
function join(...p: Uint8Array[]): Uint8Array {
  const b=new Uint8Array(p.reduce((n,v)=>n+v.length,0));let at=0;for(const v of p){b.set(v,at);at+=v.length;}return b;
}
function data(value: unknown, fields: readonly string[]): Record<string,any> {
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)fail();
  const keys=Reflect.ownKeys(value);if(keys.length!==fields.length||keys.some(k=>typeof k!=='string'||!fields.includes(k)))fail();
  const result:Record<string,any>={};for(const k of fields){const d=Object.getOwnPropertyDescriptor(value,k);if(!d||!Object.hasOwn(d,'value'))fail();result[k]=d.value;}return result;
}
function fixed(value: unknown,n: number): Uint8Array {
  if(!(value instanceof Uint8Array)||value.length!==n||!value.some(v=>v!==0))fail();return Uint8Array.from(value);
}
function u64(n: unknown): Uint8Array {
  if(typeof n!=='bigint'||n<1n||n>max)fail();const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;
}
function origin(value: unknown): Uint8Array {
  if(typeof value!=='string'||value.length<9||value.length>512||/[^\x21-\x7e]/.test(value))fail();
  let url:URL;try{url=new URL(value);}catch{return fail();}
  if(url.protocol!=='https:'||url.origin!==value||url.username||url.password||url.pathname!=='/'||url.search||url.hash)fail();return encoder.encode(value);
}
function capture(input: unknown): ContactReaderStatementUnsigned01 {
  const s=data(input,names);for(const k of ['authorizationId','accountId'])s[k]=fixed(s[k],16);
  for(const k of ['rootFingerprint','manifestDigest','readerId'])s[k]=fixed(s[k],32);
  s.readerPoint=fixed(s.readerPoint,65);if(s.readerPoint[0]!==4||s.capability!==3||s.trustGeneration!==1n)fail();
  for(const k of ['trustGeneration','manifestVersion','readerGeneration','issuedMs','untilMs'])u64(s[k]);
  origin(s.origin);if(s.untilMs<=s.issuedMs||s.untilMs-s.issuedMs>86400000n)fail();return s as ContactReaderStatementUnsigned01;
}
/** Synchronous public unsigned framing only; no curve-membership or trust proof. */
export function encodeContactReaderStatementUnsigned01(input: ContactReaderStatementUnsigned01): Uint8Array {
  const s=capture(input),o=origin(s.origin),length=new Uint8Array(2);new DataView(length.buffer).setUint16(0,o.length);
  return join(encoder.encode('ZTKA'),Uint8Array.of(1,3),s.authorizationId,s.accountId,length,o,
    ...[s.trustGeneration,s.manifestVersion,s.readerGeneration].map(u64),s.rootFingerprint,s.manifestDigest,
    s.readerId,s.readerPoint,u64(s.issuedMs),u64(s.untilMs));
}
function snapshot<T extends object>(value: T): T {
  const out:Record<string,unknown>={};for(const [k,v]of Object.entries(value)){
    if(v instanceof Uint8Array){const b=Uint8Array.from(v);Object.defineProperty(out,k,{enumerable:true,get:()=>Uint8Array.from(b)});}
    else Object.defineProperty(out,k,{enumerable:true,value:v});
  }return Object.freeze(out) as T;
}
async function hash(bytes: Uint8Array): Promise<Uint8Array> {return new Uint8Array(await crypto.subtle.digest('SHA-256',copy(bytes)));}
/** Captures bytes synchronously; maintained WebCrypto validates actual P256 membership. */
export async function parseContactReaderStatement01(input: Uint8Array): Promise<ParsedContactReaderStatement01> {
  if(!(input instanceof Uint8Array)||input.length<314||input.length>817)fail();const bytes=Uint8Array.from(input),v=new DataView(bytes.buffer);
  if(!same(bytes.slice(0,6),encoder.encode('ZTKA\x01\x03')))fail();const n=v.getUint16(38);if(n<9||n>512||bytes.length!==305+n)fail();
  let at=40+n;const number=()=>{const value=v.getBigUint64(at);at+=8;return value;};const field=(width:number)=>{const b=bytes.slice(at,at+width);at+=width;return b;};
  const s=capture({authorizationId:bytes.slice(6,22),accountId:bytes.slice(22,38),origin:new TextDecoder('utf-8',{fatal:true}).decode(bytes.slice(40,40+n)),
    trustGeneration:number(),manifestVersion:number(),readerGeneration:number(),rootFingerprint:field(32),manifestDigest:field(32),readerId:field(32),readerPoint:field(65),issuedMs:number(),untilMs:number(),capability:3});
  const unsigned=encodeContactReaderStatementUnsigned01(s),signature=bytes.slice(at);
  if(!same(unsigned,bytes.slice(0,at))||!same(signature,canonicalSignature02(signature)))fail();
  await crypto.subtle.importKey('raw',copy(s.readerPoint),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const readerId=await hash(join(encoder.encode('ZTSE/key/v1\0'),Uint8Array.of(0,16),s.readerPoint));if(!same(readerId,s.readerId))fail();
  return snapshot({...s,bytes,unsigned,signature});
}
export async function verifyContactReaderStatement01(input: {
  bytes: Uint8Array; acceptedManifest: Manifest02; expectedAccountId: Uint8Array;
  expectedOrigin: string; expectedRootFingerprint: Uint8Array; comparison: 'declared_issued_ms';
}): Promise<VerifiedContactReaderStatement> {
  const i=data(input,['bytes','acceptedManifest','expectedAccountId','expectedOrigin','expectedRootFingerprint','comparison']);
  if(!(i.bytes instanceof Uint8Array)||i.bytes.length<314||i.bytes.length>817)fail();
  const bytes=Uint8Array.from(i.bytes),account=fixed(i.expectedAccountId,16),fingerprint=fixed(i.expectedRootFingerprint,32);
  origin(i.expectedOrigin);if(i.comparison!=='declared_issued_ms')fail();
  const s=await parseContactReaderStatement01(bytes),m=verifiedAccountArchiveStatementRecords02(i.acceptedManifest,s.readerId,s.issuedMs);
  if(!same(s.accountId,account)||!same(m.accountId,account)||s.origin!==i.expectedOrigin||s.trustGeneration!==m.generation||s.manifestVersion!==m.version||!same(s.manifestDigest,m.digest)||!same(s.readerPoint,m.readerPoint)
    ||s.issuedMs<m.issuedMs||s.untilMs>m.expiresMs||s.untilMs>m.readerUntilMs||s.untilMs>m.rootUntilMs)fail();
  const pin=join(encoder.encode('ZTRP'),Uint8Array.of(2),account,u64(1n),m.rootPoint),actual=await hash(join(encoder.encode('ZTSE/root-pin/v2\0'),pin));
  if(!same(actual,fingerprint)||!same(s.rootFingerprint,fingerprint))fail();
  const key=await crypto.subtle.importKey('raw',copy(m.rootPoint),{name:'ECDSA',namedCurve:'P-256'},false,['verify']),length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,s.unsigned.length);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,copy(s.signature),copy(join(encoder.encode('ZT/contact-reader/authorization/v1\0'),length,s.unsigned))))fail();
  const result=Object.freeze({kind:'historical_integrity' as const});accepted.set(result,snapshot({...s,digest:await hash(s.bytes),rootWriterId:m.rootWriterId,rootPoint:m.rootPoint,readerFromMs:m.readerFromMs,readerUntilMs:m.readerUntilMs,rootFromMs:m.rootFromMs,rootUntilMs:m.rootUntilMs}));return result;
}
export function verifiedContactReaderStatementIdentity01(result: VerifiedContactReaderStatement): ContactReaderStatementIdentity01 {
  const identity=accepted.get(result);if(!identity)fail();return snapshot(identity);
}
