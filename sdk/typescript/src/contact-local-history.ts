// SPDX-License-Identifier: AGPL-3.0-only
/** Unmounted application-owned local history. No current authority or integrity-brand restoration. */
import { Draft02TrustStore, type Draft02TrustSnapshot } from './draft02-trust-store.js';
import { enrollRootPin02, verifiedManifestIdentity02, verifiedAccountArchiveStatementRecords02 } from './draft02-manifest.js';
import { verifiedContactTransitionIdentity01, type VerifiedHistoricalTransition } from './contact-content-contract.js';
import { verifiedContactReaderStatementIdentity01, type VerifiedContactReaderStatement } from './contact-reader-statement.js';

const max = (1n << 63n) - 1n, records = 'contacts', headerKey = 'scope', databaseName = 'ztse-contact-local-history-v1';
const operationMs = 10_000, lifetimeMs = 30 * 60_000;
let permits = 0;
type Slot = Readonly<{tag: 0|1; sealRevision: bigint; digest: Uint8Array}>;
type RootStamp = Readonly<{version: bigint; digest: Uint8Array; anchorDigest: Uint8Array; time: bigint}>;
type Header = {schema: 1; accountId: Uint8Array; rootPoint: Uint8Array; rootFingerprint: Uint8Array;
  origin: string; maximumRecords: number; count: number};
export type ContactAcceptedMetadata01 = Readonly<{schema: 1; state: 'accepted'; contactId: Uint8Array;
  revision: bigint; digest: Uint8Array; requestId: Uint8Array; routingDigest: Uint8Array; name: Slot; notes: Slot;
  statementDigest: Uint8Array; manifestVersion: bigint; manifestDigest: Uint8Array; readerId: Uint8Array;
  readerGeneration: bigint; rootWriterId: Uint8Array; comparisonMs: bigint; rootStamp: RootStamp}>;
type Row = ContactAcceptedMetadata01 | {schema: 1; state: 'unavailable'; contactId: Uint8Array};
export type ContactLocalRecordToken01 = Readonly<{kind: 'local_record'}>;
type UnavailableReason01 = 'unobserved'|'local_stop'|'history_missing'|'root_mismatch'|'corrupt'|'reduction_only';
export type ContactHistoryLookup01 = Readonly<{kind: 'accepted_local_history'; token: ContactLocalRecordToken01;
  metadata: ContactAcceptedMetadata01; evidence: 'available'}> | Readonly<{kind: 'unavailable'; reason: UnavailableReason01;
  token?: ContactLocalRecordToken01}>;
export type ContactHistoryWrite01 = ContactHistoryLookup01 | Readonly<{kind: 'recorded_needs_recheck'|'write_unknown'}>;
export type ContactLocalHistory01 = Readonly<{
  lookup(contactId: Uint8Array): Promise<ContactHistoryLookup01>;
  accept(input: Readonly<{expected: ContactLocalRecordToken01|null; transition: VerifiedHistoricalTransition;
    statement: VerifiedContactReaderStatement}>): Promise<ContactHistoryWrite01>;
  markUnavailable(input: Readonly<{expected: ContactLocalRecordToken01}>): Promise<ContactHistoryWrite01>;
  close(): void;
}>;
type Session = {header: Header; db: IDBDatabase|null; root: Draft02TrustStore|null; mode: 'history'|'local_reduction';
  closed: boolean; busy: boolean; released: boolean; signal: AbortSignal; onAbort: () => void;
  onVisibility: () => void; timer: ReturnType<typeof setTimeout>|null; until: number;
  tx: IDBTransaction|null; tokens: Map<string, ContactLocalRecordToken01>; opening: boolean;
  pendingOpens: number; closeListeners: Set<() => void>};
const tokenRecords = new WeakMap<ContactLocalRecordToken01, {session: Session; row: Row}>();
const adapterRecords = new WeakMap<ContactLocalHistory01, Session>();
function ownedAdapter(api: ContactLocalHistory01): Session {const s=adapterRecords.get(api);if(!s)refuse('invalid adapter');return s;}
function refuse(reason = 'refused'): never {throw Error(`Contact local history: ${reason}`);}
function object(value: unknown, keys: readonly string[]): Record<string, any> {
  if(!value || Object.getPrototypeOf(value)!==Object.prototype || Reflect.ownKeys(value).length!==keys.length)refuse();
  const out: Record<string, any> = {};
  for(const key of keys){const d=Object.getOwnPropertyDescriptor(value,key);if(!d||!Object.hasOwn(d,'value'))refuse();out[key]=d.value;}
  return out;
}
function bytes(v: unknown, n: number, zero = false): Uint8Array {
  if(!(v instanceof Uint8Array)||v.length!==n||!zero&&v.every(x=>x===0))refuse();return Uint8Array.from(v);
}
function integer(v: unknown, zero = false): bigint {if(typeof v!=='bigint'||v<(zero?0n:1n)||v>max)refuse();return v;}
function hex(b: Uint8Array): string {return Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');}
function encoding(v: unknown): string {return JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x instanceof Uint8Array?hex(x):x);}
function equal(a: unknown,b: unknown): boolean {return encoding(a)===encoding(b);}
function same(a: Uint8Array,b: Uint8Array): boolean {return a.length===b.length&&a.every((v,i)=>v===b[i]);}
function clone<T>(v: T): T {return structuredClone(v);}
function wipe(v: any): void {if(v instanceof Uint8Array)v.fill(0);else if(v&&typeof v==='object')for(const x of Object.values(v))wipe(x);}
function slot(v: unknown): Slot {
  const s=object(v,['tag','sealRevision','digest']);if(s.tag!==0&&s.tag!==1)refuse();
  const revision=integer(s.sealRevision,s.tag===0),digest=bytes(s.digest,32,s.tag===0);
  if(s.tag===0&&(revision!==0n||digest.some(x=>x!==0)))refuse();return {tag:s.tag,sealRevision:revision,digest};
}
function stamp(v: unknown): RootStamp {
  const r=object(v,['version','digest','anchorDigest','time']);return {version:integer(r.version),digest:bytes(r.digest,32),
    anchorDigest:bytes(r.anchorDigest,32,true),time:integer(r.time,true)};
}
const rowKeys = ['schema','state','contactId','revision','digest','requestId','routingDigest','name','notes',
  'statementDigest','manifestVersion','manifestDigest','readerId','readerGeneration','rootWriterId','comparisonMs','rootStamp'];
function row(v: unknown): Row {
  if(v&&typeof v==='object'&&(v as any).state==='unavailable'){
    const r=object(v,['schema','state','contactId']);if(r.schema!==1||r.state!=='unavailable')refuse('corrupt');
    return {schema:1,state:'unavailable',contactId:bytes(r.contactId,16)};
  }
  const r=object(v,rowKeys);if(r.schema!==1||r.state!=='accepted')refuse('corrupt');
  const out: ContactAcceptedMetadata01={schema:1,state:'accepted',contactId:bytes(r.contactId,16),revision:integer(r.revision),
    digest:bytes(r.digest,32),requestId:bytes(r.requestId,16),routingDigest:bytes(r.routingDigest,32),name:slot(r.name),notes:slot(r.notes),
    statementDigest:bytes(r.statementDigest,32),manifestVersion:integer(r.manifestVersion),manifestDigest:bytes(r.manifestDigest,32),
    readerId:bytes(r.readerId,32),readerGeneration:integer(r.readerGeneration),rootWriterId:bytes(r.rootWriterId,32),
    comparisonMs:integer(r.comparisonMs),rootStamp:stamp(r.rootStamp)};
  if(out.name.sealRevision>out.revision||out.notes.sealRevision>out.revision||new TextEncoder().encode(encoding(out)).length>2048)refuse('corrupt');
  return out;
}
function header(v: unknown): Header {
  const h=object(v,['schema','accountId','rootPoint','rootFingerprint','origin','maximumRecords','count']);
  if(h.schema!==1||typeof h.origin!=='string'||!Number.isInteger(h.maximumRecords)||h.maximumRecords<1||h.maximumRecords>256||
    !Number.isInteger(h.count)||h.count<0||h.count>h.maximumRecords)refuse('corrupt');
  const out: Header={schema:1,accountId:bytes(h.accountId,16),rootPoint:bytes(h.rootPoint,65),rootFingerprint:bytes(h.rootFingerprint,32),
    origin:h.origin,maximumRecords:h.maximumRecords,count:h.count};
  if(out.rootPoint[0]!==4||new TextEncoder().encode(encoding(out)).length>1024)refuse('corrupt');return out;
}
function sameHeader(a: Header,b: Header): boolean {return equal({...a,count:0},{...b,count:0});}
function live(s: Session): void {if(s.closed||s.signal.aborted||performance.now()>=s.until)refuse('closed');}
function release(s: Session): void {if(!s.opening&&s.pendingOpens===0&&!s.released){s.released=true;permits--;}}
function close(s: Session): void {
  if(!s.closed){s.closed=true;if(s.timer!==null)clearTimeout(s.timer);s.timer=null;s.signal.removeEventListener('abort',s.onAbort);
    if(typeof document!=='undefined')document.removeEventListener('visibilitychange',s.onVisibility);
    if(s.tx){try{s.tx.abort();}catch{}s.tx=null;}
    s.db?.close();s.db=null;s.root?.close();s.root=null;
    for(const token of s.tokens.values()){const t=tokenRecords.get(token);if(t)wipe(t.row);tokenRecords.delete(token);}s.tokens.clear();
    for(const listener of s.closeListeners)listener();s.closeListeners.clear();wipe(s.header);}
  release(s);
}
function token(s: Session,r: Row): ContactLocalRecordToken01 {
  live(s);const key=hex(r.contactId),old=s.tokens.get(key);
  if(old){const before=tokenRecords.get(old);if(before&&equal(before.row,r))return old;
    if(before)wipe(before.row);tokenRecords.delete(old);s.tokens.delete(key);}
  if(s.tokens.size>=s.header.maximumRecords)refuse('corrupt');
  const t=Object.freeze({kind:'local_record' as const});tokenRecords.set(t,{session:s,row:clone(r)});s.tokens.set(key,t);return t;
}
function expected(s: Session,t: ContactLocalRecordToken01|null): Row|null {
  if(t===null)return null;const r=tokenRecords.get(t);if(!r||r.session!==s)refuse('invalid local token');return clone(r.row);
}
async function operation<T>(s: Session, run: () => Promise<T>): Promise<T> {
  live(s);if(s.busy)refuse('busy');s.busy=true;
  let timer: ReturnType<typeof setTimeout>|null=null,onClose:()=>void=()=>{};
  try {return await Promise.race([Promise.resolve().then(()=>{live(s);return run();}),new Promise<T>((_,reject)=>{
    timer=setTimeout(()=>{close(s);reject(Error('Contact local history: closed'));},Math.min(operationMs,Math.max(0,s.until-performance.now())));
    onClose=()=>reject(Error('Contact local history: closed'));s.closeListeners.add(onClose);
  })]);} finally {if(timer!==null)clearTimeout(timer);s.closeListeners.delete(onClose);s.busy=false;}
}
async function ownedOpen<T extends {close(): void}>(s:Session,p:Promise<T>,install:(value:T)=>void):Promise<T>{
  s.pendingOpens++;let onClose:()=>void=()=>{};
  const observed=p.then(value=>{if(s.closed){value.close();refuse('closed');}install(value);return value;}).finally(()=>{s.pendingOpens--;release(s);});
  try{return await Promise.race([observed,new Promise<T>((_,reject)=>{onClose=()=>reject(Error('Contact local history: closed'));s.closeListeners.add(onClose);if(s.closed)onClose();})]);}
  finally{s.closeListeners.delete(onClose);}
}
function openDatabase(): Promise<IDBDatabase> {return new Promise((resolve,reject)=>{
  const q=indexedDB.open(databaseName,1);q.onupgradeneeded=()=>{q.result.createObjectStore('header');q.result.createObjectStore(records);};
  q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);q.onblocked=()=>{};
});}
function transaction<T>(s: Session, mode: IDBTransactionMode, work: (h: Header|undefined, store: IDBObjectStore, done:(v:T)=>void, abort:(e:unknown)=>void)=>void): Promise<T> {
  live(s);return new Promise((resolve,reject)=>{
    const tx=s.db!.transaction(['header',records],mode);s.tx=tx;let value:T,error:unknown;
    const h=tx.objectStore('header').get(headerKey);
    h.onsuccess=()=>{try{live(s);const actual=h.result===undefined?undefined:header(h.result);
      if(actual&&!sameHeader(actual,s.header))refuse('root_mismatch');work(actual,tx.objectStore(records),v=>{value=v;},e=>{error=e;tx.abort();});
    }catch(e){error=e;tx.abort();}};
    tx.oncomplete=()=>{if(s.tx===tx)s.tx=null;resolve(value!);};
    tx.onabort=()=>{if(s.tx===tx)s.tx=null;reject(error??tx.error??Error('Contact local history: storage unavailable'));};
    tx.onerror=()=>{};
  });
}
async function readRow(s: Session,id: Uint8Array): Promise<Row|undefined> {return transaction(s,'readonly',(h,store,done,abort)=>{
  if(!h)refuse('unobserved');const q=store.get(hex(id));q.onsuccess=()=>{try{const r=q.result===undefined?undefined:row(q.result);
    if(r&&!same(r.contactId,id))refuse('corrupt');done(r);}catch(e){abort(e);}};
});}
function rootSnapshot(s: Session,r: Draft02TrustSnapshot|null): Draft02TrustSnapshot {
  if(!r||r.trust.generation!==1n||r.trust.version<1n||!same(r.trust.accountId,s.header.accountId)||!same(r.trust.rootPoint,s.header.rootPoint))refuse('root_mismatch');
  return clone(r);
}
function rootStamp(r: Draft02TrustSnapshot): RootStamp {return {version:r.trust.version,digest:Uint8Array.from(r.trust.digest),
  anchorDigest:Uint8Array.from(r.trust.anchorDigest),time:r.lastTrustedTimeMs};}
async function history(s: Session,r: Omit<ContactAcceptedMetadata01,'rootStamp'>, statement?: ReturnType<typeof verifiedContactReaderStatementIdentity01>,floor?: RootStamp): Promise<Draft02TrustSnapshot> {
  live(s);if(!s.root)refuse('history_missing');const before=rootSnapshot(s,await s.root.read());live(s);
  const minimum=floor??('rootStamp' in r?(r as ContactAcceptedMetadata01).rootStamp:undefined);
  if(minimum&&(before.trust.version<minimum.version||before.trust.version===minimum.version&&!same(before.trust.digest,minimum.digest)||
    !same(before.trust.anchorDigest,minimum.anchorDigest)||before.lastTrustedTimeMs<minimum.time))refuse('history_missing');
  const verified=await s.root.verifyStoredHistory(r.manifestDigest,r.comparisonMs);live(s);
  const m=verifiedAccountArchiveStatementRecords02(verified,r.readerId,r.comparisonMs);
  if(m.generation!==1n||m.version!==r.manifestVersion||!same(m.digest,r.manifestDigest)||!same(m.accountId,s.header.accountId)||
    !same(m.rootPoint,s.header.rootPoint)||!same(m.rootWriterId,r.rootWriterId)||!same(m.readerId,r.readerId))refuse('history_missing');
  if(statement&&(!same(m.readerPoint,statement.readerPoint)||m.readerFromMs!==statement.readerFromMs||m.readerUntilMs!==statement.readerUntilMs||
    m.rootFromMs!==statement.rootFromMs||m.rootUntilMs!==statement.rootUntilMs))refuse('history_missing');
  const after=rootSnapshot(s,await s.root.read());live(s);if(!equal(before,after))refuse('root changed');return after;
}
function capture(s: Session,input: unknown) {
  const i=object(input,['expected','transition','statement']),prior=expected(s,i.expected);
  const n=verifiedContactTransitionIdentity01(i.transition),st=verifiedContactReaderStatementIdentity01(i.statement);
  if(n.trustGeneration!==1n||st.trustGeneration!==1n||!same(n.accountId,s.header.accountId)||!same(st.accountId,n.accountId)||
    st.origin!==s.header.origin||!same(st.rootFingerprint,s.header.rootFingerprint)||!same(st.rootPoint,s.header.rootPoint)||
    st.manifestVersion!==n.manifestVersion||!same(st.manifestDigest,n.manifestDigest)||!same(st.digest,n.statementDigest))refuse();
  const r: Omit<ContactAcceptedMetadata01,'rootStamp'>={schema:1,state:'accepted',contactId:Uint8Array.from(n.contactId),revision:n.revision,digest:Uint8Array.from(n.digest),
    requestId:Uint8Array.from(n.requestId),routingDigest:Uint8Array.from(n.routingDigest),
    name:slot({tag:n.name.tag,sealRevision:n.name.sealRevision,digest:n.name.digest}),
    notes:slot({tag:n.notes.tag,sealRevision:n.notes.sealRevision,digest:n.notes.digest}),
    statementDigest:Uint8Array.from(n.statementDigest),manifestVersion:n.manifestVersion,manifestDigest:Uint8Array.from(n.manifestDigest),
    readerId:Uint8Array.from(st.readerId),readerGeneration:st.readerGeneration,rootWriterId:Uint8Array.from(st.rootWriterId),comparisonMs:st.issuedMs};
  return {prior,r,operation:n.operation,previousDigest:Uint8Array.from(n.previousDigest),statement:st};
}
export async function openContactLocalHistory01(input: Readonly<{expectedAccountId:Uint8Array;expectedOrigin:string;rootPin:Uint8Array;
  independentlyComparedRootFingerprint:Uint8Array;maximumRecords:number;mode:'history'|'local_reduction';signal:AbortSignal}>): Promise<ContactLocalHistory01> {
  const i=object(input,['expectedAccountId','expectedOrigin','rootPin','independentlyComparedRootFingerprint','maximumRecords','mode','signal']);
  const account=bytes(i.expectedAccountId,16),pin=bytes(i.rootPin,94),fingerprint=bytes(i.independentlyComparedRootFingerprint,32);
  if(typeof i.expectedOrigin!=='string'||new TextEncoder().encode(i.expectedOrigin).length>512||new URL(i.expectedOrigin).origin!==i.expectedOrigin||
    new URL(i.expectedOrigin).protocol!=='https:'||!Number.isInteger(i.maximumRecords)||i.maximumRecords<1||i.maximumRecords>256||
    !['history','local_reduction'].includes(i.mode)||!(i.signal instanceof AbortSignal)||i.signal.aborted||permits>=4)refuse();
  permits++;const s:Session={header:{schema:1,accountId:account,rootPoint:new Uint8Array(65),rootFingerprint:fingerprint,
    origin:i.expectedOrigin,maximumRecords:i.maximumRecords,count:0},db:null,root:null,mode:i.mode,closed:false,busy:false,released:false,
    signal:i.signal,onAbort:()=>{},onVisibility:()=>{},timer:null,until:performance.now()+lifetimeMs,tx:null,tokens:new Map(),opening:true,pendingOpens:0,closeListeners:new Set()};
  s.onAbort=()=>close(s);s.onVisibility=()=>{if(document.visibilityState!=='visible')close(s);};
  s.signal.addEventListener('abort',s.onAbort,{once:true});if(typeof document!=='undefined')document.addEventListener('visibilitychange',s.onVisibility);
  s.timer=setTimeout(()=>close(s),operationMs);
  try {
    const enrolled=await enrollRootPin02(pin,fingerprint);live(s);if(enrolled.generation!==1n||!same(enrolled.accountId,account))refuse();s.header.rootPoint=Uint8Array.from(enrolled.rootPoint);
    await ownedOpen(s,openDatabase(),db=>{s.db=db;});live(s);
    const exists=await transaction(s,'readonly',(h,_,done)=>done(h));live(s);
    if(s.mode==='local_reduction'&&!exists)refuse('unobserved');
    if(s.mode==='history'){
      const root=await ownedOpen(s,Draft02TrustStore.open(),value=>{s.root=value;});live(s);
      if(!exists){const before=rootSnapshot(s,await root.read()),verified=await root.verifyStoredHistory(before.trust.digest,before.lastTrustedTimeMs);
        const actual=verifiedManifestIdentity02(verified,before.lastTrustedTimeMs);if(actual.generation!==1n||!same(actual.rootPoint,s.header.rootPoint)||!same(actual.accountId,account))refuse();
        const after=rootSnapshot(s,await root.read());if(!equal(before,after))refuse('root changed');live(s);
        await transaction(s,'readwrite',(h,_,done)=>{if(!h)s.tx!.objectStore('header').put(clone(s.header),headerKey);done(undefined);});}
    }
    live(s);if(s.timer!==null)clearTimeout(s.timer);s.timer=setTimeout(()=>close(s),Math.max(0,s.until-performance.now()));s.opening=false;const api: ContactLocalHistory01=Object.freeze({close(this:ContactLocalHistory01){close(ownedAdapter(this));},
      lookup:async function(this:ContactLocalHistory01,id:Uint8Array){const s=ownedAdapter(this),selected=bytes(id,16);return operation<ContactHistoryLookup01>(s,async()=>{
        const r=await readRow(s,selected);live(s);if(!r)return {kind:'unavailable' as const,reason:'unobserved'};
        const t=token(s,r);if(r.state==='unavailable')return {kind:'unavailable' as const,reason:'local_stop',token:t};
        if(s.mode==='local_reduction')return {kind:'unavailable' as const,reason:'reduction_only',token:t};
        try{await history(s,r);live(s);return {kind:'accepted_local_history' as const,token:t,metadata:clone(r),evidence:'available' as const};}
        catch(e){live(s);const reason:UnavailableReason01=e instanceof Error&&e.message.includes('root_mismatch')?'root_mismatch':'history_missing';return {kind:'unavailable' as const,reason,token:t};}
      });},
      accept:async function(this:ContactLocalHistory01,input:Parameters<ContactLocalHistory01['accept']>[0]){const s=ownedAdapter(this);live(s);if(s.mode!=='history')refuse('reduction_only');const c=capture(s,input);let attempted=false;
        try{return await operation<ContactHistoryWrite01>(s,async()=>{
          const before=await history(s,c.r,c.statement,c.prior?.state==='accepted'?c.prior.rootStamp:undefined),proposed={...c.r,rootStamp:rootStamp(before)};live(s);attempted=true;
          const saved=await transaction<Row>(s,'readwrite',(h,store,done,abort)=>{
            if(!h)refuse('unobserved');const q=store.get(hex(c.r.contactId));q.onsuccess=()=>{try{
              live(s);const old=q.result===undefined?null:row(q.result);if(!equal(old,c.prior))refuse('stale local CAS');
              if(old?.state==='unavailable')refuse('local_stop');
              if(old&&old.state==='accepted'&&old.revision===c.r.revision){const sameRow={...proposed,rootStamp:old.rootStamp};if(!equal(old,sameRow))refuse('fork');done(old);return;}
              if(old){if(old.state!=='accepted'||c.operation!==2||old.revision===max||c.r.revision!==old.revision+1n||!same(c.previousDigest,old.digest)||
                !same(c.r.routingDigest,old.routingDigest)||c.r.manifestVersion<old.manifestVersion||c.r.manifestVersion===old.manifestVersion&&!same(c.r.manifestDigest,old.manifestDigest)||
                c.r.readerGeneration<old.readerGeneration||c.r.readerGeneration===old.readerGeneration&&!same(c.r.readerId,old.readerId))refuse('fork');}
              else {if(![1,3].includes(c.operation)||c.r.revision!==1n)refuse('cold update');if(h.count>=h.maximumRecords)refuse('storage unavailable');h.count++;s.tx!.objectStore('header').put(h,headerKey);}
              const next=row(proposed);store.put(next,hex(next.contactId));done(next);
            }catch(e){abort(e);}};
          });
          live(s);let after:Draft02TrustSnapshot;try{after=rootSnapshot(s,await s.root!.read());live(s);}catch(e){live(s);return {kind:'recorded_needs_recheck' as const};}
          if(!equal(before,after))return {kind:'recorded_needs_recheck' as const};
          const t=token(s,saved);return {kind:'accepted_local_history' as const,token:t,metadata:clone(saved as ContactAcceptedMetadata01),evidence:'available' as const};
        });}catch(e){if(attempted&&s.closed)return {kind:'write_unknown' as const};throw e;}finally{wipe(c);}
      },
      markUnavailable:async function(this:ContactLocalHistory01,input:Parameters<ContactLocalHistory01['markUnavailable']>[0]){const s=ownedAdapter(this);live(s);const i=object(input,['expected']),prior=expected(s,i.expected);if(!prior)refuse();let attempted=false;
        try{return await operation<ContactHistoryWrite01>(s,async()=>{live(s);attempted=true;const saved=await transaction<Row>(s,'readwrite',(h,store,done,abort)=>{
          if(!h)refuse('unobserved');const q=store.get(hex(prior.contactId));q.onsuccess=()=>{try{live(s);const old=q.result===undefined?null:row(q.result);
            if(!equal(old,prior))refuse('stale local CAS');const next:Row={schema:1,state:'unavailable',contactId:Uint8Array.from(prior.contactId)};
            if(old?.state!=='unavailable')store.put(next,hex(next.contactId));done(next);
          }catch(e){abort(e);}};
        });live(s);return {kind:'unavailable' as const,reason:'local_stop',token:token(s,saved)};});}
        catch(e){if(attempted&&s.closed)return {kind:'write_unknown' as const};throw e;}finally{wipe(prior);}
      }});
    adapterRecords.set(api,s);return api;
  }catch(e){close(s);throw e;}finally{s.opening=false;if(s.closed)release(s);wipe(pin);}
}
