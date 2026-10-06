// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic signed history; no customer key, field decryption, remote erasure or permission.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import 'fake-indexeddb/auto';
import {Draft02TrustStore} from '../dist/draft02-trust-store.js';
import {canonicalSignature02} from '../dist/draft02-manifest.js';
import {encodeContactReaderStatementUnsigned01,verifyContactReaderStatement01,verifiedContactReaderStatementIdentity01} from '../dist/contact-reader-statement.js';
import * as c from '../dist/contact-content-contract.js';
import {openContactLocalHistory01} from '../dist/contact-local-history.js';
const localName='ztse-contact-local-history-v1',rootName='ztse-draft02-trust-v1',enc=new TextEncoder();
const hex=s=>new Uint8Array(Buffer.from(s,'hex')),join=(...b)=>new Uint8Array(Buffer.concat(b));
const hash=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
const v=JSON.parse(await readFile(new URL('../../../protocol/v1/contact-content-contract-vectors.json',import.meta.url),'utf8'));
const fieldKeys=['kind','accountId','contactId','sealRevision','trustGeneration','manifestVersion','readerGeneration','readerId','manifestDigest','statementDigest','routingDigest','requestId','rootWriterId','encapsulation','ciphertext'];
const statementKeys=['authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration','rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability'];
const pick=(x,keys)=>Object.fromEntries(keys.map(k=>[k,x[k]]));
export async function removeDatabase(name){await new Promise((resolve,reject)=>{const q=indexedDB.deleteDatabase(name);q.onsuccess=()=>resolve();q.onerror=()=>reject(q.error);q.onblocked=()=>reject(Error('fixture connection still open'));});}
export async function rawLocal(run){const db=await new Promise((resolve,reject)=>{const q=indexedDB.open(localName,1);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});try{return await new Promise((resolve,reject)=>{
  const tx=db.transaction(['header','contacts'],'readwrite');let result;run(tx,v=>{result=v;});tx.oncomplete=()=>resolve(result);tx.onabort=()=>reject(tx.error);
});}finally{db.close();}}
export async function prepareContactHistoryFixture({reset=true}={}){
  if(reset){await removeDatabase(localName);await removeDatabase(rootName);}
  const s=v.reader_statement,pin=hex(s.root_pin_hex),fingerprint=hex(s.expected_root_fingerprint_hex),account=hex(s.account_hex),contact=hex(v.contact_hex),routing=hex(v.routing_digest_hex);
  const point=pin.slice(29),b64=b=>Buffer.from(b).toString('base64url'),scalar=new Uint8Array(32);scalar[31]=1;
  const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(point.slice(1,33)),y:b64(point.slice(33)),d:b64(scalar)},
    {name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
  const sign=async(unsigned,domain)=>{const n=new Uint8Array(4);new DataView(n.buffer).setUint32(0,unsigned.length);
    return join(unsigned,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,join(enc.encode(domain+'\0'),n,unsigned)))));};
  const root=await Draft02TrustStore.open();await root.enroll(pin,fingerprint,2000n);
  let previous=new Uint8Array(32),accepted;const manifests=[];
  for(let version=1;version<=7;version++){const b=hex(s.accepted_manifest_hex).slice(0,-64);new DataView(b.buffer).setBigUint64(29,BigInt(version));b.set(previous,53);
    const signed=await sign(b,'ZTSE/manifest/v2');accepted=await root.acceptManifest(signed,2000n);previous=accepted.digest;manifests.push(signed);}
  const parsed=await import('../dist/contact-reader-statement.js').then(m=>m.parseContactReaderStatement01(hex(s.statement_hex)));
  const statementBytes=await sign(encodeContactReaderStatementUnsigned01({...pick(parsed,statementKeys),manifestDigest:accepted.digest}),'ZT/contact-reader/authorization/v1');
  const verifyStatement=bytes=>verifyContactReaderStatement01({bytes,acceptedManifest:accepted,expectedAccountId:account,expectedOrigin:s.origin,expectedRootFingerprint:fingerprint,comparison:'declared_issued_ms'});
  const statement=await verifyStatement(statementBytes),sid=verifiedContactReaderStatementIdentity01(statement);
  const wrongStatement=await verifyStatement(await sign(encodeContactReaderStatementUnsigned01({...pick(sid,statementKeys),authorizationId:new Uint8Array(16).fill(77)}),'ZT/contact-reader/authorization/v1'));
  const createFor=async(id)=>{
    const scope={expectedContactId:id,expectedRoutingDigest:routing},fields=[],fieldBytes=[];
    for(const template of [v.name_hex,v.notes_hex]){const parsed=await c.parseContactField01(hex(template));const b=await sign(c.encodeContactFieldUnsigned01({...pick(parsed,fieldKeys),contactId:id,manifestDigest:accepted.digest,statementDigest:sid.digest}),'ZT/contact-field/commitment/v1');
      fieldBytes.push(b);fields.push(await c.verifyContactField01({bytes:b,statement,...scope}));}
    const original=c.parseContactMutation01(hex(v.create_hex)),parts={operation:1,accountId:account,contactId:id,expectedRevision:0n,revision:1n,requestId:original.requestId,
      previousDigest:new Uint8Array(32),trustGeneration:1n,manifestVersion:7n,manifestDigest:accepted.digest,statementDigest:sid.digest,routingDigest:routing,legacyGeneration:0n,
      name:{tag:1,sealRevision:1n,digest:c.verifiedContactFieldIdentity01(fields[0]).digest},notes:{tag:1,sealRevision:1n,digest:c.verifiedContactFieldIdentity01(fields[1]).digest}};
    const createBytes=await sign(c.encodeContactMutationUnsigned01(parts),'ZT/contact-field/mutation/v1');
    const create=await c.verifyContactMutation01({bytes:createBytes,statement,...scope,expectedLegacyGeneration:0n});
    const first=c.verifyContactTransition01({previous:null,next:create,replacementFields:fields}),firstId=c.verifiedContactTransitionIdentity01(first);
    const updates=[],updateBytes=[];
    for(const [at,cleared] of [[1,'notes'],[2,'name']]){const p={...parts,operation:2,expectedRevision:1n,revision:2n,requestId:new Uint8Array(16).fill(40+at),previousDigest:firstId.digest,
      [cleared]:{tag:0,sealRevision:0n,digest:new Uint8Array(32)}};const b=await sign(c.encodeContactMutationUnsigned01(p),'ZT/contact-field/mutation/v1');
      updateBytes.push(b);const m=await c.verifyContactMutation01({bytes:b,statement,...scope,expectedLegacyGeneration:0n});updates.push(c.verifyContactTransition01({previous:first,next:m,replacementFields:[]}));}
    return {first,updates,publicBytes:{contact:Array.from(id),fields:fieldBytes.map(b=>Array.from(b)),create:Array.from(createBytes),updates:updateBytes.map(b=>Array.from(b))}};
  };
  const made=await createFor(contact),controller=new AbortController();
  const options={expectedAccountId:account,expectedOrigin:s.origin,rootPin:pin,independentlyComparedRootFingerprint:fingerprint,maximumRecords:2,mode:'history',signal:controller.signal};
  return {root,options,controller,contact,statement,wrongStatement,first:made.first,updates:made.updates,
    other:()=>createFor(new Uint8Array(16).fill(55)),
    publicBytes:{pin:Array.from(pin),fingerprint:Array.from(fingerprint),account:Array.from(account),origin:s.origin,manifests:manifests.map(b=>Array.from(b)),statement:Array.from(statementBytes),...made.publicBytes},
    advance:async()=>{const next=(await root.read()).trust.version+1n,b=hex(s.accepted_manifest_hex).slice(0,-64);new DataView(b.buffer).setBigUint64(29,next);b.set((await root.read()).trust.digest,53);return root.acceptManifest(await sign(b,'ZTSE/manifest/v2'),2000n);},
    close:()=>root.close()};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
test('genuine local history survives reopen without restoring a contact integrity brand',async()=>{
  const f=await prepareContactHistoryFixture();let store;try{store=await openContactLocalHistory01(f.options);const first=await store.accept({expected:null,transition:f.first,statement:f.statement});
    assert.equal(first.kind,'accepted_local_history');assert.equal(first.metadata.revision,1n);first.metadata.digest.fill(0);
    const read=await store.lookup(f.contact);assert.notEqual(read.metadata.digest[0],undefined);assert.ok(read.metadata.digest.some(v=>v!==0));
    assert.throws(()=>c.verifiedContactTransitionIdentity01(read.token));store.close();store=await openContactLocalHistory01(f.options);
    const restored=await store.lookup(f.contact);assert.equal(restored.kind,'accepted_local_history');assert.equal(restored.token.kind,'local_record');
    const updated=await store.accept({expected:restored.token,transition:f.updates[0],statement:f.statement});assert.equal(updated.metadata.revision,2n);
    const rows=await rawLocal((tx,done)=>{const q=tx.objectStore('contacts').getAll();q.onsuccess=()=>done(q.result);});
    assert.equal(rows.length,1);for(const key of ['bytes','unsigned','signature','ciphertext','phone','purpose','session'])assert.equal(Object.hasOwn(rows[0],key),false);
  }finally{store?.close();f.close();}});
test('forged brands and a genuine wrong statement refuse before storing any contact',async()=>{
  const f=await prepareContactHistoryFixture();const store=await openContactLocalHistory01(f.options);try{
    await assert.rejects(store.accept({expected:null,transition:{kind:'historical_integrity'},statement:f.statement}));
    await assert.rejects(store.accept({expected:null,transition:f.first,statement:f.wrongStatement}));
    await assert.rejects(store.accept({expected:{kind:'local_record'},transition:f.first,statement:f.statement}));
    assert.equal((await store.lookup(f.contact)).reason,'unobserved');
  }finally{store.close();f.close();}});
test('two genuine fork successors compete on exact local CAS and only one wins',async()=>{
  const f=await prepareContactHistoryFixture(),a=await openContactLocalHistory01(f.options),b=await openContactLocalHistory01(f.options);try{
    await a.accept({expected:null,transition:f.first,statement:f.statement});const ta=(await a.lookup(f.contact)).token,tb=(await b.lookup(f.contact)).token;
    const out=await Promise.allSettled([a.accept({expected:ta,transition:f.updates[0],statement:f.statement}),b.accept({expected:tb,transition:f.updates[1],statement:f.statement})]);
    assert.equal(out.filter(x=>x.status==='fulfilled').length,1);assert.match(out.find(x=>x.status==='rejected').reason.message,/stale local CAS/);
    const now=await a.lookup(f.contact);assert.equal(now.metadata.revision,2n);
    await assert.rejects(a.accept({expected:now.token,transition:f.updates[1-out.findIndex(x=>x.status==='fulfilled')],statement:f.statement}),/fork/);
  }finally{a.close();b.close();f.close();}});
for(const loss of ['missing','mismatch'])test('MAX/full local reduction remains possible after real root '+loss,async()=>{
  const f=await prepareContactHistoryFixture();let store=await openContactLocalHistory01({...f.options,maximumRecords:1});try{
    await store.accept({expected:null,transition:f.first,statement:f.statement});const other=await f.other();await assert.rejects(store.accept({expected:null,transition:other.first,statement:f.statement}),/storage unavailable/);
    // Controlled pre-existing durable MAX representation for reduction, never an invented integrity brand.
    await rawLocal((tx,done)=>{const q=tx.objectStore('contacts').getAll();q.onsuccess=()=>{const r=q.result[0];r.revision=(1n<<63n)-1n;tx.objectStore('contacts').put(r,Buffer.from(f.contact).toString('hex'));done();};});
    assert.equal((await store.lookup(f.contact)).metadata.revision,(1n<<63n)-1n);
    store.close();f.close();await removeDatabase(rootName);
    if(loss==='mismatch'){const generated=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),point=new Uint8Array(await crypto.subtle.exportKey('raw',generated.publicKey)),pin=Uint8Array.from(f.options.rootPin);pin.set(point,29);
      const root=await Draft02TrustStore.open();await root.enroll(pin,await hash(join(enc.encode('ZTSE/root-pin/v2\0'),pin)),2000n);root.close();}
    store=await openContactLocalHistory01({...f.options,maximumRecords:1,mode:'local_reduction'});const r=await store.lookup(f.contact);assert.equal(r.kind,'unavailable');assert.equal(r.reason,'reduction_only');
    await assert.rejects(store.accept({expected:r.token,transition:f.first,statement:f.statement}),/reduction_only/);
    assert.equal((await store.markUnavailable({expected:r.token})).reason,'local_stop');
    for(let n=0;n<8;n++)assert.equal((await store.markUnavailable({expected:(await store.lookup(f.contact)).token})).reason,'local_stop');
    const result=await rawLocal((tx,done)=>{const h=tx.objectStore('header').get('scope'),q=tx.objectStore('contacts').getAll();q.onsuccess=()=>done({header:h.result,rows:q.result});});
    assert.equal(result.header.count,1);assert.equal(result.rows.length,1);assert.deepEqual(Object.keys(result.rows[0]).sort(),['contactId','schema','state']);
  }finally{store.close();f.close();}});
test('pruned genuine manifest history disables positive lookup while retaining reduction',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options);try{await store.accept({expected:null,transition:f.first,statement:f.statement});
    for(let at=0;at<64;at++)await f.advance();const r=await store.lookup(f.contact);assert.equal(r.kind,'unavailable');assert.equal(r.reason,'history_missing');
    assert.equal((await store.markUnavailable({expected:r.token})).reason,'local_stop');
  }finally{store.close();f.close();}});
test('root advance after commit reports recorded-needs-recheck',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options),original=Draft02TrustStore.prototype.read,tx=IDBDatabase.prototype.transaction;let committed=false,advanced=false;
  try{IDBDatabase.prototype.transaction=function(...args){const actual=tx.apply(this,args);if(this.name===localName&&args[1]==='readwrite')actual.addEventListener('complete',()=>{committed=true;});return actual;};
    Draft02TrustStore.prototype.read=async function(){const value=await original.call(this);if(committed&&!advanced){advanced=true;await f.advance();return original.call(this);}return value;};
    const out=await store.accept({expected:null,transition:f.first,statement:f.statement});assert.equal(out.kind,'recorded_needs_recheck');
    assert.equal(committed,true);assert.equal(advanced,true);
  }finally{Draft02TrustStore.prototype.read=original;IDBDatabase.prototype.transaction=tx;store.close();f.close();}});
test('real root advance after historical verification but before CAS leaves no contact effects',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options),original=Draft02TrustStore.prototype.verifyStoredHistory;
  try{let advanced=false;Draft02TrustStore.prototype.verifyStoredHistory=async function(...args){const verified=await original.apply(this,args);if(!advanced){advanced=true;await f.advance();}return verified;};
    await assert.rejects(store.accept({expected:null,transition:f.first,statement:f.statement}),/root changed/);
    assert.equal((await store.lookup(f.contact)).reason,'unobserved');
  }finally{Draft02TrustStore.prototype.verifyStoredHistory=original;store.close();f.close();}});
test('four owned adapters bound connections and closing one never closes another',async()=>{
  const f=await prepareContactHistoryFixture(),all=[],original=indexedDB.open;let opened=0,live=0;
  try{indexedDB.open=function(...args){opened++;const q=original.apply(this,args);q.addEventListener('success',()=>{live++;const db=q.result,close=db.close.bind(db);let closed=false;
      db.close=()=>{if(!closed){closed=true;live--;}close();};});return q;};
    for(let n=0;n<4;n++)all.push(await openContactLocalHistory01(f.options));assert.equal(opened,8);assert.equal(live,8);
    await assert.rejects(openContactLocalHistory01(f.options));assert.equal(opened,8);
    all[0].close();assert.equal(live,6);assert.equal((await all[1].lookup(f.contact)).reason,'unobserved');all.push(await openContactLocalHistory01(f.options));assert.equal(live,8);
  }finally{for(const s of all)s.close();assert.equal(live,0);indexedDB.open=original;f.close();}});
test('close while history waits refuses late receipt and observes late rejected work',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options),original=Draft02TrustStore.prototype.verifyStoredHistory;let release;
  const held=new Promise((_,reject)=>{release=reject;});try{Draft02TrustStore.prototype.verifyStoredHistory=function(){store.close();return held;};
    const pending=store.accept({expected:null,transition:f.first,statement:f.statement});await assert.rejects(pending,/closed/);release(Error('synthetic late refusal'));await new Promise(r=>setTimeout(r,0));
  }finally{Draft02TrustStore.prototype.verifyStoredHistory=original;store.close();f.close();}});
test('same-root observed clock reset makes history unavailable but cannot block reduction',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options);try{
    await store.accept({expected:null,transition:f.first,statement:f.statement});await f.root.resetTrustedTime(await f.root.read(),1999n);
    const r=await store.lookup(f.contact);assert.equal(r.kind,'unavailable');assert.equal(r.reason,'history_missing');
    assert.equal((await store.markUnavailable({expected:r.token})).reason,'local_stop');
  }finally{store.close();f.close();}});
test('missing root history mode can load a reduction token without minting positive history',async()=>{
  const f=await prepareContactHistoryFixture();let store=await openContactLocalHistory01(f.options);try{
    await store.accept({expected:null,transition:f.first,statement:f.statement});store.close();f.close();await removeDatabase(rootName);
    store=await openContactLocalHistory01(f.options);const r=await store.lookup(f.contact);assert.equal(r.kind,'unavailable');assert.equal(r.reason,'root_mismatch');
    await assert.rejects(store.accept({expected:r.token,transition:f.updates[0],statement:f.statement}),/root_mismatch/);
    assert.equal((await store.markUnavailable({expected:r.token})).reason,'local_stop');
  }finally{store.close();f.close();}});
test('cold, wrong independent fingerprint and corrupt records never become positive history',async()=>{
  await removeDatabase(localName);await removeDatabase(rootName);
  const f=await prepareContactHistoryFixture();let store;try{
    await assert.rejects(openContactLocalHistory01({...f.options,mode:'local_reduction'}),/unobserved/);
    const wrong=Uint8Array.from(f.options.independentlyComparedRootFingerprint);wrong[0]^=1;
    await assert.rejects(openContactLocalHistory01({...f.options,independentlyComparedRootFingerprint:wrong}));
    store=await openContactLocalHistory01(f.options);await store.accept({expected:null,transition:f.first,statement:f.statement});
    await rawLocal((tx,done)=>{tx.objectStore('contacts').put({schema:99},Buffer.from(f.contact).toString('hex'));done();});
    await assert.rejects(store.lookup(f.contact));const rows=await rawLocal((tx,done)=>{const q=tx.objectStore('contacts').getAll();q.onsuccess=()=>done(q.result);});assert.equal(rows[0].schema,99);
  }finally{store?.close();f.close();}});
test('runtime adapter brands reject copied methods and duplicate lookups reuse one token',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options);try{
    await assert.rejects(store.lookup.call({...store},f.contact),/invalid adapter/);
    const saved=await store.accept({expected:null,transition:f.first,statement:f.statement});for(let n=0;n<12;n++)assert.equal((await store.lookup(f.contact)).token,saved.token);
    const old=saved.token;await store.accept({expected:old,transition:f.updates[0],statement:f.statement});await assert.rejects(store.markUnavailable({expected:old}),/invalid local token/);
  }finally{store.close();f.close();}});
test('synchronous root callback closure observes its already-rejecting promise',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options),original=Draft02TrustStore.prototype.read;try{
    Draft02TrustStore.prototype.read=function(){store.close();return Promise.reject(Error('synthetic rejected root read'));};
    await assert.rejects(store.accept({expected:null,transition:f.first,statement:f.statement}),/closed/);await new Promise(r=>setTimeout(r,0));
  }finally{Draft02TrustStore.prototype.read=original;store.close();f.close();}});
test('abort during actual delayed database open closes its late handle and releases its charged permit',async()=>{
  const f=await prepareContactHistoryFixture(),original=indexedDB.open;let began,started=new Promise(resolve=>{began=resolve;});
  try{indexedDB.open=function(...args){const q=original.apply(this,args);if(args[0]===localName){Object.defineProperty(q,'onsuccess',{set(fn){q.addEventListener('success',e=>setTimeout(()=>fn.call(q,e),30));}});began();}return q;};
    const pending=openContactLocalHistory01(f.options);await started;f.controller.abort();await assert.rejects(pending,/closed/);await new Promise(r=>setTimeout(r,60));
    await removeDatabase(localName);const fresh=await openContactLocalHistory01({...f.options,signal:new AbortController().signal});fresh.close();
  }finally{indexedDB.open=original;f.close();}});
test('idle absolute lifetime closes owned adapters',async t=>{
  const f=await prepareContactHistoryFixture();let a,b;try{
    t.mock.timers.enable({apis:['setTimeout']});a=await openContactLocalHistory01(f.options);b=await openContactLocalHistory01(f.options);
    t.mock.timers.tick(30*60_000);await assert.rejects(a.lookup(f.contact),/closed/);await assert.rejects(b.lookup(f.contact),/closed/);
  }finally{a?.close();b?.close();t.mock.timers.reset();f.close();}});
test('held operation has a fixed deadline, refuses concurrent work and observes late failure',async t=>{
  const f=await prepareContactHistoryFixture(),original=Draft02TrustStore.prototype.verifyStoredHistory;let store;
  let began,release;const started=new Promise(resolve=>{began=resolve;}),held=new Promise((_,reject)=>{release=reject;});
  try{t.mock.timers.enable({apis:['setTimeout']});store=await openContactLocalHistory01(f.options);Draft02TrustStore.prototype.verifyStoredHistory=function(){began();return held;};
    const pending=store.accept({expected:null,transition:f.first,statement:f.statement});await started;
    await assert.rejects(store.lookup(f.contact),/busy/);const refusal=assert.rejects(pending,/closed/);
    t.mock.timers.tick(10_000);await refusal;release(Error('late timed-out history'));await Promise.resolve();
    t.mock.timers.reset();assert.equal((await rawLocal((tx,done)=>{const q=tx.objectStore('contacts').getAll();q.onsuccess=()=>done(q.result);})).length,0);
    await assert.rejects(store.lookup(f.contact),/closed/);
  }finally{Draft02TrustStore.prototype.verifyStoredHistory=original;store?.close();t.mock.timers.reset();f.close();}});
test('captured genuine metadata is owned before asynchronous history verification',async()=>{
  const f=await prepareContactHistoryFixture(),store=await openContactLocalHistory01(f.options),original=Draft02TrustStore.prototype.verifyStoredHistory;
  try{Draft02TrustStore.prototype.verifyStoredHistory=async function(...args){
      const exposed=c.verifiedContactTransitionIdentity01(f.first);exposed.contactId.fill(0);exposed.digest.fill(0);exposed.statementDigest.fill(0);
      f.options.expectedAccountId.fill(0);f.options.rootPin.fill(0);return original.apply(this,args);};
    const accepted=await store.accept({expected:null,transition:f.first,statement:f.statement});assert.equal(accepted.kind,'accepted_local_history');
    assert.deepEqual(accepted.metadata.contactId,f.contact);assert.ok(accepted.metadata.digest.some(x=>x!==0));
    await assert.rejects(store.markUnavailable({expected:{status:404,contactId:f.contact}}),/invalid local token/);
    await assert.rejects(store.markUnavailable({expected:{schema:1,state:'unavailable',contactId:f.contact}}),/invalid local token/);
  }finally{Draft02TrustStore.prototype.verifyStoredHistory=original;store.close();f.close();}});
test('closure after contact commit reports unknown and exact lookup reconciles without replay',async()=>{
  const f=await prepareContactHistoryFixture(),original=Draft02TrustStore.prototype.read,tx=IDBDatabase.prototype.transaction;let store=await openContactLocalHistory01(f.options),committed=false;
  try{IDBDatabase.prototype.transaction=function(...args){const actual=tx.apply(this,args);if(this.name===localName&&args[1]==='readwrite')actual.addEventListener('complete',()=>{committed=true;});return actual;};
    Draft02TrustStore.prototype.read=async function(){const value=await original.call(this);if(committed)store.close();return value;};
    assert.equal((await store.accept({expected:null,transition:f.first,statement:f.statement})).kind,'write_unknown');
    assert.equal(committed,true);Draft02TrustStore.prototype.read=original;IDBDatabase.prototype.transaction=tx;store=await openContactLocalHistory01(f.options);
    const reconciled=await store.lookup(f.contact);assert.equal(reconciled.kind,'accepted_local_history');assert.equal(reconciled.metadata.revision,1n);
    await assert.rejects(store.accept({expected:null,transition:f.first,statement:f.statement}),/stale local CAS/);
  }finally{Draft02TrustStore.prototype.read=original;IDBDatabase.prototype.transaction=tx;store.close();f.close();}});
test('initial real crypto wait rejects outward open at its absolute ten-second deadline',async()=>{
  const f=await prepareContactHistoryFixture(),original=crypto.subtle.digest;let began,release,timer;
  const entered=new Promise(resolve=>{began=resolve;}),held=new Promise((_,reject)=>{release=reject;});
  try{crypto.subtle.digest=function(){began();return held;};const start=performance.now(),opening=openContactLocalHistory01(f.options);
    const refusal=assert.rejects(Promise.race([opening,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('control did not settle opening')),13_000);})]),/closed/);
    await entered;await refusal;assert.ok(performance.now()-start>=9900);clearTimeout(timer);
    release(Error('late initial crypto failure'));await new Promise(resolve=>setTimeout(resolve,0));
    crypto.subtle.digest=original;const fresh=await openContactLocalHistory01({...f.options,signal:new AbortController().signal});fresh.close();
  }finally{clearTimeout(timer);crypto.subtle.digest=original;release?.(Error('control cleanup'));f.close();}});
for(const phase of ['initial_read','stored_history','final_read'])test('abort settles outward open during genuine initial '+phase+' without late header writes',async()=>{
  const f=await prepareContactHistoryFixture(),read=Draft02TrustStore.prototype.read,verify=Draft02TrustStore.prototype.verifyStoredHistory;
  let began,release,timer,heldOnce=false,verified=false;const entered=new Promise(resolve=>{began=resolve;});
  const hold=async(value)=>{heldOnce=true;began();await new Promise(resolve=>{release=resolve;});return value;};
  try{Draft02TrustStore.prototype.read=async function(){const value=await read.call(this);
      if(!heldOnce&&(phase==='initial_read'||phase==='final_read'&&verified))return hold(value);return value;};
    Draft02TrustStore.prototype.verifyStoredHistory=async function(...args){const value=await verify.apply(this,args);verified=true;
      if(phase==='stored_history'&&!heldOnce)return hold(value);return value;};
    const opening=openContactLocalHistory01(f.options),refusal=assert.rejects(Promise.race([opening,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(Error('control did not settle opening')),1000);})]),/closed/);
    await entered;f.controller.abort();await refusal;clearTimeout(timer);release();await new Promise(resolve=>setTimeout(resolve,0));
    const saved=await rawLocal((tx,done)=>{const h=tx.objectStore('header').get('scope'),rows=tx.objectStore('contacts').getAll();rows.onsuccess=()=>done({header:h.result,rows:rows.result});});
    assert.equal(saved.header,undefined);assert.deepEqual(saved.rows,[]);
    Draft02TrustStore.prototype.read=read;Draft02TrustStore.prototype.verifyStoredHistory=verify;
    const fresh=await openContactLocalHistory01({...f.options,signal:new AbortController().signal});fresh.close();
  }finally{clearTimeout(timer);release?.();Draft02TrustStore.prototype.read=read;Draft02TrustStore.prototype.verifyStoredHistory=verify;f.close();}});
}
