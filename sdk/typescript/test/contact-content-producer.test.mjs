// SPDX-License-Identifier: AGPL-3.0-only
// Genuine synthetic software keys and existing signed vectors, not a custody/current authority fixture.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import {enrollRootPin02,verifyManifest02} from '../dist/draft02-manifest.js';
import {verifyContactReaderStatement01,verifiedContactReaderStatementIdentity01} from '../dist/contact-reader-statement.js';
import * as c from '../dist/contact-content-contract.js';
import {produceContactFieldCommitment01 as field,produceContactMutationTransition01 as mutation} from '../dist/contact-content-producer.js';
const hex=s=>new Uint8Array(Buffer.from(s,'hex'));
const vector=JSON.parse(await readFile(new URL('../../../protocol/v1/contact-content-contract-vectors.json',import.meta.url),'utf8'));
const names=['operation','accountId','contactId','expectedRevision','revision','requestId','previousDigest','trustGeneration','manifestVersion','manifestDigest','statementDigest','routingDigest','legacyGeneration','name','notes'];
const plain=p=>Object.fromEntries(names.map(k=>[k,k==='name'||k==='notes'?{...p[k]}:p[k]]));
const signal=()=>new AbortController().signal;
async function fixture(){const v=vector.reader_statement,trust=await enrollRootPin02(hex(v.root_pin_hex),hex(v.expected_root_fingerprint_hex));
 const m=await verifyManifest02(hex(v.accepted_manifest_hex),{...trust,version:6n,digest:hex(v.accepted_previous_digest_hex)},2000n),next=await verifyManifest02(hex(vector.successor_manifest_hex),{...trust,version:7n,digest:m.digest},2002n);
 const check=(bytes,acceptedManifest)=>verifyContactReaderStatement01({bytes,acceptedManifest,expectedAccountId:hex(v.account_hex),expectedOrigin:v.origin,expectedRootFingerprint:hex(v.expected_root_fingerprint_hex),comparison:'declared_issued_ms'});
 const statement=await check(hex(v.statement_hex),m),nextStatement=await check(hex(vector.successor_statement_hex),next),s=verifiedContactReaderStatementIdentity01(statement),scalar=new Uint8Array(32);scalar[31]=1;
 const b64=b=>Buffer.from(b).toString('base64url'),rootPrivateKey=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(s.rootPoint.slice(1,33)),y:b64(s.rootPoint.slice(33)),d:b64(scalar)},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
 const expected={accountId:s.accountId,origin:s.origin,rootFingerprint:s.rootFingerprint,contactId:hex(vector.contact_hex),routingDigest:hex(vector.routing_digest_hex)},scope={expectedContactId:expected.contactId,expectedRoutingDigest:expected.routingDigest};
 const name=await c.verifyContactField01({bytes:hex(vector.name_hex),statement,...scope}),notes=await c.verifyContactField01({bytes:hex(vector.notes_hex),statement,...scope}),replacement=await c.verifyContactField01({bytes:hex(vector.replacement_notes_hex),statement:nextStatement,...scope});
 const create=await c.verifyContactMutation01({bytes:hex(vector.create_hex),statement,...scope,expectedLegacyGeneration:0n}),first=c.verifyContactTransition01({previous:null,next:create,replacementFields:[name,notes]});
 const base={rootPrivateKey,statement,expected,signal:signal()},q=c.verifiedContactFieldIdentity01(name),f={kind:q.kind,sealRevision:q.sealRevision,requestId:q.requestId,encapsulation:q.encapsulation,ciphertext:q.ciphertext};
 const mi=(m=c.parseContactMutation01(hex(vector.create_hex)),selected=statement,previous=null,previousStatement=null,fields=[name,notes])=>({rootPrivateKey,statement:selected,expected:{...expected,legacyGeneration:0n},mutation:plain(m),previous,previousStatement,replacementFields:fields,signal:signal()});
 return {base,f,expected,statement,nextStatement,name,notes,replacement,first,mi};
}
test('existing matched root signs actual field and creation and output passes maintained verifier',async()=>{const f=await fixture(),made=await field({...f.base,field:f.f});assert.equal(made.kind,'produced_historical_integrity');assert.equal(c.verifiedContactFieldIdentity01(made.verified).kind,1);
 const i=f.mi();i.mutation.name.digest=c.verifiedContactFieldIdentity01(made.verified).digest;i.replacementFields=[made.verified,f.notes];const created=await mutation(i);assert.equal(c.verifiedContactTransitionIdentity01(created.verified).revision,1n);assert.equal(created.bytes.length,368);
 made.bytes.fill(0);created.bytes.fill(0);assert.equal(c.verifiedContactFieldIdentity01(made.verified).bytes[0],90);assert.equal(c.verifiedContactTransitionIdentity01(created.verified).bytes[0],90);
});
test('exact genuine previous statement supports reader advance retain then irreversible clear',async()=>{const f=await fixture(),p=c.parseContactMutation01(hex(vector.update_hex));const updated=await mutation(f.mi(p,f.nextStatement,f.first,f.statement,[f.replacement]));const id=c.verifiedContactTransitionIdentity01(updated.verified);assert.equal(id.name.sealRevision,1n);
 const clear=c.parseContactMutation01(hex(vector.clear_hex));const input=f.mi(clear,f.nextStatement,updated.verified,f.nextStatement,[]);input.mutation.previousDigest=id.digest;const out=await mutation(input);assert.equal(c.verifiedContactTransitionIdentity01(out.verified).name.tag,0);
 const resurrect=f.mi({...c.verifiedContactTransitionIdentity01(out.verified),expectedRevision:3n,revision:4n,previousDigest:c.verifiedContactTransitionIdentity01(out.verified).digest,name:id.name},f.nextStatement,out.verified,f.nextStatement,[]);await assert.rejects(mutation(resurrect));
});
test('wrong actual nonextractable root cannot publish signature or historical output',async()=>{const f=await fixture(),wrong=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);await assert.rejects(field({...f.base,rootPrivateKey:wrong.privateKey,field:f.f}));await assert.rejects(mutation({...f.mi(),rootPrivateKey:wrong.privateKey}));});
test('independent scope private brands actual native key and closed inputs refuse before signing',async()=>{const f=await fixture();const original=crypto.subtle.sign;let calls=0;crypto.subtle.sign=function(...args){calls++;return original.apply(this,args);};
 try{for(const change of[{accountId:new Uint8Array(16).fill(4)},{origin:'https://different.example'},{rootFingerprint:new Uint8Array(32).fill(4)}])await assert.rejects(field({...f.base,expected:{...f.expected,...change},field:f.f}));
  for(const change of[{statement:{kind:'historical_integrity'}},{rootPrivateKey:{get type(){throw Error('key getter invoked');}}},{extra:1}])await assert.rejects(field({...f.base,field:f.f,...change}));
  const getter={...f.f};Object.defineProperty(getter,'ciphertext',{get(){throw Error('input getter invoked');}});await assert.rejects(field({...f.base,field:getter}),/Contact producer refused/);
  const exportable=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);await assert.rejects(field({...f.base,rootPrivateKey:exportable.privateKey,field:f.f}));assert.equal(calls,0);
 }finally{crypto.subtle.sign=original;}
});
test('pre-sign mutation CAS statement binding and slot invariants refuse with zero signing calls',async()=>{const f=await fixture(),p=c.parseContactMutation01(hex(vector.update_hex));const original=crypto.subtle.sign;let calls=0;crypto.subtle.sign=function(...args){calls++;return original.apply(this,args);};
 try{const valid=f.mi(p,f.nextStatement,f.first,f.statement,[f.replacement]);for(const change of[{previousStatement:f.nextStatement},{previous:{kind:'historical_integrity',entity:'transition'}},{replacementFields:[f.replacement,f.replacement]},{replacementFields:[f.name,f.replacement]},{previous:null,previousStatement:null}])await assert.rejects(mutation({...valid,...change}));
  for(const change of[{contactId:new Uint8Array(16).fill(4)},{requestId:new Uint8Array(16).fill(4)},{previousDigest:new Uint8Array(32).fill(4)},{name:{tag:1,sealRevision:1n,digest:new Uint8Array(32).fill(4)}},{statementDigest:new Uint8Array(32).fill(4)},{legacyGeneration:1n},{expectedRevision:(1n<<63n)-1n,revision:1n}])await assert.rejects(mutation({...valid,mutation:{...valid.mutation,...change}}));assert.equal(calls,0);
 }finally{crypto.subtle.sign=original;}
});
test('offcurve encapsulation and field bounds refuse before signing and owned bytes survive aliases',async()=>{const f=await fixture(),original=crypto.subtle.sign;let calls=0;crypto.subtle.sign=function(...args){calls++;return original.apply(this,args);};
 try{const point=new Uint8Array(65);point[0]=4;await assert.rejects(field({...f.base,field:{...f.f,encapsulation:point}}));for(const change of[{kind:3},{ciphertext:new Uint8Array(16)},{ciphertext:new Uint8Array(273)},{sealRevision:0n}])await assert.rejects(field({...f.base,field:{...f.f,...change}}));assert.equal(calls,0);
  const i={...f.base,field:{...f.f,ciphertext:f.f.ciphertext.slice(),requestId:f.f.requestId.slice()},expected:{...f.expected,contactId:f.expected.contactId.slice()}};const pending=field(i);i.field.ciphertext.fill(0);i.field.requestId.fill(0);i.expected.contactId.fill(0);const out=await pending;assert.equal(c.verifiedContactFieldIdentity01(out.verified).ciphertext[0],f.f.ciphertext[0]);
 }finally{crypto.subtle.sign=original;}
});
test('abort settles outward while four held actual signing operations retain permits and observe late rejection',async()=>{const f=await fixture(),original=crypto.subtle.sign,releases=[];let calls=0;crypto.subtle.sign=function(...args){const at=++calls,real=original.apply(this,args);return new Promise((resolve,reject)=>{real.then(value=>releases.push(()=>at%2?resolve(value):reject(Error('synthetic late signing refusal'))),error=>releases.push(()=>reject(error)));});};
 try{const controls=Array.from({length:4},()=>new AbortController()),pending=controls.map(signal=>field({...f.base,signal:signal.signal,field:f.f}));await new Promise(resolve=>{const poll=()=>{if(releases.length===4)resolve();else setTimeout(poll,2);};poll();});
  controls.forEach(a=>a.abort());await Promise.all(pending.map(p=>assert.rejects(p,/Contact producer refused/)));await assert.rejects(field({...f.base,field:f.f}));assert.equal(calls,4);releases.forEach(r=>r());await new Promise(r=>setTimeout(r,10));
 }finally{crypto.subtle.sign=original;}assert.equal((await field({...f.base,field:f.f})).kind,'produced_historical_integrity');
});
test('real absolute ten second deadline rejects idle held crypto without premature permit release',async()=>{const f=await fixture(),original=crypto.subtle.sign;let release;crypto.subtle.sign=function(...args){const real=original.apply(this,args);return new Promise((resolve,reject)=>{real.then(value=>{release=()=>resolve(value);},reject);});};
 const start=performance.now();try{await assert.rejects(field({...f.base,field:f.f}),/Contact producer refused/);assert.ok(performance.now()-start>=9900);release();await new Promise(r=>setTimeout(r,10));}finally{crypto.subtle.sign=original;}
});
test('native signal state and event methods cannot be replaced with caller callbacks',async()=>{const f=await fixture(),control=new AbortController();let calls=0;Object.defineProperty(control.signal,'aborted',{get(){calls++;return false;}});Object.defineProperty(control.signal,'addEventListener',{value(){calls++;}});Object.defineProperty(control.signal,'removeEventListener',{value(){calls++;}});
 const pending=field({...f.base,signal:control.signal,field:f.f});control.abort();await assert.rejects(pending,/Contact producer refused/);assert.equal(calls,0);await assert.rejects(field({...f.base,signal:control.signal,field:f.f}));assert.equal(calls,0);
});
