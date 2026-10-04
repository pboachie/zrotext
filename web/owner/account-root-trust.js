// SPDX-License-Identifier: AGPL-3.0-only
// Public local history and dormant issuer review. No key recovery or current permission.
import {enrollRootPin02,verifyManifest02,verifiedManifestIdentity02,verifiedAccountArchiveStatementRecords02} from '/v1/owner/account-root-trust-sdk/sdk/draft02-manifest.js';
import {Draft02TrustStore} from '/v1/owner/account-root-trust-sdk/sdk/draft02-trust-store.js';
import {verifyContactReaderStatement01,verifiedContactReaderStatementIdentity01,encodeContactReaderStatementUnsigned01,parseContactReaderStatement01} from '/v1/owner/account-root-trust-sdk/sdk/contact-reader-statement.js';
const max=(1n<<63n)-1n,encoder=new TextEncoder();let unsettled=0;
function refuse(){throw Error('Local root review unavailable');}
function same(a,b){return a instanceof Uint8Array&&b instanceof Uint8Array&&a.length===b.length&&a.every((v,i)=>v===b[i]);}
function hex(b){return Array.from(b,v=>v.toString(16).padStart(2,'0')).join('');}
function unhex(s,n){if(typeof s!=='string'||s.length!==n*2||!/^[0-9a-f]+$/.test(s))refuse();return Uint8Array.from(s.match(/../g),v=>parseInt(v,16));}
function uuid(s){if(typeof s!=='string'||s.length!==36||!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(s)||s==='00000000-0000-0000-0000-000000000000')refuse();return unhex(s.replaceAll('-',''),16);}
function origin(s){if(typeof s!=='string'||s.length<9||s.length>512||/[^\x21-\x7e]/.test(s))refuse();let u;try{u=new URL(s);}catch{refuse();}if(u.protocol!=='https:'||u.origin!==s||u.username||u.password||u.pathname!=='/'||u.search||u.hash)refuse();return s;}
function integer(s){if(typeof s!=='string'||s.length<1||s.length>19||!/^[1-9][0-9]*$/.test(s))refuse();const v=BigInt(s);if(v>max)refuse();return v;}
function closed(o,keys){if(!o||Object.getPrototypeOf(o)!==Object.prototype||Reflect.ownKeys(o).length!==keys.length)refuse();const out={};for(const k of keys){const d=Object.getOwnPropertyDescriptor(o,k);if(!d||!Object.hasOwn(d,'value'))refuse();out[k]=d.value;}return out;}
// The wire/intent fields are flat canonical scalars. Refuse duplicate names,
// escapes, nested values and extra tokens rather than JSON last-key-wins.
function flatJson(text,limit){
 if(typeof text!=='string'||text.length>limit)refuse();const s=text.replace(/^[ \t\r\n]*|[ \t\r\n]*$/g,'');if(s[0]!=='{'||s.at(-1)!=='}')refuse();const out={};let at=1;
 const field=/"([A-Za-z][A-Za-z0-9_]*)"\s*:\s*(?:"([^"\u005c\u0000-\u001f]*)"|([0-9]+))/y;
 while(at<s.length-1){while(/[ \t\r\n]/.test(s[at]))at++;field.lastIndex=at;const m=field.exec(s);if(!m||Object.hasOwn(out,m[1])||(m[3]&&(!/^(?:0|[1-9][0-9]*)$/.test(m[3])||!Number.isSafeInteger(Number(m[3])))))refuse();out[m[1]]=m[2]??Number(m[3]);at=field.lastIndex;while(/[ \t\r\n]/.test(s[at]))at++;if(at===s.length-1)break;if(s[at++]!==',')refuse();if(s.slice(at,-1).trim()==='')refuse();}return out;
}
function snapshot(s){if(!s)return null;return {trust:{...s.trust,accountId:s.trust.accountId.slice(),rootPoint:s.trust.rootPoint.slice(),digest:s.trust.digest.slice(),anchorDigest:s.trust.anchorDigest.slice()},lastTrustedTimeMs:s.lastTrustedTimeMs};}
function sameSnapshot(a,b){return a===null?b===null:b!==null&&a.lastTrustedTimeMs===b.lastTrustedTimeMs&&['generation','version'].every(k=>a.trust[k]===b.trust[k])&&['accountId','rootPoint','digest','anchorDigest'].every(k=>same(a.trust[k],b.trust[k]));}
function csrf(doc){const tokens=doc.cookie.split(';').map(s=>s.trim()).filter(s=>s.startsWith('__Host-zrotext_csrf='));if(tokens.length!==1||tokens[0].length<24||tokens[0].length>256||/[^\x21-\x7e]/.test(tokens[0]))refuse();return tokens[0];}
/** Syntax extraction only; fingerprint and curve verification stay in the maintained helper. */
export function capturePublicCard(bytes,expectedOrigin){
 origin(expectedOrigin);if(!(bytes instanceof Uint8Array)||bytes.length<142||bytes.length>645)refuse();const b=bytes.slice(),n=new DataView(b.buffer).getUint16(5);
 if(n<9||n>512||b.length!==133+n||!same(b.slice(0,5),Uint8Array.of(90,84,82,67,1))||new TextDecoder('utf-8',{fatal:true}).decode(b.slice(7,7+n))!==expectedOrigin)refuse();
 const pin=b.slice(7+n,101+n);if(!same(pin.slice(0,5),Uint8Array.of(90,84,82,80,2)))refuse();return pin;
}
const expectedKeys=['authorizationId','accountId','origin','trustGeneration','manifestVersion','readerGeneration','rootFingerprint','manifestDigest','readerId','readerPoint','issuedMs','untilMs','capability'];
function expectedStatement(text){
 const parsed=flatJson(text,4096);
 const v=closed(parsed,[...expectedKeys,'statementDigest']);v.authorizationId=uuid(v.authorizationId);v.accountId=uuid(v.accountId);origin(v.origin);
 for(const k of ['rootFingerprint','manifestDigest','readerId','statementDigest'])v[k]=unhex(v[k],32);v.readerPoint=unhex(v.readerPoint,65);
 for(const k of ['trustGeneration','manifestVersion','readerGeneration','issuedMs','untilMs'])v[k]=integer(v[k]);if(v.trustGeneration!==1n||v.capability!==3)refuse();return v;
}
function scalarView(m){return {account:hex(m.accountId),generation:m.generation.toString(),version:m.version.toString(),manifestDigest:hex(m.digest),issuedMs:m.issuedMs.toString(),expiresMs:m.expiresMs.toString(),rootPoint:hex(m.rootPoint),keys:m.keys.map(k=>({role:k.role,id:hex(k.keyId),point:hex(k.point),fromMs:k.fromMs.toString(),untilMs:k.untilMs.toString(),state:k.state}))};}
const issuerPath='/v1/owner/contact-reader-issuance';
const createKeys=['create_request','expected_revision','prior','selected_reader_id','compared_root_fingerprint','requested_until_ms'];
function decimal(s,zero=false){if(zero&&s==='0')return 0n;return integer(s);}
function b64(bytes){let s='';for(const v of bytes)s+=String.fromCharCode(v);return btoa(s);}
function packed(s,min,n,nonzero=false){
 if(typeof s!=='string'||s.length>Math.ceil(n/3)*4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))refuse();
 let b;try{b=Uint8Array.from(atob(s),c=>c.charCodeAt(0));}catch{refuse();}
 if(b.length<min||b.length>n||b64(b)!==s||(nonzero&&!b.some(v=>v)))refuse();return b;
}
function fixed64(s,n){return packed(s,n,n,true);}
function join(...parts){const b=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){b.set(p,at);at+=p.length;}return b;}
function u64(n){const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;}
async function digest(b){return new Uint8Array(await crypto.subtle.digest('SHA-256',b.slice().buffer));}
// Bounded nested wire grammar. Detect duplicates BEFORE materializing members;
// escaped key aliases and unquoted numbers are never accepted as DTO fields.
function issuerJson(text,limit=20480){
 if(typeof text!=='string'||encoder.encode(text).length>limit)refuse();let at=0,members=0;
 const ws=()=>{while(at<text.length&&/[ \t\r\n]/.test(text[at]))at++;};
 const string=key=>{const start=at++;let escape=false;for(;at<text.length;at++){const c=text[at];if(!escape&&c==='"'){at++;const raw=text.slice(start,at);if(key&&!/^"[A-Za-z][A-Za-z0-9_]*"$/.test(raw))refuse();let s;try{s=JSON.parse(raw);}catch{refuse();}if(s.length>16384)refuse();return s;}if(!escape&&c==='\\')escape=true;else escape=false;}refuse();};
 const value=depth=>{if(depth>8)refuse();ws();if(text[at]==='"')return string(false);if(text.slice(at,at+4)==='null'){at+=4;return null;}if(text[at++]!=='{')refuse();const o={};ws();if(text[at]==='}'){at++;return o;}for(;;){ws();if(text[at]!=='"')refuse();const k=string(true);if(Object.hasOwn(o,k)||++members>256)refuse();ws();if(text[at++]!==':')refuse();Object.defineProperty(o,k,{value:value(depth+1),enumerable:true});ws();const c=text[at++];if(c==='}')return o;if(c!==',')refuse();}};
 const result=value(0);ws();if(at!==text.length)refuse();return result;
}
function currentView(input){
 const phase=input?.phase;if(!['empty','active','withdrawn'].includes(phase))refuse();
 const c=closed(input,['phase','mutation_revision','allocation_generation','observed_ms',...(phase==='empty'?[]:['authorization','generation','statement_digest'])]);
 const revision=decimal(c.mutation_revision,true),allocation=decimal(c.allocation_generation,true);decimal(c.observed_ms);if(allocation>revision)refuse();
 if(phase!=='empty'){uuid(c.authorization);if(decimal(c.generation)>allocation)refuse();fixed64(c.statement_digest,32);}
 return c;
}
function priorView(input){const p=closed(input,input?.phase==='empty'?['phase']:['phase','authorization','generation','digest']);if(!['empty','active','withdrawn'].includes(p.phase))refuse();if(p.phase!=='empty'){uuid(p.authorization);decimal(p.generation);fixed64(p.digest,32);}return p;}
function createView(input){const c=closed(input,createKeys);uuid(c.create_request);decimal(c.expected_revision,true);priorView(c.prior);fixed64(c.selected_reader_id,32);fixed64(c.compared_root_fingerprint,32);decimal(c.requested_until_ms);return c;}
function keyView(input){const k=closed(input,['key_id_b64','public_point_b64','from_ms','until_ms']);fixed64(k.key_id_b64,32);if(fixed64(k.public_point_b64,65)[0]!==4||decimal(k.from_ms,true)>=decimal(k.until_ms))refuse();return k;}
function sourceView(input){
 const s=closed(input,['kind','account_id','root_pin_b64','root_fingerprint_b64','trust_generation','manifest_version','manifest_digest_b64','manifest_b64','observed_ms','manifest_issued_ms','manifest_expires_ms','signed_until_ms','reader','root_writer']);
 if(s.kind!=='historical_creation_source'||decimal(s.trust_generation)!==1n)refuse();uuid(s.account_id);fixed64(s.root_pin_b64,94);fixed64(s.root_fingerprint_b64,32);fixed64(s.manifest_digest_b64,32);packed(s.manifest_b64,364,9751);decimal(s.manifest_version);decimal(s.observed_ms);decimal(s.manifest_issued_ms);decimal(s.manifest_expires_ms);decimal(s.signed_until_ms);keyView(s.reader);keyView(s.root_writer);return s;
}
function resultView(input){
 if(input?.kind==='unavailable'){closed(input,['kind']);return input;}
 if(input?.kind==='pending'){
  const p=closed(input,['kind','create_input_digest','create_request','authorization','generation','creation_expected_revision','allocated_revision','unsigned_digest','unsigned','issued_ms','expires_ms','until_ms','created_by_user','created_session','creation_source','current']);
  for(const k of ['create_request','authorization','created_by_user','created_session'])uuid(p[k]);for(const k of ['create_input_digest','unsigned_digest'])fixed64(p[k],32);
  for(const k of ['generation','allocated_revision','issued_ms','expires_ms','until_ms'])decimal(p[k]);decimal(p.creation_expected_revision,true);packed(p.unsigned,250,753);sourceView(p.creation_source);currentView(p.current);return p;
 }
 if(['historical_completed','cancelled','expired'].includes(input?.kind)){
  const p=closed(input,['kind','create_input_digest','create_request','authorization','generation','creation_expected_revision','unsigned_digest','terminal_ms','current',...(input.kind==='historical_completed'?['signed_statement','statement_digest']:[])]);
  for(const k of ['create_request','authorization'])uuid(p[k]);for(const k of ['create_input_digest','unsigned_digest'])fixed64(p[k],32);decimal(p.generation);decimal(p.creation_expected_revision,true);decimal(p.terminal_ms);currentView(p.current);
  if(p.kind==='historical_completed'){packed(p.signed_statement,314,817);fixed64(p.statement_digest,32);}return p;
 }
 if(['withdrawn','already_withdrawn'].includes(input?.kind)){const p=closed(input,['kind','authorization','generation','statement_digest','mutation_revision','observed_ms']);uuid(p.authorization);decimal(p.generation);fixed64(p.statement_digest,32);decimal(p.mutation_revision,true);decimal(p.observed_ms);return p;}
 refuse();
}
async function createDigest(c,account,host){
 const o=encoder.encode(host),length=new Uint8Array(2);new DataView(length.buffer).setUint16(0,o.length);const p=priorView(c.prior),empty=p.phase==='empty';
 return digest(join(Uint8Array.of(1),account,length,o,uuid(c.create_request),u64(decimal(c.expected_revision,true)),Uint8Array.of(empty?0:p.phase==='active'?1:2),empty?new Uint8Array(16):uuid(p.authorization),u64(empty?0n:decimal(p.generation)),empty?new Uint8Array(32):fixed64(p.digest,32),fixed64(c.selected_reader_id,32),fixed64(c.compared_root_fingerprint,32),u64(decimal(c.requested_until_ms))));
}
class Review {
 #doc;#win;#nodes;#record=null;#closed=false;#busy=false;#unknown=null;#lastWall=0;#listeners=[];#phase='EMPTY_INPUT';#issuer=null;#issuerUnknown=null;
 constructor(){
  this.#doc=globalThis.document;this.#win=globalThis.window;
  if(!this.#doc||!this.#win||this.#doc.hidden)refuse();origin(this.#win.location.origin);
  this.#nodes=Object.fromEntries(['account','origin','fingerprint','card','manifest','inputs','review','decision','tuple','accept','decline','status','reconcile','expected','statement','verify-statement'].map(k=>{const el=this.#doc.getElementById(k);if(!el)refuse();return [k,el];}));
  for(const id of ['bundle','reader-id','reader-point','requested-until','issuer-review','issuer-create','issuer-retry','issuer-export','issuer-recovery-export','issuer-import','issuer-signature','issuer-complete','issuer-factor','issuer-lookup','issuer-cancel','issuer-withdraw','issuer-decline','issuer-facts','issuer-status','issuer-recovery','issuer-recover']){const el=this.#doc.getElementById(id);if(!el)refuse();this.#nodes[id]=el;}
  for(const [target,event,fn]of [[this.#doc,'visibilitychange',()=>{if(this.#doc.hidden)this.close();}],[this.#win,'pagehide',()=>this.close()]]){target.addEventListener(event,fn);this.#listeners.push([target,event,fn]);}
  this.#bind('inputs','submit',()=>this.prepare());this.#bind('accept','click',()=>this.accept());this.#bind('decline','click',()=>this.decline());this.#bind('reconcile','click',()=>this.reconcile());this.#bind('verify-statement','click',()=>this.verifyStatement());
  for(const [id,fn] of [['issuer-review',()=>this.#prepareIssuer()],['issuer-create',()=>this.#createIssuer(false)],['issuer-retry',()=>this.#createIssuer(true)],['issuer-export',()=>this.#exportIssuer()],['issuer-recovery-export',()=>this.#exportRecovery()],['issuer-import',()=>this.#importIssuer()],['issuer-complete',()=>this.#completeIssuer()],['issuer-lookup',()=>this.#lookupIssuer()],['issuer-cancel',()=>this.#reduceIssuer(false)],['issuer-withdraw',()=>this.#reduceIssuer(true)],['issuer-decline',()=>this.#endIssuer()],['issuer-recover',()=>this.#recoverIssuer()]])this.#bind(id,'click',fn);
  this.#issuerStatus('UNAVAILABLE','Reader issuance is unavailable until an admitted owner state and authenticated handler exist.');
  this.#nodes.review.disabled=false;this.#status('EMPTY_INPUT','Ready for independent public kit review.');
 }
 #bind(id,event,fn){const listener=e=>{e.preventDefault();Promise.resolve().then(fn).catch(()=>{if(id.startsWith('issuer-'))this.#issuerStatus(this.#issuerUnknown?'UNKNOWN':'UNAVAILABLE',this.#issuerUnknown?'The original outcome is unknown. Read its outcome; do not start another intent.':'Reader issuance unavailable. No replacement intent was created.');else if(!this.#closed&&this.#phase!=='UNKNOWN')this.#status('UNAVAILABLE','Local review unavailable. Check the independent kit and owner session.');});};this.#nodes[id].addEventListener(event,listener);this.#listeners.push([this.#nodes[id],event,listener]);}
 #status(phase,text){this.#phase=phase;this.#nodes.status.textContent=text;this.#nodes.review.disabled=this.#closed||!!this.#unknown||!!this.#issuerUnknown||!!this.#issuer?.active;this.#nodes.accept.disabled=phase!=='REVIEWING';this.#nodes['verify-statement'].disabled=phase!=='LOCAL_ACCEPTED_HISTORY'||!!this.#issuer?.active;this.#nodes.reconcile.hidden=!this.#unknown||this.#closed;this.#nodes['issuer-review'].disabled=phase!=='LOCAL_ACCEPTED_HISTORY'||!!this.#issuerUnknown||!!this.#issuer?.active;}
 #now(){const n=Date.now();if(!Number.isSafeInteger(n)||n<1||BigInt(n)>max||n<this.#lastWall)refuse();this.#lastWall=n;return BigInt(n);}
 #live(r){if(this.#closed||this.#doc.hidden||r.abort.signal.aborted||performance.now()>=r.deadline||this.#record!==r)refuse();}
 #arm(r,deadline){r.deadline=Math.min(r.deadline,deadline);this.#live(r);clearTimeout(r.timer);r.timer=setTimeout(()=>this.#forget(r),Math.max(0,r.deadline-performance.now()));}
 #new(selectedAccount){if(this.#closed||this.#busy||this.#doc.hidden)refuse();const token=csrf(this.#doc);if(this.#record)this.#forget(this.#record);const account=selectedAccount.slice(),expectedAccount=hex(account).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');const started=performance.now(),r={account,expectedAccount,abort:new AbortController(),deadline:started+10000,reviewDeadline:started+300000,timer:null,store:null,buffers:[account],possibleWrite:false,session:null,csrf:token};this.#record=r;this.#busy=true;try{this.#arm(r,r.deadline);return r;}catch(e){this.#forget(r);this.#busy=false;throw e;}}
 #forget(r){
  if(this.#issuer?.r===r)this.#endIssuer();
  if(r.possibleWrite&&r.unknown)this.#unknown={...r.unknown};clearTimeout(r.timer);r.abort.abort();if(r.store)r.store.close();for(const b of r.buffers)b.fill(0);r.buffers.length=0;r.manifest=null;r.identity=null;r.before=null;r.session=null;
  if(this.#record===r){this.#record=null;this.#nodes.decision.hidden=true;this.#nodes.tuple.textContent='';this.#status(this.#unknown?'UNKNOWN':'DECLINED',this.#unknown?'A local write may have started. Read the local outcome; do not automatically retry.':'Local decision closed.');}
 }
 async #race(p,r,deadline=r.deadline){
  const observed=Promise.resolve(p);observed.catch(()=>{});this.#live(r);
  let reject,timeout;const stopped=new Promise((_,no)=>{reject=()=>no(Error('Local root review closed'));r.abort.signal.addEventListener('abort',reject,{once:true});timeout=setTimeout(reject,Math.max(0,Math.min(r.deadline,deadline)-performance.now()));});
  try{const value=await Promise.race([observed,stopped]);this.#live(r);if(performance.now()>=deadline)refuse();return value;}finally{clearTimeout(timeout);r.abort.signal.removeEventListener('abort',reject);}
 }
 async #job(r,fn,late,deadline=r.deadline){
  this.#live(r);if(performance.now()>=deadline||unsettled>=4)refuse();unsettled++;
  const p=Promise.resolve().then(()=>{this.#live(r);if(performance.now()>=deadline)refuse();return fn();}).then(v=>{if((r.abort.signal.aborted||this.#closed||performance.now()>=Math.min(r.deadline,deadline))&&late)late(v);return v;}).finally(()=>{unsettled--;});
  return this.#race(p,r,deadline);
 }
 async #session(r){
  const deadline=Math.min(r.deadline,performance.now()+10000);
  this.#live(r);if(this.#nodes.account.value!==r.expectedAccount||csrf(this.#doc)!==r.csrf)refuse();
  const response=await this.#job(r,()=>this.#win.fetch('/v1/auth/session',{credentials:'same-origin',cache:'no-store',redirect:'error',signal:r.abort.signal}),undefined,deadline);
  if(response.status!==200||response.redirected||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')||!response.body)refuse();
  const reader=response.body.getReader();let b=new Uint8Array(0);
  try{for(;;){const item=await this.#job(r,()=>reader.read(),undefined,deadline);if(item.done)break;if(b.length+item.value.length>1024)refuse();const next=new Uint8Array(b.length+item.value.length);next.set(b);next.set(item.value,b.length);b=next;}}finally{reader.cancel().catch(()=>{});reader.releaseLock();}
  const body=flatJson(new TextDecoder('utf-8',{fatal:true}).decode(b),1024);
  const s=closed(body,['account_id','user_id','session_id','role']);for(const k of ['account_id','user_id','session_id'])uuid(s[k]);if(s.role!=='owner'||s.account_id!==r.expectedAccount||this.#nodes.account.value!==r.expectedAccount||csrf(this.#doc)!==r.csrf)refuse();
  if(r.session&&['account_id','user_id','session_id','role'].some(k=>r.session[k]!==s[k]))refuse();r.session=s;this.#live(r);return s;
 }
 #selection(node,min,maxSize){const list=node.files;if(!list||list.length!==1||!(list[0] instanceof this.#win.File)||list[0].size<min||list[0].size>maxSize)refuse();return list[0];}
 async #file(r,f,min,maxSize){const b=new Uint8Array(await this.#job(r,()=>f.arrayBuffer(),v=>new Uint8Array(v).fill(0),Math.min(r.deadline,performance.now()+10000))).slice();if(b.length!==f.size||b.length<min||b.length>maxSize)refuse();r.buffers.push(b);return b;}
 async #open(r){r.store=await this.#job(r,()=>Draft02TrustStore.open(),s=>s.close());return r.store;}
 async prepare(){
  if(this.#unknown||this.#issuerUnknown||this.#issuer?.active)refuse();
  const account=uuid(this.#nodes.account.value),visibleOrigin=origin(this.#nodes.origin.value),fingerprint=unhex(this.#nodes.fingerprint.value,32),cardFile=this.#selection(this.#nodes.card,142,645),manifestFile=this.#selection(this.#nodes.manifest,364,9751);if(visibleOrigin!==this.#win.location.origin)refuse();
  const r=this.#new(account);try{
   const card=await this.#file(r,cardFile,142,645),signed=await this.#file(r,manifestFile,364,9751),pin=capturePublicCard(card,visibleOrigin);r.buffers.push(pin);
   const trust=await this.#job(r,()=>enrollRootPin02(pin,fingerprint));if(trust.generation!==1n||!same(trust.accountId,account))refuse();
   await this.#session(r);const store=await this.#open(r),before=await this.#job(r,()=>store.read());if(before&&(before.trust.generation!==1n||!same(before.trust.accountId,account)||!same(before.trust.rootPoint,trust.rootPoint)))refuse();
   const now=this.#now(),manifest=await this.#job(r,()=>verifyManifest02(signed,before?.trust??trust,now)),m={...manifest,...verifiedManifestIdentity02(manifest,now)};
   if(!before||before.trust.version===0n){if(m.version!==1n||m.previousDigest.some(v=>v!==0))refuse();}
   const life=Number(m.expiresMs-now);if(life<=0)refuse();r.reviewDeadline=Math.min(r.reviewDeadline,performance.now()+life);r.origin=visibleOrigin;r.fingerprint=fingerprint;r.pin=pin;r.signed=signed;r.before=snapshot(before);r.manifest=manifest;r.identity=m;r.comparisonMs=now;r.buffers.push(account,fingerprint);
   await this.#session(r);this.#live(r);r.deadline=r.reviewDeadline;this.#arm(r,r.deadline);this.#nodes.tuple.textContent=JSON.stringify({origin:visibleOrigin,fingerprint:hex(fingerprint),priorState:before===null?'NO_LOCAL_ROOT':before.trust.version===0n?'PIN_ONLY':'ACCEPTED_LOCAL_HISTORY',previousVersion:before?.trust.version.toString()??'absent',...scalarView(m)},null,2);this.#nodes.decision.hidden=false;this.#status('REVIEWING','Compare the complete tuple before accepting local history.');return this.status();
  }catch(e){this.#forget(r);throw e;}finally{this.#busy=false;}
 }
 async accept(){
  const r=this.#record;if(!r||this.#phase!=='REVIEWING'||this.#busy)refuse();this.#busy=true;
  try{
   this.#arm(r,Math.min(r.deadline,performance.now()+10000));await this.#session(r);const now=this.#now();if(now>=r.identity.expiresMs)refuse();
   const before=await this.#job(r,()=>r.store.read());if(!sameSnapshot(r.before,before))refuse();
   r.unknown={account:r.session.account_id,origin:r.origin,fingerprint:hex(r.fingerprint),version:r.identity.version.toString(),digest:hex(r.identity.digest),comparisonMs:now.toString()};r.possibleWrite=true;
   if(!before)await this.#job(r,()=>r.store.enroll(r.pin,r.fingerprint,now));
   await this.#job(r,()=>r.store.acceptManifest(r.signed,now));
   const after=await this.#job(r,()=>r.store.read());if(!after||after.trust.version!==r.identity.version||!same(after.trust.digest,r.identity.digest)||!same(after.trust.accountId,r.account)||!same(after.trust.rootPoint,r.identity.rootPoint))refuse();
   const history=await this.#job(r,()=>r.store.verifyStoredHistory(r.identity.digest,now));if(!same(verifiedManifestIdentity02(history,now).digest,r.identity.digest))refuse();
   const last=await this.#job(r,()=>r.store.read());if(!sameSnapshot(after,last))refuse();await this.#session(r);this.#live(r);r.before=snapshot(last);r.comparisonMs=now;
   r.reviewDeadline=Math.min(r.reviewDeadline,performance.now()+Number(r.identity.expiresMs-this.#now()));r.deadline=r.reviewDeadline;this.#arm(r,r.deadline);this.#live(r);r.possibleWrite=false;this.#unknown=null;this.#status('LOCAL_ACCEPTED_HISTORY','Signed local history accepted. This is not current contact permission or custody.');return this.status();
  }catch(e){this.#forget(r);throw e;}finally{this.#busy=false;}
 }
 decline(){if(this.#record)this.#forget(this.#record);return this.status();}
 async reconcile(){
  if(!this.#unknown)refuse();const unknown={...this.#unknown},r=this.#new(uuid(unknown.account));let matched=false;try{
   await this.#session(r);if(r.session.account_id!==unknown.account)refuse();const store=await this.#open(r),before=await this.#job(r,()=>store.read());
   if(!before||before.trust.generation!==1n||!same(before.trust.accountId,uuid(unknown.account)))refuse();
   const pin=new Uint8Array(94);pin.set([90,84,82,80,2]);pin.set(before.trust.accountId,5);new DataView(pin.buffer).setBigUint64(21,1n);pin.set(before.trust.rootPoint,29);
   await this.#job(r,()=>enrollRootPin02(pin,unhex(unknown.fingerprint,32)));await this.#job(r,()=>store.verifyStoredHistory(unhex(unknown.digest,32),integer(unknown.comparisonMs)));
   const after=await this.#job(r,()=>store.read());if(!sameSnapshot(before,after)||after.trust.version!==integer(unknown.version)||!same(after.trust.digest,unhex(unknown.digest,32)))refuse();await this.#session(r);this.#live(r);
   matched=true;return Object.freeze({kind:'local_content_match',unknown:Object.freeze({...unknown})});
  }finally{this.#forget(r);this.#busy=false;if(matched&&!this.#closed)this.#status('UNKNOWN','Stored content matches the possible write. This does not prove which operation committed or grant current permission.');}
 }
 async verifyStatement(){
  const r=this.#record;if(!r||this.#phase!=='LOCAL_ACCEPTED_HISTORY'||this.#busy||this.#issuer?.active)refuse();const expected=expectedStatement(this.#nodes.expected.value),file=this.#selection(this.#nodes.statement,314,817);if(!same(expected.accountId,r.account)||expected.origin!==r.origin||!same(expected.rootFingerprint,r.fingerprint))refuse();this.#busy=true;
  let bytes;try{
   this.#arm(r,Math.min(r.deadline,performance.now()+10000));await this.#session(r);bytes=await this.#file(r,file,314,817);const before=await this.#job(r,()=>r.store.read()),manifest=await this.#job(r,()=>r.store.verifyStoredHistory(expected.manifestDigest,expected.issuedMs));
   const verified=await this.#job(r,()=>verifyContactReaderStatement01({bytes,acceptedManifest:manifest,expectedAccountId:r.account,expectedOrigin:r.origin,expectedRootFingerprint:r.fingerprint,comparison:'declared_issued_ms'})),actual=verifiedContactReaderStatementIdentity01(verified);
   for(const k of expectedKeys){if(expected[k] instanceof Uint8Array?!same(expected[k],actual[k]):expected[k]!==actual[k])refuse();}
   if(!same(expected.statementDigest,actual.digest))refuse();
   if(!sameSnapshot(before,await this.#job(r,()=>r.store.read())))refuse();await this.#session(r);this.#live(r);r.deadline=r.reviewDeadline;this.#arm(r,r.deadline);this.#status('LOCAL_ACCEPTED_HISTORY','Historical reader statement integrity verified; no current permission or private custody.');return Object.freeze({kind:'historical_integrity',statementDigest:hex(actual.digest)});
  }catch(e){this.#forget(r);throw e;}finally{if(bytes){bytes.fill(0);r.buffers=r.buffers.filter(v=>v!==bytes);}this.#busy=false;}
 }
 #issuerStatus(phase,text){
  this.#nodes['issuer-status'].textContent=text;const p=this.#issuer,active=!!p?.active&&!this.#closed;
  for(const id of ['issuer-create','issuer-retry','issuer-export','issuer-import','issuer-complete','issuer-lookup','issuer-cancel','issuer-withdraw','issuer-decline'])this.#nodes[id].disabled=true;
  this.#nodes['issuer-create'].disabled=!active||phase!=='REVIEWING';this.#nodes['issuer-retry'].disabled=!active||phase!=='UNKNOWN'||!!p?.pending||p?.slots>=3;
  this.#nodes['issuer-export'].disabled=this.#closed||!this.#issuerUnknown?.pending;this.#nodes['issuer-recovery-export'].disabled=this.#closed||!this.#issuerUnknown;this.#nodes['issuer-import'].disabled=!active||!p?.pending||!!p.signed;
  this.#nodes['issuer-complete'].disabled=!active||!p?.signed||p.slots>=3;this.#nodes['issuer-decline'].disabled=!active;
  this.#nodes['issuer-lookup'].disabled=this.#closed||!this.#issuerUnknown;this.#nodes['issuer-cancel'].disabled=this.#closed||!this.#issuerUnknown?.pending;
  this.#nodes['issuer-withdraw'].disabled=this.#closed||!this.#issuerUnknown;
  this.#nodes['issuer-recover'].disabled=this.#closed||!!this.#issuerUnknown||active;
 }
 #endIssuer(){
  const p=this.#issuer;if(p){p.active=false;clearTimeout(p.timer);p.requestAbort?.abort();p.r.abort.abort();if(p.r.store){p.r.store.close();p.r.store=null;}for(const b of p.r.buffers)b.fill(0);p.r.buffers.length=0;p.r.manifest=null;p.r.identity=null;p.r.before=null;p.r.session=null;p.signed=null;p.manifest=null;}
  this.#nodes['issuer-factor'].value='';this.#nodes['issuer-facts'].textContent='';
  this.#issuerStatus(this.#issuerUnknown?'UNKNOWN':'DECLINED',this.#issuerUnknown?'Positive approval ended. Read or reduce only the exact original intent.':'Positive approval ended. No intent was sent.');
 }
 #issuerLive(p){
  try{this.#live(p.r);this.#now();if(this.#issuer!==p||!p.active||performance.now()>=p.deadline||this.#nodes.account.value!==p.account||this.#nodes.origin.value!==p.origin||this.#nodes.fingerprint.value!==p.fingerprint||this.#nodes.bundle.value!==p.bundle||this.#nodes['reader-id'].value!==p.reader||this.#nodes['reader-point'].value!==p.point||this.#nodes['requested-until'].value!==p.until)refuse();this.#live(p.r);}catch(e){this.#endIssuer();throw e;}
 }
 async #issuerRequest(r,path,body,positive=null,cap=20480,consume=false){
  const deadline=Math.min(r.deadline,performance.now()+10000,positive?.deadline??Infinity);
  if(positive)this.#issuerLive(positive);this.#live(r);this.#now();
  const abort=new AbortController(),onAbort=()=>abort.abort();r.abort.signal.addEventListener('abort',onAbort,{once:true});const timer=setTimeout(onAbort,Math.max(0,deadline-performance.now()));
  if(positive)positive.requestAbort=abort;
  try{
   const reference=csrf(this.#doc);if(reference!==r.csrf||this.#nodes.account.value!==r.expectedAccount)refuse();
   const headers={'x-zrotext-csrf':reference.slice('__Host-zrotext_csrf='.length)};if(body!==null){headers['Content-Type']='application/json';if(encoder.encode(body).length>8192)refuse();}
   const response=await this.#job(r,()=>{
    if(positive)this.#issuerLive(positive);
    if(this.#nodes.account.value!==r.expectedAccount||csrf(this.#doc)!==reference)refuse();
    this.#live(r);
    if(consume){if(!positive||positive.slots>=3)refuse();positive.slots++;this.#issuerUnknown=positive.original;}
    return this.#win.fetch(path,{method:body===null?'GET':'POST',headers,body:body??undefined,credentials:'same-origin',cache:'no-store',redirect:'error',signal:abort.signal});
   },v=>{if(v?.body)Promise.resolve(v.body.cancel()).catch(()=>{});},deadline);
   if(response.status!==200||response.redirected||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')||!response.body)refuse();
   const reader=response.body.getReader();let bytes=new Uint8Array(0);
   try{for(;;){const v=await this.#job(r,()=>reader.read(),undefined,deadline);if(v.done)break;if(!(v.value instanceof Uint8Array)||bytes.length+v.value.length>cap)refuse();bytes=join(bytes,v.value);}}finally{reader.cancel().catch(()=>{});reader.releaseLock();}
   this.#live(r);this.#now();if(csrf(this.#doc)!==reference||this.#nodes.account.value!==r.expectedAccount)refuse();if(positive)this.#issuerLive(positive);
   const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);return {value:issuerJson(text,cap),text};
  }finally{clearTimeout(timer);r.abort.signal.removeEventListener('abort',onAbort);abort.abort();if(positive?.requestAbort===abort)positive.requestAbort=null;}
 }
 async #issuerHistory(r,source,selected){
  const before=await this.#job(r,()=>r.store.read());if(!before||!sameSnapshot(r.before,before))refuse();
  const m=await this.#job(r,()=>r.store.verifyStoredHistory(fixed64(source.manifest_digest_b64,32),decimal(source.observed_ms)));
  const facts=verifiedAccountArchiveStatementRecords02(m,selected,decimal(source.observed_ms));
  if(!same(m.bytes,packed(source.manifest_b64,364,9751))||!same(facts.accountId,r.account)||facts.generation!==1n||facts.version!==decimal(source.manifest_version)||facts.issuedMs!==decimal(source.manifest_issued_ms)||facts.expiresMs!==decimal(source.manifest_expires_ms)||!same(r.pin,fixed64(source.root_pin_b64,94))||!same(r.fingerprint,fixed64(source.root_fingerprint_b64,32)))refuse();
  for(const [k,id,point,from,until]of [['reader',facts.readerId,facts.readerPoint,facts.readerFromMs,facts.readerUntilMs],['root_writer',facts.rootWriterId,facts.rootPoint,facts.rootFromMs,facts.rootUntilMs]]){const v=source[k];if(!same(fixed64(v.key_id_b64,32),id)||!same(fixed64(v.public_point_b64,65),point)||decimal(v.from_ms,true)!==from||decimal(v.until_ms)!==until)refuse();}
  if(!sameSnapshot(before,await this.#job(r,()=>r.store.read())))refuse();return {manifest:m,facts};
 }
 async #prepareIssuer(){
  const r=this.#record;if(!r||this.#phase!=='LOCAL_ACCEPTED_HISTORY'||this.#busy||this.#issuerUnknown||this.#issuer?.active)refuse();
  const bundle=this.#nodes.bundle.value,reader=this.#nodes['reader-id'].value,point=this.#nodes['reader-point'].value,until=this.#nodes['requested-until'].value;
  if(!unhex(bundle,16).some(v=>v)||!unhex(reader,32).some(v=>v)||unhex(point,65)[0]!==4||decimal(until)<=this.#now())refuse();
  const p={r,account:r.expectedAccount,origin:r.origin,fingerprint:hex(r.fingerprint),bundle,reader,point,until,slots:0,active:true,deadline:performance.now()+60000,pending:null,signed:null,timer:null,original:null};this.#issuer=p;
  p.deadline=Math.min(p.deadline,r.reviewDeadline,performance.now()+Number(decimal(until)-this.#now()));p.timer=setTimeout(()=>this.#endIssuer(),Math.max(0,p.deadline-performance.now()));this.#busy=true;
  try{
   this.#issuerLive(p);await this.#session(r);this.#issuerLive(p);
   const response=await this.#issuerRequest(r,'/v1/owner/export?contact_reader_only=state',null,p,4096),v=closed(response.value,['kind','state']);this.#issuerLive(p);
   if(v.kind!=='contact_reader_state'||v.state===null)refuse();const s=closed(v.state,['root_pin_b64','root_fingerprint_b64','trust_generation','last_mutation_ms','current','signed_statement']);
   if(decimal(s.trust_generation)!==1n||!same(fixed64(s.root_pin_b64,94),r.pin)||!same(fixed64(s.root_fingerprint_b64,32),r.fingerprint))refuse();const c=currentView(s.current);if(decimal(s.last_mutation_ms)>decimal(c.observed_ms)||decimal(c.observed_ms)>this.#now()||decimal(c.mutation_revision,true)>max-2n)refuse();p.observed=decimal(c.observed_ms);
   if(c.phase==='active'){
    const bytes=packed(s.signed_statement,314,817),parsed=await this.#job(r,()=>parseContactReaderStatement01(bytes)),history=await this.#job(r,()=>r.store.verifyStoredHistory(parsed.manifestDigest,parsed.issuedMs));
    const verified=await this.#job(r,()=>verifyContactReaderStatement01({bytes,acceptedManifest:history,expectedAccountId:r.account,expectedOrigin:r.origin,expectedRootFingerprint:r.fingerprint,comparison:'declared_issued_ms'})),identity=verifiedContactReaderStatementIdentity01(verified);
    if(!same(identity.authorizationId,uuid(c.authorization))||identity.readerGeneration!==decimal(c.generation)||!same(identity.digest,fixed64(c.statement_digest,32)))refuse();
   }else if(s.signed_statement!==null)refuse();
   const before=await this.#job(r,()=>r.store.read());if(!sameSnapshot(r.before,before))refuse();const m=await this.#job(r,()=>r.store.verifyStoredHistory(r.identity.digest,r.comparisonMs)),facts=verifiedAccountArchiveStatementRecords02(m,unhex(reader,32),this.#now());if(!same(facts.readerPoint,unhex(point,65))||decimal(until)>facts.expiresMs||decimal(until)>facts.readerUntilMs||decimal(until)>facts.rootUntilMs)refuse();
   const prior=Object.freeze(c.phase==='empty'?{phase:'empty'}:{phase:c.phase,authorization:c.authorization,generation:c.generation,digest:c.statement_digest});
   p.create=Object.freeze({create_request:crypto.randomUUID(),expected_revision:c.mutation_revision,prior,selected_reader_id:b64(unhex(reader,32)),compared_root_fingerprint:b64(r.fingerprint),requested_until_ms:until});createView(p.create);p.createJson=JSON.stringify(p.create);p.inputDigest=b64(await this.#job(r,()=>createDigest(p.create,r.account,p.origin)));
   if(!sameSnapshot(before,await this.#job(r,()=>r.store.read())))refuse();await this.#session(r);this.#issuerLive(p);
   p.original={account:p.account,origin:p.origin,bundle,reader_point:point,create:p.create,createJson:p.createJson,inputDigest:p.inputDigest,pending:null,pendingJson:null,signed:null,observed:p.observed};
   this.#nodes['issuer-facts'].textContent=JSON.stringify({account:p.account,origin:p.origin,bundle,rootFingerprint:p.fingerprint,readerId:reader,readerPoint:point,requestedUntil:until,originalCreate:p.create},null,2);this.#issuerStatus('REVIEWING','Compare these facts. Approval permits this original intent only.');
  }catch(e){this.#endIssuer();throw e;}finally{this.#busy=false;}
 }
 async #pending(p,value,positive){
  const v=resultView(value);if(v.kind!=='pending')refuse();const c=p.create,s=v.creation_source;
  if(v.create_request!==c.create_request||v.creation_expected_revision!==c.expected_revision||v.create_input_digest!==p.inputDigest||decimal(v.allocated_revision)!==decimal(c.expected_revision,true)+1n||decimal(v.current.mutation_revision,true)<decimal(v.allocated_revision)||decimal(v.generation)>decimal(v.current.allocation_generation,true)||s.account_id!==p.account||s.root_fingerprint_b64!==c.compared_root_fingerprint||s.reader.key_id_b64!==c.selected_reader_id||hex(fixed64(s.reader.public_point_b64,65))!==p.point||decimal(s.observed_ms)>decimal(v.issued_ms)||decimal(v.until_ms)>decimal(c.requested_until_ms)||v.until_ms!==s.signed_until_ms||decimal(v.until_ms)<=decimal(v.issued_ms)||decimal(v.expires_ms)<=decimal(v.issued_ms)||decimal(v.expires_ms)>decimal(v.issued_ms)+300000n)refuse();
  if(decimal(v.current.observed_ms)<decimal(v.issued_ms)||decimal(v.current.observed_ms)<(p.observed??0n))refuse();
  const unsigned=packed(v.unsigned,250,753);if(!same(await this.#job(p.r,()=>digest(unsigned)),fixed64(v.unsigned_digest,32)))refuse();
  const expected=encodeContactReaderStatementUnsigned01({authorizationId:uuid(v.authorization),accountId:uuid(p.account),origin:p.origin,trustGeneration:1n,manifestVersion:decimal(s.manifest_version),readerGeneration:decimal(v.generation),rootFingerprint:fixed64(c.compared_root_fingerprint,32),manifestDigest:fixed64(s.manifest_digest_b64,32),readerId:fixed64(c.selected_reader_id,32),readerPoint:unhex(p.point,65),issuedMs:decimal(v.issued_ms),untilMs:decimal(v.until_ms),capability:3});if(!same(expected,unsigned))refuse();
  if(p.pending&&(p.pending.authorization!==v.authorization||p.pending.generation!==v.generation||p.pending.unsigned!==v.unsigned||JSON.stringify(p.pending.creation_source)!==JSON.stringify(s)))refuse();
  if(positive){if(v.created_by_user!==p.r.session.user_id||v.created_session!==p.r.session.session_id||decimal(v.expires_ms)<=this.#now())refuse();const h=await this.#issuerHistory(p.r,s,unhex(p.reader,32));if(decimal(v.until_ms)>h.facts.expiresMs||decimal(v.until_ms)>h.facts.readerUntilMs||decimal(v.until_ms)>h.facts.rootUntilMs)refuse();this.#issuerLive(p);p.deadline=Math.min(p.deadline,performance.now()+Number(decimal(v.expires_ms)-this.#now()),performance.now()+Number(decimal(v.until_ms)-this.#now()));clearTimeout(p.timer);p.timer=setTimeout(()=>this.#endIssuer(),Math.max(0,p.deadline-performance.now()));}
  return v;
 }
 async #createIssuer(retry){
  const p=this.#issuer;if(!p||this.#busy||!p.original||p.pending||p.slots>=3||retry!==(p.slots>0))refuse();this.#busy=true;
  try{this.#issuerLive(p);await this.#positiveSession(p);const response=await this.#issuerRequest(p.r,issuerPath+'/intents',p.createJson,p,20480,true),pending=await this.#pending(p,response.value,true);await this.#positiveSession(p);p.pending=pending;p.original.pending=p.pending;p.original.pendingJson=response.text;this.#issuerUnknown=p.original;this.#issuerStatus('PENDING','Original intent saved. Export its public proposal for the existing offline signer.');}
  catch(e){this.#issuerStatus(this.#issuerUnknown?'UNKNOWN':'UNAVAILABLE','Original intent outcome unavailable. Reconcile it; do not replace its identity.');throw e;}finally{this.#busy=false;}
 }
 #exportIssuer(){
  const o=this.#issuerUnknown;if(!o?.pendingJson||this.#closed)refuse();const text='{"create":'+o.createJson+',"pending":'+o.pendingJson+'}';if(encoder.encode(text).length>32768)refuse();
  this.#nodes['issuer-facts'].textContent='Command template: replace both file paths. Compare the full fingerprint in the offline ceremony: '+hex(fixed64(o.create.compared_root_fingerprint,32))+'\ncontact-reader-sign --account '+o.account+' --origin '+o.origin+' --bundle '+o.bundle+' --proposal <absolute-existing-proposal-path> --output <absolute-new-output-path> --reader '+hex(fixed64(o.create.selected_reader_id,32))+' --reader-point '+o.reader_point+' --until '+o.create.requested_until_ms+'\nPublic proposal:\n'+text;
  this.#download('contact-reader-proposal.json',text);
 }
 #exportRecovery(){const o=this.#issuerUnknown;if(!o||this.#closed)refuse();const text=JSON.stringify({account:o.account,origin:o.origin,bundle:o.bundle,reader_point:o.reader_point,create:o.create,inputDigest:o.inputDigest,pending:o.pending,signed:o.signed});if(encoder.encode(text).length>32768)refuse();this.#download('contact-reader-recovery.json',text);}
 #download(name,text){const bytes=encoder.encode(text);if(bytes.length>32768||this.#closed)refuse();const url=this.#win.URL.createObjectURL(new this.#win.Blob([bytes],{type:'application/json'})),a=this.#doc.createElement('a');try{a.href=url;a.download=name;a.click();}finally{this.#win.URL.revokeObjectURL(url);}}
 async #importIssuer(){
  const p=this.#issuer;if(!p?.pending||this.#busy||p.signed)refuse();const file=this.#selection(this.#nodes['issuer-signature'],314,817);this.#busy=true;
  try{this.#issuerLive(p);const bytes=await this.#file(p.r,file,314,817);this.#issuerLive(p);if(!same(bytes.slice(0,-64),packed(p.pending.unsigned,250,753)))refuse();const h=await this.#issuerHistory(p.r,p.pending.creation_source,unhex(p.reader,32));
   const result=await this.#job(p.r,()=>verifyContactReaderStatement01({bytes,acceptedManifest:h.manifest,expectedAccountId:p.r.account,expectedOrigin:p.origin,expectedRootFingerprint:p.r.fingerprint,comparison:'declared_issued_ms'})),identity=verifiedContactReaderStatementIdentity01(result);
   if(!same(identity.authorizationId,uuid(p.pending.authorization))||identity.readerGeneration!==decimal(p.pending.generation)||!same(identity.readerId,unhex(p.reader,32))||!same(identity.readerPoint,unhex(p.point,65))||identity.untilMs!==decimal(p.pending.until_ms)||identity.issuedMs!==decimal(p.pending.issued_ms)||!same(identity.manifestDigest,fixed64(p.pending.creation_source.manifest_digest_b64,32)))refuse();await this.#positiveSession(p);p.signed=b64(bytes);p.original.signed=p.signed;p.statementDigest=b64(identity.digest);this.#issuerStatus('SIGNED','Whole signature verified against the original intent. Review again before completion.');
  }catch(e){this.#endIssuer();throw e;}finally{this.#busy=false;}
 }
 async #completeIssuer(){
  let code=this.#nodes['issuer-factor'].value;this.#nodes['issuer-factor'].value='';const p=this.#issuer;if(!p?.signed||this.#busy||!(/^[0-9]{6}$/.test(code)||/^zrc_[A-Za-z0-9_-]{22}$/.test(code)))refuse();this.#busy=true;
  try{this.#issuerLive(p);await this.#positiveSession(p);const request={generation:p.pending.generation,create_request:p.create.create_request,creation_expected_revision:p.create.expected_revision,unsigned_digest:p.pending.unsigned_digest,signed_statement:p.signed,code};code='';let body=JSON.stringify(request);request.code='';
   const result=await this.#issuerRequest(p.r,issuerPath+'/'+p.pending.authorization+'/complete',body,p,20480,true);body='';const v=resultView(result.value);await this.#matchReceipt(p.r,p.original,v);await this.#positiveSession(p);if(v.kind!=='historical_completed'||v.signed_statement!==p.signed||v.statement_digest!==p.statementDigest)refuse();this.#endIssuer();this.#issuerStatus('SAVED','The server acknowledged this exact whole statement. This is not custody or contact access.');
  }catch(e){this.#endIssuer();throw e;}finally{code='';this.#busy=false;}
 }
 async #positiveSession(p){try{this.#issuerLive(p);await this.#session(p.r);this.#issuerLive(p);}catch(e){this.#endIssuer();throw e;}}
 async #matchReceipt(r,o,v){if(!['historical_completed','cancelled','expired'].includes(v.kind)||v.create_request!==o.create.create_request||v.create_input_digest!==o.inputDigest||v.creation_expected_revision!==o.create.expected_revision||(o.pending&&(v.authorization!==o.pending.authorization||v.generation!==o.pending.generation||v.unsigned_digest!==o.pending.unsigned_digest))||(v.kind==='historical_completed'&&(!o.signed||v.signed_statement!==o.signed))||decimal(v.current.observed_ms)<(o.observed??0n)||decimal(v.current.observed_ms)<decimal(v.terminal_ms))refuse();if(v.kind==='historical_completed'&&!same(await this.#job(r,()=>digest(packed(o.signed,314,817))),fixed64(v.statement_digest,32)))refuse();}
 async #readOnly(fn){
  const o=this.#issuerUnknown;if(!o||this.#busy||this.#closed)refuse();this.#endIssuer();const r=this.#new(uuid(o.account));try{await this.#session(r);if(o.origin!==this.#win.location.origin)refuse();return await fn(r,o);}finally{this.#forget(r);this.#busy=false;}
 }
 async #lookupIssuer(){
  return this.#readOnly(async(r,o)=>{const response=await this.#issuerRequest(r,o.pending?issuerPath+'/'+o.pending.authorization+'?generation='+o.pending.generation:issuerPath+'/intents/lookup',o.pending?null:JSON.stringify({create:o.create,expected_input_digest:o.inputDigest}));const v=resultView(response.value);
   if(v.kind==='pending'){const p={r,create:o.create,account:o.account,origin:o.origin,point:o.reader_point,reader:hex(fixed64(o.create.selected_reader_id,32)),inputDigest:o.inputDigest,pending:o.pending};const pending=await this.#pending(p,v,false);o.pending=pending;if(!o.pendingJson)o.pendingJson=response.text;this.#issuerStatus('UNKNOWN','Historical original pending content found. Positive approval is not renewed.');}
   else if(v.kind==='unavailable')this.#issuerStatus('UNKNOWN','Original outcome unavailable or pruned. This does not prove no effect.');else{await this.#matchReceipt(r,o,v);this.#issuerStatus('UNKNOWN','Exact historical receipt found. No new positive authority is supplied.');}return v.kind;});
 }
 async #reduceIssuer(withdraw){
  return this.#readOnly(async(r,o)=>{let path,body;
   if(withdraw){const response=await this.#issuerRequest(r,'/v1/owner/export?contact_reader_only=state',null,null,4096),v=closed(response.value,['kind','state']);if(v.kind!=='contact_reader_state'||v.state===null)refuse();const s=closed(v.state,['root_pin_b64','root_fingerprint_b64','trust_generation','last_mutation_ms','current','signed_statement']),c=currentView(s.current);if(!o.pending||c.phase!=='active'||c.authorization!==o.pending.authorization||c.generation!==o.pending.generation||!o.signed||!same(fixed64(c.statement_digest,32),await this.#job(r,()=>digest(packed(o.signed,314,817)))))refuse();path=issuerPath+'/withdraw';body={expected_revision:c.mutation_revision,expected_authorization:c.authorization,expected_generation:c.generation,expected_digest:c.statement_digest};}
   else{if(!o.pending)refuse();path=issuerPath+'/'+o.pending.authorization+'/cancel';body={generation:o.pending.generation,create_request:o.create.create_request,unsigned_digest:o.pending.unsigned_digest};}
   const response=await this.#issuerRequest(r,path,JSON.stringify(body)),v=resultView(response.value);if(withdraw){if(!['withdrawn','already_withdrawn'].includes(v.kind)||v.authorization!==body.expected_authorization||v.generation!==body.expected_generation||v.statement_digest!==body.expected_digest)refuse();}else await this.#matchReceipt(r,o,v);
   this.#issuerStatus('UNKNOWN','Exact original reduction acknowledged. No replacement intent is allowed.');return v.kind;
  });
 }
 async #recoverIssuer(){
  if(this.#issuerUnknown||this.#issuer?.active||this.#busy||this.#closed)refuse();const file=this.#selection(this.#nodes['issuer-recovery'],1,32768),r=this.#new(uuid(this.#nodes.account.value));
  try{const bytes=await this.#file(r,file,1,32768),o=closed(issuerJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes),32768),['account','origin','bundle','reader_point','create','inputDigest','pending','signed']);
   if(o.account!==r.expectedAccount||origin(o.origin)!==this.#win.location.origin||!unhex(o.bundle,16).some(v=>v)||unhex(o.reader_point,65)[0]!==4)refuse();createView(o.create);fixed64(o.inputDigest,32);if(!same(await this.#job(r,()=>createDigest(o.create,r.account,o.origin)),fixed64(o.inputDigest,32)))refuse();
   if(o.pending!==null)await this.#pending({r,create:o.create,account:o.account,origin:o.origin,point:o.reader_point,inputDigest:o.inputDigest,pending:null},o.pending,false);
   if(o.signed!==null){if(!o.pending||!same(packed(o.signed,314,817).slice(0,-64),packed(o.pending.unsigned,250,753)))refuse();}
   await this.#session(r);this.#issuerUnknown={...o,createJson:JSON.stringify(o.create),pendingJson:o.pending?JSON.stringify(o.pending):null,observed:o.pending?decimal(o.pending.current.observed_ms):0n};this.#issuerStatus('UNKNOWN','Untrusted original request imported for read-only lookup only.');
  }finally{this.#forget(r);this.#busy=false;}
 }
 status(){return Object.freeze({phase:this.#phase,unknown:this.#unknown?Object.freeze({...this.#unknown}):null});}
 close(){if(this.#closed)return;this.#closed=true;if(this.#record)this.#forget(this.#record);for(const [target,event,fn]of this.#listeners)target.removeEventListener(event,fn);this.#listeners=[];this.#nodes.review.disabled=true;this.#nodes['verify-statement'].disabled=true;this.#status(this.#unknown?'UNKNOWN':'CLOSED','Local review closed. No current permission is supplied.');}
}
export function startAccountRootReview(){const review=new Review();return Object.freeze(Object.fromEntries(['prepare','accept','decline','reconcile','verifyStatement','status','close'].map(k=>[k,review[k].bind(review)])));}
if(typeof document!=='undefined'&&document.getElementById('inputs'))startAccountRootReview();
