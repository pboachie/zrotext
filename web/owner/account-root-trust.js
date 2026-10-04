// SPDX-License-Identifier: AGPL-3.0-only
// Public local history only. No current permission, key recovery or remote mutation.
import {enrollRootPin02,verifyManifest02,verifiedManifestIdentity02} from '/v1/owner/account-root-trust-sdk/sdk/draft02-manifest.js';
import {Draft02TrustStore} from '/v1/owner/account-root-trust-sdk/sdk/draft02-trust-store.js';
import {verifyContactReaderStatement01,verifiedContactReaderStatementIdentity01} from '/v1/owner/account-root-trust-sdk/sdk/contact-reader-statement.js';
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
class Review {
 #doc;#win;#nodes;#record=null;#closed=false;#busy=false;#unknown=null;#lastWall=0;#listeners=[];#phase='EMPTY_INPUT';
 constructor(){
  this.#doc=globalThis.document;this.#win=globalThis.window;
  if(!this.#doc||!this.#win||this.#doc.hidden)refuse();origin(this.#win.location.origin);
  this.#nodes=Object.fromEntries(['account','origin','fingerprint','card','manifest','inputs','review','decision','tuple','accept','decline','status','reconcile','expected','statement','verify-statement'].map(k=>{const el=this.#doc.getElementById(k);if(!el)refuse();return [k,el];}));
  for(const [target,event,fn]of [[this.#doc,'visibilitychange',()=>{if(this.#doc.hidden)this.close();}],[this.#win,'pagehide',()=>this.close()]]){target.addEventListener(event,fn);this.#listeners.push([target,event,fn]);}
  this.#bind('inputs','submit',()=>this.prepare());this.#bind('accept','click',()=>this.accept());this.#bind('decline','click',()=>this.decline());this.#bind('reconcile','click',()=>this.reconcile());this.#bind('verify-statement','click',()=>this.verifyStatement());
  this.#nodes.review.disabled=false;this.#status('EMPTY_INPUT','Ready for independent public kit review.');
 }
 #bind(id,event,fn){const listener=e=>{e.preventDefault();Promise.resolve().then(fn).catch(()=>{if(!this.#closed&&this.#phase!=='UNKNOWN')this.#status('UNAVAILABLE','Local review unavailable. Check the independent kit and owner session.');});};this.#nodes[id].addEventListener(event,listener);this.#listeners.push([this.#nodes[id],event,listener]);}
 #status(phase,text){this.#phase=phase;this.#nodes.status.textContent=text;this.#nodes.review.disabled=this.#closed||!!this.#unknown;this.#nodes.accept.disabled=phase!=='REVIEWING';this.#nodes['verify-statement'].disabled=phase!=='LOCAL_ACCEPTED_HISTORY';this.#nodes.reconcile.hidden=!this.#unknown||this.#closed;}
 #now(){const n=Date.now();if(!Number.isSafeInteger(n)||n<1||BigInt(n)>max||n<this.#lastWall)refuse();this.#lastWall=n;return BigInt(n);}
 #live(r){if(this.#closed||this.#doc.hidden||r.abort.signal.aborted||performance.now()>=r.deadline||this.#record!==r)refuse();}
 #arm(r,deadline){r.deadline=Math.min(r.deadline,deadline);this.#live(r);clearTimeout(r.timer);r.timer=setTimeout(()=>this.#forget(r),Math.max(0,r.deadline-performance.now()));}
 #new(selectedAccount){if(this.#closed||this.#busy||this.#doc.hidden)refuse();const token=csrf(this.#doc);if(this.#record)this.#forget(this.#record);const account=selectedAccount.slice(),expectedAccount=hex(account).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');const started=performance.now(),r={account,expectedAccount,abort:new AbortController(),deadline:started+10000,reviewDeadline:started+300000,timer:null,store:null,buffers:[account],possibleWrite:false,session:null,csrf:token};this.#record=r;this.#busy=true;try{this.#arm(r,r.deadline);return r;}catch(e){this.#forget(r);this.#busy=false;throw e;}}
 #forget(r){
  if(r.possibleWrite&&r.unknown)this.#unknown={...r.unknown};clearTimeout(r.timer);r.abort.abort();if(r.store)r.store.close();for(const b of r.buffers)b.fill(0);r.buffers.length=0;r.manifest=null;r.identity=null;r.before=null;r.session=null;
  if(this.#record===r){this.#record=null;this.#nodes.decision.hidden=true;this.#nodes.tuple.textContent='';this.#status(this.#unknown?'UNKNOWN':'DECLINED',this.#unknown?'A local write may have started. Read the local outcome; do not automatically retry.':'Local decision closed.');}
 }
 async #race(p,r){
  const observed=Promise.resolve(p);observed.catch(()=>{});this.#live(r);
  let reject,timeout;const stopped=new Promise((_,no)=>{reject=()=>no(Error('Local root review closed'));r.abort.signal.addEventListener('abort',reject,{once:true});timeout=setTimeout(reject,Math.max(0,r.deadline-performance.now()));});
  try{const value=await Promise.race([observed,stopped]);this.#live(r);return value;}finally{clearTimeout(timeout);r.abort.signal.removeEventListener('abort',reject);}
 }
 async #job(r,fn,late){
  this.#live(r);if(unsettled>=4)refuse();unsettled++;
  const p=Promise.resolve().then(()=>{this.#live(r);return fn();}).then(v=>{if((r.abort.signal.aborted||this.#closed||performance.now()>=r.deadline)&&late)late(v);return v;}).finally(()=>{unsettled--;});
  return this.#race(p,r);
 }
 async #session(r){
  this.#live(r);if(this.#nodes.account.value!==r.expectedAccount||csrf(this.#doc)!==r.csrf)refuse();
  const response=await this.#job(r,()=>this.#win.fetch('/v1/auth/session',{credentials:'same-origin',cache:'no-store',redirect:'error',signal:r.abort.signal}));
  if(response.status!==200||response.redirected||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')||!response.body)refuse();
  const reader=response.body.getReader();let b=new Uint8Array(0);
  try{for(;;){const item=await this.#job(r,()=>reader.read());if(item.done)break;if(b.length+item.value.length>1024)refuse();const next=new Uint8Array(b.length+item.value.length);next.set(b);next.set(item.value,b.length);b=next;}}finally{reader.cancel().catch(()=>{});reader.releaseLock();}
  const body=flatJson(new TextDecoder('utf-8',{fatal:true}).decode(b),1024);
  const s=closed(body,['account_id','user_id','session_id','role']);for(const k of ['account_id','user_id','session_id'])uuid(s[k]);if(s.role!=='owner'||s.account_id!==r.expectedAccount||this.#nodes.account.value!==r.expectedAccount||csrf(this.#doc)!==r.csrf)refuse();
  if(r.session&&['account_id','user_id','session_id','role'].some(k=>r.session[k]!==s[k]))refuse();r.session=s;this.#live(r);return s;
 }
 #selection(node,min,maxSize){const list=node.files;if(!list||list.length!==1||!(list[0] instanceof this.#win.File)||list[0].size<min||list[0].size>maxSize)refuse();return list[0];}
 async #file(r,f,min,maxSize){const b=new Uint8Array(await this.#job(r,()=>f.arrayBuffer(),v=>new Uint8Array(v).fill(0)));if(b.length!==f.size||b.length<min||b.length>maxSize)refuse();r.buffers.push(b);return b;}
 async #open(r){r.store=await this.#job(r,()=>Draft02TrustStore.open(),s=>s.close());return r.store;}
 async prepare(){
  if(this.#unknown)refuse();
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
  const r=this.#record;if(!r||this.#phase!=='LOCAL_ACCEPTED_HISTORY'||this.#busy)refuse();const expected=expectedStatement(this.#nodes.expected.value),file=this.#selection(this.#nodes.statement,314,817);if(!same(expected.accountId,r.account)||expected.origin!==r.origin||!same(expected.rootFingerprint,r.fingerprint))refuse();this.#busy=true;
  let bytes;try{
   this.#arm(r,Math.min(r.deadline,performance.now()+10000));await this.#session(r);bytes=await this.#file(r,file,314,817);const before=await this.#job(r,()=>r.store.read()),manifest=await this.#job(r,()=>r.store.verifyStoredHistory(expected.manifestDigest,expected.issuedMs));
   const verified=await this.#job(r,()=>verifyContactReaderStatement01({bytes,acceptedManifest:manifest,expectedAccountId:r.account,expectedOrigin:r.origin,expectedRootFingerprint:r.fingerprint,comparison:'declared_issued_ms'})),actual=verifiedContactReaderStatementIdentity01(verified);
   for(const k of expectedKeys){if(expected[k] instanceof Uint8Array?!same(expected[k],actual[k]):expected[k]!==actual[k])refuse();}
   if(!same(expected.statementDigest,actual.digest))refuse();
   if(!sameSnapshot(before,await this.#job(r,()=>r.store.read())))refuse();await this.#session(r);this.#live(r);r.deadline=r.reviewDeadline;this.#arm(r,r.deadline);this.#status('LOCAL_ACCEPTED_HISTORY','Historical reader statement integrity verified; no current permission or private custody.');return Object.freeze({kind:'historical_integrity',statementDigest:hex(actual.digest)});
  }catch(e){this.#forget(r);throw e;}finally{if(bytes){bytes.fill(0);r.buffers=r.buffers.filter(v=>v!==bytes);}this.#busy=false;}
 }
 status(){return Object.freeze({phase:this.#phase,unknown:this.#unknown?Object.freeze({...this.#unknown}):null});}
 close(){if(this.#closed)return;this.#closed=true;if(this.#record)this.#forget(this.#record);for(const [target,event,fn]of this.#listeners)target.removeEventListener(event,fn);this.#listeners=[];this.#nodes.review.disabled=true;this.#nodes['verify-statement'].disabled=true;this.#status(this.#unknown?'UNKNOWN':'CLOSED','Local review closed. No current permission is supplied.');}
}
export function startAccountRootReview(){const review=new Review();return Object.freeze(Object.fromEntries(['prepare','accept','decline','reconcile','verifyStatement','status','close'].map(k=>[k,review[k].bind(review)])));}
if(typeof document!=='undefined'&&document.getElementById('inputs'))startAccountRootReview();
