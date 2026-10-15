// Compare the actual maintained owner template save/reconciliation state machine.
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {OwnerEncryptedTemplateClient} from '../../../typescript/dist/owner-encrypted-template-client.js';
globalThis.crypto??=webcrypto;
let input='';for await(const chunk of process.stdin)input+=chunk;
const {fixture:f,cases}=JSON.parse(input),out=[];
const dec=x=>new Uint8Array(Buffer.from(x,'base64')),b64=x=>Buffer.from(x).toString('base64');
const numeric=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
for(const c of cases){
 const binding=Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:dec(v)]));
 const scope=Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,numeric.includes(k)?BigInt(v):dec(v)]));
 const manifest=await verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));
 const controller=new AbortController(),responses=[...(c.responses??[])],trace=[],results=[];let ticket,review=0,live=true;
 const client=new OwnerEncryptedTemplateClient({enabled:true,origin:'https://owner.example.invalid',binding,templateId:scope.templateId,signal:controller.signal,
  readCurrent:async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:live,consentLive:true,phase:'active',validForMs:10000}),
  currentCsrf:()=> 'synthetic-csrf',consumeCiphertextReview:async()=>{review++;if(c.reviewReject)throw Error('review refused');},
  fetchImpl:async(url,options)=>{
   trace.push({method:options.method,path:new URL(url).pathname,body:options.body?b64(new Uint8Array(options.body)):null,
    requestId:options.headers['idempotency-key']??null,revision:options.headers['x-zrotext-template-revision']??null});
   const r=responses.shift()??{};if(r.network)throw Error('synthetic network');
   if(r.ownerLost)live=false;
   const body=options.method==='GET'?dec(r.envelope??f.envelope):new TextEncoder().encode(r.body??'{"revision":1}');
   return new Response(body,{status:r.status??200,headers:{'content-type':r.contentType??(options.method==='GET'?'application/vnd.zrotext.workflow-template.v1':'application/json')}});
  }});
 for(const op of c.ops){
  try{
   let value;
   if(op==='prepare'){ticket=await client.prepareSave({requestId:'00000000-0000-0000-0000-000000000041',expectedRevision:0,scope,envelope:dec(f.envelope)});value={ticket:true};}
   else if(op==='close'){client.close();value=null;}
   else if(op==='pending')value=client.pending();
   else if(op==='commit')value=await client.commit(ticket);
   else if(op==='retry')value=await client.retryUnknown(ticket);
   else if(op==='verify')value=await client.verifyUnknown(ticket);
   else if(op==='read')value=await client.readLatest();
   else if(op==='wrong')value=await client.commit({});
   if(value?.state==='verified_current_snapshot')value={state:value.state,requestAcknowledged:value.requestAcknowledged,encryptedDigest:value.encryptedDigest,matchesPending:value.matchesPending};
   results.push({ok:true,value});
  }catch(error){results.push({ok:false,code:error.code,state:error.state});}
 }
 client.close();out.push({results,trace,review});
}
process.stdout.write(JSON.stringify(out));
