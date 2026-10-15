// Compare the actual maintained owner template save/reconciliation state machine.
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {OwnerWorkflowContextClient} from '../../../typescript/dist/owner-workflow-context-client.js';
globalThis.crypto??=webcrypto;
let input='';for await(const chunk of process.stdin)input+=chunk;
const {fixture:f,cases}=JSON.parse(input),out=[];
const dec=x=>new Uint8Array(Buffer.from(x,'base64')),b64=x=>Buffer.from(x).toString('base64');
const numeric=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
for(const c of cases){
 const binding=Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:dec(v)]));
 const scope=Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,k==='kind'?v:numeric.includes(k)?BigInt(v):dec(v)]));
 const manifest=await verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));
 const controller=new AbortController(),responses=[...(c.responses??[])],trace=[],results=[];let ticket,review=0,live=true;
 const client=new OwnerWorkflowContextClient({enabled:true,origin:'https://owner.example.invalid',selection:{binding,contextId:scope.contextId,kind:scope.kind},signal:controller.signal,
  readCurrent:async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:live,consentLive:true,phase:'active',validForMs:10000}),
  currentCsrf:()=> 'synthetic-csrf',consumeWriteReview:async()=>{review++;if(c.reviewReject)throw Error('review refused');},
  fetchImpl:async(url,options)=>{
   trace.push({method:options.method,path:new URL(url).pathname,body:options.body?b64(new Uint8Array(options.body)):null,
    requestId:options.headers['idempotency-key']??null,revision:options.headers['x-zrotext-context-revision']??null});
   const r=responses.shift()??{};if(r.network)throw Error('synthetic network');
   if(r.ownerLost)live=false;
   const body=options.method==='GET'?dec(r.newer?f.newer:(r.envelope??f.envelope)):new TextEncoder().encode(r.body??'{"revision":1}');
   return new Response(body,{status:r.status??200,headers:{'content-type':r.contentType??(options.method==='GET'?'application/vnd.zrotext.workflow-context.v1':'application/json')}});
  }});
 for(const op of c.ops){
  try{
   let value;
   if(op==='prepare'){ticket=await client.prepare({requestId:'00000000-0000-0000-0000-000000000041',expectedRevision:0,scope,envelope:dec(f.envelope)});value={ticket:true};}
   else if(op==='close'){client.close();value=null;}
   else if(op==='pending')value=client.pending();
   else if(op==='commit')value=await client.commit(ticket);
   else if(op==='retry')value=await client.retryUnknown(ticket);
   else if(op==='verify')value=await client.verifyUnknown(ticket);
   else if(op==='wrong')value=await client.commit({});
   results.push({ok:true,value});
  }catch(error){results.push({ok:false,code:error.code??'read_refused',state:error.state??'refused'});}
 }
 client.close();out.push({results,trace,review});
}
process.stdout.write(JSON.stringify(out));
