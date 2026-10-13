// Actual maintained DOM-free template authoring callbacks; no browser facade.
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {OwnerTemplateAuthoring} from '../../../typescript/dist/owner-template-authoring.js';
globalThis.crypto??=webcrypto;
let text='';for await(const chunk of process.stdin)text+=chunk;const {fixture:f,cases}=JSON.parse(text),results=[];
const dec=x=>new Uint8Array(Buffer.from(x,'base64')),numbers=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
for(const c of cases){
 const scope=Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,numbers.includes(k)?BigInt(v):dec(v)]));
 const binding=Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:dec(v)]));
 const manifest=await verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));
 let reviewed=0,metadata=0,posts=0;
 const a=new OwnerTemplateAuthoring({enabled:true,origin:'https://owner.example.invalid',binding,templateId:scope.templateId,signal:new AbortController().signal,
  readCurrent:async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:!(c.ownerLost&&reviewed),consentLive:true,phase:'active',validForMs:10000}),
  currentCsrf:()=>c.csrfChanged&&reviewed?'rotated':'synthetic-csrf',
  readDraftState:async()=>({epoch:c.epochChanged&&reviewed?2n:1n,revision:c.revisionChanged&&reviewed?2n:1n,custodyLive:c.custodyLive!==false&&!(c.custodyLost&&reviewed)}),
  consumeDraftReview:async()=>{reviewed++;return Object.hasOwn(c,'decision')?c.decision:true;},consumeCiphertextReview:async()=>{metadata++;},fetchImpl:async()=>{posts++;throw Error('must not dispatch');}});
 try{await a.prepare({requestId:'00000000-0000-0000-0000-000000000041',expectedRevision:0,scope,template:c.template??f.content.template,values:c.values??f.content.values,epoch:1n,draftRevision:1n});results.push({accepted:true,reviewed,metadata,posts});}
 catch(error){results.push({accepted:false,reviewed,metadata,posts});}finally{a.close();}
}
process.stdout.write(JSON.stringify(results));
