// Real maintained persistence contract, including raw receipt decoding.
import {templateSaveRequest,templateSaveReceipt} from '../../../typescript/dist/template-store-contract.js';
const dec=s=>new Uint8Array(Buffer.from(s,'base64')),b64=b=>Buffer.from(b).toString('base64');
const numbers=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
let text='';for await(const part of process.stdin){text+=part;if(text.length>3000000)throw Error('case bound');}
const inputs=JSON.parse(text),results=[];
for(const input of inputs){
 try{
  const scope=Object.fromEntries(Object.entries(input.scope).map(([k,v])=>[k,numbers.includes(k)?BigInt(v):dec(v)]));
  const request=await templateSaveRequest(scope,input.requestId,input.expectedRevision,dec(input.envelope));
  results.push({accepted:true,value:input.receipt===undefined?{path:request.path,headers:request.headers,body:b64(request.body),revision:request.revision,encryptedDigest:request.encryptedDigest}:templateSaveReceipt(request,dec(input.receipt))});
 }catch{results.push({accepted:false});}
}
process.stdout.write(JSON.stringify(results));
