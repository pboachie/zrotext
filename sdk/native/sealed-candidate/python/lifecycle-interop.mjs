// Differential metadata validation against the maintained TypeScript API.
import {SealedLifecycleClient,SealedLifecycleError} from '../../../typescript/dist/sealed-lifecycle-client.js';
let text='';for await(const part of process.stdin){text+=part;if(text.length>200000)throw Error('case bound');}
const cases=JSON.parse(text),results=[];
for(const item of cases){
 const client=new SealedLifecycleClient({baseUrl:'https://synthetic.example.invalid',apiToken:'synthetic',fetchImpl:async()=>new Response(item.raw?Buffer.from(item.raw,'base64'):JSON.stringify(item.body),{status:item.status})});
 try{results.push({accepted:true,value:await client[item.method](item.argument===null?undefined:item.argument)});}
 catch(error){results.push({accepted:false,code:error instanceof SealedLifecycleError?error.code:'unexpected_response'});}
}
process.stdout.write(JSON.stringify(results));
