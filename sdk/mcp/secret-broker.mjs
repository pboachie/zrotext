// SPDX-License-Identifier: AGPL-3.0-only
// Private parent-process bootstrap is consumed before any model JSON-RPC.
import { createSession } from './server.mjs';
import { WorkflowToolClient } from '../typescript/dist/workflow-tool-client.js';
import { pathToFileURL } from 'node:url';
export async function broker(input,write){
 const iterator=input[Symbol.asyncIterator]();let pending=Buffer.alloc(0),client;
 try{
  while(!client){const next=await iterator.next();if(next.done)throw Error('broker_refused');pending=Buffer.concat([pending,next.value]);
   const end=pending.indexOf(10);if(end<0){if(pending.length>1024)throw Error('broker_refused');continue;}
   if(end>1024)throw Error('broker_refused');const startup=pending.subarray(0,end);
   try{const v=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(startup));
    if(!v||Object.keys(v).sort().join(',')!=='credential,origin,v'||v.v!==1)throw Error();
    client=new WorkflowToolClient({origin:v.origin,credential:v.credential});
   }finally{startup.fill(0);}pending=Buffer.from(pending.subarray(end+1));
  }
  const session=createSession({client});
  while(true){let end;while((end=pending.indexOf(10))>=0){if(end>65536)throw Error('broker_refused');
    const line=pending.subarray(0,end);pending=Buffer.from(pending.subarray(end+1));let response;
    try{response=await session(JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(line)));}
    catch{response={jsonrpc:'2.0',id:null,error:{code:-32700,message:'Parse error'}};}
    if(response){let serialized=JSON.stringify(response);if(Buffer.byteLength(serialized)>262144)throw Error('broker_refused');await write(serialized+'\n');}
   }
   if(pending.length>65536)throw Error('broker_refused');const next=await iterator.next();if(next.done){if(pending.length)throw Error('broker_refused');break;}
   pending=Buffer.concat([pending,next.value]);
  }
 }finally{pending.fill(0);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{if(process.argv.length!==2)throw Error();await broker(process.stdin,async value=>{if(!process.stdout.write(value))await new Promise(r=>process.stdout.once('drain',r));});}
 catch{process.stderr.write('Workflow broker refused.\n');process.exitCode=2;}
}
