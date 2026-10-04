// SPDX-License-Identifier: AGPL-3.0-only
// Explicit compiled fixtures, never a product launcher or Node root signer.
import assert from 'node:assert/strict';
import {CleanupFailure,terminateOwnedTree,runOwnedProcess} from '../sdk/typescript/test/owned-process-fixture.mjs';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {createReadStream} from 'node:fs';
import {realpath,lstat,mkdir,rm} from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import {lookup} from 'node:dns/promises';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {runCompiledSetupAcceptance,fixtureControl,validateReady} from '../sdk/typescript/test/conversation-setup-server-orchestration.mjs';
export const SERVER_TEST='http_owner_conversations::sealed_line_setup::server_browser_fixture::ordinary_setup_server_browser_fixture';
const READY='ZT_OWNER_SETUP_READY ',MAX_OUTPUT=16*1024*1024,MAX_READY=16384;
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const samePath=(a,b)=>process.platform==='win32'?a.toLowerCase()===b.toLowerCase():a===b;
export function parseOptions(args){
  const options={};const allowed=new Set(['tools','server-executable','native-executable','server-source','native-source']);
  for(let at=0;at<args.length;at+=2){assert.ok(args[at]?.startsWith('--'));const name=args[at].slice(2);assert.ok(allowed.has(name)&&!(name in options)&&args[at+1]);options[name]=args[at+1];}
  assert.ok(options.tools&&path.isAbsolute(options.tools));
  for(const kind of ['server','native']){assert.equal(Boolean(options[kind+'-executable']),Boolean(options[kind+'-source']),'Existing executable overrides require independent source labels');if(options[kind+'-executable']){assert.ok(path.isAbsolute(options[kind+'-executable'])&&options[kind+'-executable'].toLowerCase().endsWith('.exe'));assert.match(options[kind+'-source'],/^[0-9a-f]{40}$/);}}
  return options;
}
export function selectExecutable(output,manifest,target,kind){
  const matches=[];
  for(const line of output.split(/\r?\n/)){if(!line)continue;const value=JSON.parse(line);if(value.reason!=='compiler-artifact'||value.profile?.test!==true||!value.executable)continue;
    if(!samePath(path.resolve(value.manifest_path),manifest)||value.target?.name.replaceAll('-','_')!==target||JSON.stringify(value.target.kind)!==JSON.stringify([kind]))continue;
    assert.ok(path.isAbsolute(value.executable)&&value.executable.toLowerCase().endsWith('.exe'));matches.push(value.executable);
  }
  assert.equal(matches.length,1,'Exactly one compiled test executable required');return matches[0];
}
export class ReadyParser{
  constructor(){this.pending='';this.total=0;this.ready=null;}
  feed(bytes){this.total+=bytes.length;assert.ok(this.total<=1048576,'Fixture diagnostics exceeded bound');this.pending+=bytes.toString('utf8');let newline;
    while((newline=this.pending.indexOf('\n'))>=0){const line=this.pending.slice(0,newline).replace(/\r$/,'');this.pending=this.pending.slice(newline+1);const prefix=`test ${SERVER_TEST} ... `;
      if(!line.includes(READY))continue;assert.ok(line.startsWith(READY)||line.startsWith(prefix+READY),'Unexpected readiness framing');assert.equal(this.ready,null,'Duplicate readiness refused');const payload=line.slice(line.startsWith(READY)?READY.length:prefix.length+READY.length);assert.ok(Buffer.byteLength(payload)<=MAX_READY);this.ready=validateReady(JSON.parse(payload));
    }return this.ready;
  }
}
export function serverPassed(output){return [...output.matchAll(/^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$/gm)].length===1;}
async function executable(value){assert.ok(path.isAbsolute(value)&&value.toLowerCase().endsWith('.exe'));const stat=await lstat(value);assert.ok(stat.isFile()&&!stat.isSymbolicLink());const actual=await realpath(value);assert.ok(samePath(actual,path.normalize(value)),'Linked executable refused');return actual;}
export const capture=(command,args,options={})=>runOwnedProcess(command,args,{cwd:repo,...options});
export async function createBrowserPackage(){
  const namespace=path.join(repo,'target');
  try{await mkdir(namespace);}catch(error){if(error.code!=='EEXIST')throw error;}
  const metadata=await lstat(namespace);assert.ok(metadata.isDirectory()&&!metadata.isSymbolicLink());
  assert.ok(samePath(await realpath(namespace),namespace),'Linked fixture namespace refused');
  const owned=path.join(namespace,'sealed-setup-browser-fixture');
  await mkdir(owned); // Exclusive creation: never reuse or remove an existing package.
  return owned;
}

export async function executableDigest(value){const hash=createHash('sha256');for await(const chunk of createReadStream(value))hash.update(chunk);return hash.digest('hex');}
async function compiled(options,kind){
  if(options[kind+'-executable'])return executable(options[kind+'-executable']);
  const server=kind==='server',output=await capture('cargo',['test','--locked','-p',server?'zrotext-server':'zrotext-owner',...(server?['--lib']:[]),'--features',server?'conversation-simulator-tests':'unlock','--no-run','--message-format=json']);
  return executable(selectExecutable(output,path.join(repo,'crates',server?'server':'owner-cli','Cargo.toml'),server?'zrotext_server':'zrotext_owner',server?'lib':'bin'));
}
async function tlsInput(){let size=0,parts=[];for await(const chunk of process.stdin){size+=chunk.length;assert.ok(size<=16384);parts.push(chunk);}const value=JSON.parse(Buffer.concat(parts));assert.deepEqual(Object.keys(value).sort(),['cert','key']);assert.ok(typeof value.key==='string'&&typeof value.cert==='string');return value;}
async function reservePort(){const address=(await lookup('localhost',{family:4})).address;assert.ok(address.startsWith('127.'));const socket=net.createServer();await new Promise((resolve,reject)=>{socket.once('error',reject);socket.listen(0,address,resolve);});const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));return port;}
async function deadline(promise,milliseconds){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Fixture deadline exceeded')),milliseconds);})]);}finally{clearTimeout(timer);}}
export async function joinOwnedAcceptance(acceptance,{timeoutMs=240000,joinMs=90000,cancel}={}){
  // Attach settlement observers before the deadline; the losing acceptance must
  // remain owned until its native callbacks and cleanup settle.
  const settled=Promise.resolve(acceptance).then(value=>({value}),error=>({error}));
  try{return await deadline(acceptance,timeoutMs);}catch(first){
    try{await deadline(Promise.resolve().then(cancel),10000);}catch{throw new CleanupFailure('Acceptance cancellation receipt missing');}
    let result;try{result=await deadline(settled,joinMs);}catch{throw new CleanupFailure('Acceptance cleanup join unresolved');}
    if(result.error instanceof CleanupFailure)throw result.error;
    throw first;
  }
}
export function assertPhoneConsumerOutput(output){
  assert.ok(typeof output==='string'&&output.length<=MAX_OUTPUT);
  assert.ok(output.includes('BUILD SUCCESSFUL'),'Actual Android root consumer required');
  assert.match(output,/^\s*COMPOSED_PHONE_ROOT_ADMISSION_PASS\s*$/m,'Non-skipped same-instance phone admission required');
}
export async function main(args=process.argv.slice(2)){
  let stage='prerequisites',assets,server,browser,ready,serverExit,exited,unsafeCleanup=false,termination;const parser=new ReadyParser();let output='';
  try{
    const options=parseOptions(args);assert.equal(process.platform,'win32','Protected native consumer requires Windows');assert.ok(process.env.ZT_INBOUND_TEST_DATABASE_URL&&process.env.DATABASE_ALLOW_PLAINTEXT==='true','Explicit disposable database required');
    const driverSource=(await capture('git',['rev-parse','HEAD'],{timeoutMs:10000})).trim();assert.match(driverSource,/^[0-9a-f]{40}$/);
    const tls=await tlsInput(),serverExecutable=await compiled(options,'server'),nativeExecutable=await compiled(options,'native');
    const serverSha256=await executableDigest(serverExecutable),nativeSha256=await executableDigest(nativeExecutable);
    stage='browser-package';assets=await createBrowserPackage();await capture(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),'--owned-setup-fixture'],{timeoutMs:30000});
    stage='phone-consumer-build';await runOwnedProcess('cmd.exe',['/d','/c','gradlew.bat',':app:compileDebugUnitTestKotlin','--no-daemon','--max-workers=1'],{cwd:path.join(repo,'android'),timeoutMs:600000,maximum:MAX_OUTPUT});
    const origin=`https://owner.example.test:${await reservePort()}`;stage='server-readiness';let resolveReady,rejectReady;const readiness=new Promise((resolve,reject)=>{resolveReady=resolve;rejectReady=reject;});
    server=spawn(serverExecutable,['--exact',SERVER_TEST,'--ignored','--nocapture','--test-threads=1'],{cwd:repo,windowsHide:true,shell:false,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe'],env:{...process.env,ZT_OWNER_SETUP_FIXTURE_ORIGIN:origin,ZT_OWNER_SETUP_BROWSER_ASSETS:assets}});
    exited=new Promise(resolve=>server.once('close',code=>{serverExit=code;if(!ready)rejectReady(Error('Fixture exited before readiness'));resolve(code);}));server.once('error',()=>rejectReady(Error('Fixture launch failed')));
    const stopServer=()=>{termination??=terminateOwnedTree(server,exited).catch(()=>{unsafeCleanup=true;});return termination;};
    let size=0;const collect=(chunk,stdout)=>{size+=chunk.length;if(size>1048576){void stopServer();rejectReady(Error('Fixture diagnostics exceeded bound'));return;}output+=chunk.toString('utf8');if(stdout)try{const value=parser.feed(chunk);if(value){ready=value;resolveReady(value);}}catch{void stopServer();rejectReady(Error('Fixture readiness refused'));}};
    server.stdout.on('data',chunk=>collect(chunk,true));server.stderr.on('data',chunk=>collect(chunk,false));ready=await deadline(readiness,60000);assert.equal(ready.origin,origin);
    stage='compiled-browser-native-consumption';const require=createRequire(import.meta.url);const {chromium}=require(require.resolve('playwright',{paths:[options.tools]}));browser=await chromium.launch({headless:true,args:[`--host-resolver-rules=MAP owner.example.test ${(await lookup('localhost',{family:4})).address}`,'--no-proxy-server']});
    const acceptance=runCompiledSetupAcceptance({browser,ready,nativeExecutable,tls,consumePublishedRoot:async fixture=>{
      assert.ok(Buffer.byteLength(JSON.stringify(fixture))<=2048);
      const result=await runOwnedProcess('cmd.exe',['/d','/c','gradlew.bat',':app:testDebugUnitTest','--tests','org.zrotext.gateway.PublishedRootProvisioningTest','-PcomposedRootFixture=true','--rerun','--no-daemon','--max-workers=1'],{cwd:path.join(repo,'android'),env:{...process.env,ZT_COMPOSED_ROOT_FIXTURE:JSON.stringify(fixture)},timeoutMs:180000,maximum:MAX_OUTPUT});
      assertPhoneConsumerOutput(result);
    }});const result=await joinOwnedAcceptance(acceptance,{cancel:async()=>{await Promise.all([browser.close(),stopServer()]);browser=null;}});await browser.close();browser=null;
    stage='server-terminal';assert.equal(await deadline(exited,20000),0);assert.ok(serverPassed(output),'Compiled fixture assertions must pass');assert.deepEqual(new ReadyParser().feed(Buffer.from(output)),ready);
    assert.equal(await executableDigest(serverExecutable),serverSha256,'Server executable changed');assert.equal(await executableDigest(nativeExecutable),nativeSha256,'Native executable changed');
    console.log(JSON.stringify({stage:'PASS-COMPILED-SETUP-FIXTURE',result,driverSource,serverSourceLabel:options['server-source']||driverSource,nativeSourceLabel:options['native-source']||driverSource,serverSourceMode:options['server-executable']?'caller-supplied-source-label':'cargo-json-current-source',nativeSourceMode:options['native-executable']?'caller-supplied-source-label':'cargo-json-current-source',serverSha256,nativeSha256,physicalDevice:false,carrierSms:false}));return 0;
  }catch(error){if(error instanceof CleanupFailure)unsafeCleanup=true;console.error(`Sealed setup fixture failed at ${stage}; private readiness and signing material withheld.`);return unsafeCleanup?2:1;}
  finally{await browser?.close().catch(()=>{});if(ready&&serverExit===undefined)await fixtureControl(ready)('finish').catch(()=>{});if(server&&serverExit===undefined){try{await deadline(exited,15000);}catch{try{await terminateOwnedTree(server,exited);}catch{unsafeCleanup=true;}}}await termination;if(unsafeCleanup){process.exitCode=2;throw new CleanupFailure('Owned processes not confirmed stopped; staging retained');}if(assets){assert.ok(path.dirname(assets)===path.join(repo,'target')&&path.basename(assets)==='sealed-setup-browser-fixture');await rm(assets,{recursive:true,force:true});}}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))try{process.exitCode=await main();}catch{console.error('Owned process cleanup failed; staging retained and private inputs withheld.');process.exitCode=2;}
