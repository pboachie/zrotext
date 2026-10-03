// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import {CleanupFailure} from './owned-process-fixture.mjs';
import assert from 'node:assert/strict';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {packageOutput,confinedOutput} from '../../../scripts/package_conversation_browser.mjs';
import {mkdtemp,writeFile,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {parseOptions,selectExecutable,ReadyParser,serverPassed,SERVER_TEST,capture,executableDigest,joinOwnedAcceptance,createBrowserPackage} from '../../../scripts/sealed_setup_ci_driver.mjs';
const id='11111111-1111-4111-8111-111111111111',root=path.resolve('fixture-root'),manifest=path.join(root,'crates/server/Cargo.toml'),exe=path.join(root,'target/fixture.exe');
function ready(){const paired=Buffer.alloc(65);paired[0]=4;return {version:1,synthetic:true,port:4444,controlToken:'07'.repeat(32),origin:'https://owner.example.test:4443',baseline:{accountId:id,userId:id,sessionId:id,deviceId:id,lineId:id,nextGeneration:'1',pairedPoint:paired.toString('hex'),pairedFingerprintHex:createHash('sha256').update(paired).digest('hex'),rootFactor:'fixture-factor'.padEnd(26,'x'),lineFactor:'fixture-factor'.padEnd(26,'y'),cookies:[{name:'__Host-zrotext_session',value:'fixture-session'},{name:'__Host-zrotext_csrf',value:'fixture-csrf'}],lease:{connectionEpoch:'1',deploymentEpoch:'1',siteId:'fixture-site',instanceId:'fixture-instance'}}};}
const record=prefix=>prefix+JSON.stringify(ready())+'\n';
const artifact=()=>({reason:'compiler-artifact',manifest_path:manifest,profile:{test:true},target:{name:'zrotext_server',kind:['lib']},executable:exe});
test('packaged assets cannot escape the explicitly selected output',()=>{
  const output=path.resolve('synthetic-output');
  assert.equal(confinedOutput(output,'sdk/conversation.js'),path.join(output,'sdk/conversation.js'));
  for(const selected of ['..','../sibling/asset.js','.',path.resolve('sibling','asset.js')])assert.throws(()=>confinedOutput(output,selected),/escapes selected/);
});
test('compile discovery requires one exact package/test/target artifact',()=>{assert.equal(selectExecutable(JSON.stringify(artifact()),manifest,'zrotext_server','lib'),exe);for(const change of [a=>a.profile.test=false,a=>a.target.kind=['bin'],a=>a.manifest_path=path.join(root,'other/Cargo.toml'),a=>a.executable=null]){const a=artifact();change(a);assert.throws(()=>selectExecutable(JSON.stringify(a),manifest,'zrotext_server','lib'));}assert.throws(()=>selectExecutable(JSON.stringify(artifact())+'\n'+JSON.stringify(artifact()),manifest,'zrotext_server','lib'));});
test('explicit compiled overrides require absolute paths and independent source labels',()=>{const options=['--tools',root,'--server-executable',exe,'--server-source','1'.repeat(40)];assert.equal(parseOptions(options)['server-executable'],exe);assert.throws(()=>parseOptions(options.slice(0,4)));assert.throws(()=>parseOptions(['--tools',root,'--server-executable','relative.exe','--server-source','1'.repeat(40)]));assert.throws(()=>parseOptions(['--tools',root,'--tools',root]));});
test('readiness supports actual selected libtest framing and chunked transport',()=>{for(const prefix of ['ZT_OWNER_SETUP_READY ',`test ${SERVER_TEST} ... ZT_OWNER_SETUP_READY `]){const parser=new ReadyParser(),raw=Buffer.from(record(prefix));assert.equal(parser.feed(raw.subarray(0,30)),null);assert.deepEqual(parser.feed(raw.subarray(30)),ready());}});
for(const [name,raw]of [['duplicate',record('ZT_OWNER_SETUP_READY ')+record('ZT_OWNER_SETUP_READY ')],['lookalike',record('wrong prefix ZT_OWNER_SETUP_READY ')],['bad json','ZT_OWNER_SETUP_READY {invalid}\n'],['wrong fixture','ZT_OWNER_SETUP_READY '+JSON.stringify({...ready(),synthetic:false})+'\n'],['oversized','x'.repeat(1048577)]])test('readiness rejects '+name,()=>{assert.throws(()=>new ReadyParser().feed(Buffer.from(raw)));});
test('terminal fixture result requires actual one-pass zero-fail zero-ignore summary',()=>{const summary='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 20 filtered out; finished in 1.00s\n';assert.equal(serverPassed(summary),true);assert.equal(serverPassed(summary.replace('1 passed','0 passed')),false);assert.equal(serverPassed(summary.replace('0 ignored','1 ignored')),false);assert.equal(serverPassed(summary+summary),false);});
test('subprocess diagnostic overflow rejects without returning raw material',async()=>{await assert.rejects(capture(process.execPath,['-e',"process.stdout.write('x'.repeat(2048));setInterval(()=>{},1000)"],{maximum:1024,timeoutMs:2000}),/exceeded bound/);});
test('subprocess absolute deadline rejects a child that never terminates',async()=>{await assert.rejects(capture(process.execPath,['-e','setInterval(()=>{},1000)'],{timeoutMs:30}),/exceeded bound/);});

test('binary digest records actual bytes and detects changed executable',async()=>{const directory=await mkdtemp(path.join(tmpdir(),'sealed-setup-digest-'));try{const file=path.join(directory,'fixture.exe');await writeFile(file,'first');const first=await executableDigest(file);assert.equal(first,createHash('sha256').update('first').digest('hex'));await writeFile(file,'second');assert.notEqual(await executableDigest(file),first);}finally{await rm(directory,{recursive:true,force:true});}});

test('capture timeout terminates the owned grandchild before rejection',async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),'sealed-setup-tree-'));const heartbeat=path.join(directory,'heartbeat'),pidFile=path.join(directory,'pid');let grandchild;
  try{
    const leaf="const fs=require('node:fs');setInterval(()=>fs.appendFileSync(process.argv[1],'x'),40);";
    const parent="const {spawn}=require('node:child_process');const fs=require('node:fs');const child=spawn(process.execPath,['-e',process.argv[1],process.argv[2]],{stdio:'ignore',detached:process.platform==='win32'});fs.writeFileSync(process.argv[3],String(child.pid));setInterval(()=>{},1000);";
    await assert.rejects(capture(process.execPath,['-e',parent,leaf,heartbeat,pidFile],{timeoutMs:1500}),/exceeded bound/);
    grandchild=Number(await readFile(pidFile,'utf8'));assert.ok(Number.isSafeInteger(grandchild)&&grandchild>0);
    const before=await readFile(heartbeat,'utf8');assert.ok(before.length>0,'Grandchild ran before cancellation');
    await new Promise(resolve=>setTimeout(resolve,200));assert.equal(await readFile(heartbeat,'utf8'),before,'Heartbeat must stop before timeout rejection');
    assert.throws(()=>process.kill(grandchild,0),error=>error.code==='ESRCH','Owned grandchild no longer exists');
  }finally{if(grandchild)try{process.kill(grandchild);}catch{}await rm(directory,{recursive:true,force:true});}
});

test('aggregate deadline joins late native CleanupFailure before cleanup',async()=>{
  let canceled=false,settled=false;
  const acceptance=new Promise((_,reject)=>setTimeout(()=>{settled=true;reject(new CleanupFailure('late native termination unknown'));},40));
  await assert.rejects(joinOwnedAcceptance(acceptance,{timeoutMs:5,joinMs:100,cancel:()=>{canceled=true;}}),CleanupFailure);
  assert.equal(canceled,true);assert.equal(settled,true,'Do not release PostgreSQL while native acceptance is pending');
});
test('unresolved aggregate cleanup join refuses ordinary teardown',async()=>{
  let canceled=false;
  await assert.rejects(joinOwnedAcceptance(new Promise(()=>{}),{timeoutMs:5,joinMs:20,cancel:()=>{canceled=true;}}),CleanupFailure);
  assert.equal(canceled,true);
});
test('aggregate timeout joins an ordinary late rejection before returning failure',async()=>{
  let settled=false;
  const acceptance=new Promise((_,reject)=>setTimeout(()=>{settled=true;reject(Error('ordinary refused'));},30));
  await assert.rejects(joinOwnedAcceptance(acceptance,{timeoutMs:5,joinMs:100,cancel:()=>{}}),/deadline exceeded/);
  assert.equal(settled,true);
});

test('browser package creation refuses existing ownership and preserves its contents',async()=>{
  const directory=await createBrowserPackage();
  try{
    assert.equal(await packageOutput(['--owned-setup-fixture']),directory);
    await assert.rejects(packageOutput([directory]),/outside source tree/);
    await assert.rejects(packageOutput(['--owned-setup-fixture',directory]),/Explicit/);
    const marker=path.join(directory,'synthetic-marker');await writeFile(marker,'preserve');
    await assert.rejects(packageOutput(['--owned-setup-fixture']),/Empty owned/);
    await assert.rejects(createBrowserPackage());
    assert.equal(await readFile(marker,'utf8'),'preserve');
  }finally{await rm(directory,{recursive:true,force:true});}
});
