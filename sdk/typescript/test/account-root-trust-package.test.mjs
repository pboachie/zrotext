// SPDX-License-Identifier: AGPL-3.0-only
import {test} from 'node:test';import assert from 'node:assert/strict';
import fs from 'node:fs';
import {chmod,lstat,mkdir,mkdtemp,readFile,readdir,realpath,rm,symlink,writeFile} from 'node:fs/promises';import os from 'node:os';import path from 'node:path';
import {syncBuiltinESMExports} from 'node:module';
import {checkModule,packageAccountRootTrust,files} from '../../../scripts/package_account_root_trust_browser.mjs';
test('actual maintained compiled graph includes versioned IDNA and packages exactly seven modules outside source',async()=>{const out=await mkdtemp(path.join(await realpath(os.tmpdir()),'account-trust-package-'));try{const result=await packageAccountRootTrust(out);assert.deepEqual(result.files,files.map(n=>'sdk/'+n));assert.deepEqual((await readdir(out)).sort(),['sdk']);assert.deepEqual((await readdir(path.join(out,'sdk'))).sort(),[...files].sort());if(typeof process.geteuid==='function'){const s=await lstat(out);assert.equal(s.uid,process.geteuid());assert.equal(s.mode&0o777,0o700);}assert.ok(result.bytes<393216);for(const name of files)checkModule(name,await readFile(path.join(out,'sdk',name)));const idna=await readFile(path.join(out,'sdk/contact-idna16.js'),'utf8');assert.match(idna,/Copyright \(c\) Sebastian Mayr/);assert.match(idna,/Mathias Bynens/);await assert.rejects(packageAccountRootTrust(out),/Empty/);}finally{await rm(out,{recursive:true,force:true});}});
test('missing inspector and additional or dynamic imports refuse fixed graph',()=>{for(const [name,source]of [['draft02-manifest.js','export const missing=true;'],['draft02-trust-store.js',"import {a} from './other.js'; export class Draft02TrustStore {}"],['draft02-trust-store.js',"import {a} from './draft02-manifest.js'; import './other.js'; export class Draft02TrustStore {}"],['draft02-trust-store.js',"import {a} from './draft02-manifest.js'; export class Draft02TrustStore { read(){return import('./other.js');} }"],['draft02-manifest.js','export function verifiedAccountArchiveStatementRecords02() {}; export * from "./other.js";']])assert.throws(()=>checkModule(name,new TextEncoder().encode(source)));});
test('source output paths and populated leaves refuse without replacing contents',async()=>{const out=await mkdtemp(path.join(await realpath(os.tmpdir()),'account-trust-package-'));try{await writeFile(path.join(out,'kept'),'preserve');await assert.rejects(packageAccountRootTrust(out));assert.equal(await readFile(path.join(out,'kept'),'utf8'),'preserve');await assert.rejects(packageAccountRootTrust(new URL('../',import.meta.url).pathname));}finally{await rm(out,{recursive:true,force:true});}});

// Confine negative fixtures to an owned directory, not actual external paths.
async function temporaryBoundary(t){
 const fixture=await mkdtemp(path.join(await realpath(os.tmpdir()),'account-trust-boundary-'));
 const temporary=path.join(fixture,'temporary');
 await mkdir(temporary,{mode:0o700});
 t.after(async()=>{t.mock.restoreAll();syncBuiltinESMExports();await rm(fixture,{recursive:true,force:true});});
 t.mock.method(os,'tmpdir',()=>temporary);
 return {fixture,temporary};
}

test('outside, root, prefix-collision, nested and normalized escapes refuse before output writes',async t=>{
 const {fixture,temporary}=await temporaryBoundary(t);
 const outside=path.join(fixture,'outside'),prefix=temporary+'-other',parent=path.join(temporary,'parent'),nested=path.join(parent,'nested');
 for(const directory of [outside,prefix,parent,nested])await mkdir(directory,{mode:0o700});
 await writeFile(path.join(outside,'kept'),'preserve');
 for(const output of [outside,temporary,path.parse(temporary).root,prefix,nested,temporary+path.sep+'..'+path.sep+'outside']){
  await assert.rejects(packageAccountRootTrust(output),/direct child|External owned/);
 }
 assert.deepEqual(await readdir(temporary),['parent']);
 assert.deepEqual(await readdir(nested),[]);
 assert.deepEqual(await readdir(prefix),[]);
 assert.deepEqual(await readdir(outside),['kept']);
 assert.equal(await readFile(path.join(outside,'kept'),'utf8'),'preserve');
});

test('symlink outputs and symlink ancestors refuse without touching their destinations',async t=>{
 const {fixture,temporary}=await temporaryBoundary(t),outside=path.join(fixture,'outside');
 await mkdir(outside,{mode:0o700});
 await writeFile(path.join(outside,'kept'),'preserve');
 const linked=path.join(temporary,'linked');
 await symlink(outside,linked,'junction');
 await assert.rejects(packageAccountRootTrust(linked),/Owned directory/);
 await assert.rejects(packageAccountRootTrust(path.join(linked,'nested')),/direct child/);
 assert.equal((await lstat(linked)).isSymbolicLink(),true);
 assert.deepEqual(await readdir(outside),['kept']);
 assert.equal(await readFile(path.join(outside,'kept'),'utf8'),'preserve');
 assert.deepEqual(await readdir(temporary),['linked']);
});

test('a configured system-temp alias accepts direct mkdtemp children but not caller-selected links',async t=>{
 const {fixture,temporary}=await temporaryBoundary(t),alias=path.join(fixture,'temporary-alias');
 await symlink(temporary,alias,'junction');
 os.tmpdir.mock.mockImplementation(()=>alias);
 const out=await mkdtemp(path.join(os.tmpdir(),'output-'));
 const result=await packageAccountRootTrust(out);
 assert.deepEqual(result.files,files.map(n=>'sdk/'+n));
 assert.deepEqual(await readdir(out),['sdk']);
 assert.deepEqual((await readdir(path.join(out,'sdk'))).sort(),[...files].sort());
 const linked=path.join(alias,'caller-link');
 await symlink(out,linked,'junction');
 await assert.rejects(packageAccountRootTrust(linked),/Owned directory/);
 assert.deepEqual((await readdir(temporary)).sort(),['caller-link',path.basename(out)].sort());
});

test('POSIX output must be private and temporary ancestry must not permit unprotected writes',{skip:typeof process.geteuid!=='function'},async t=>{
 const {temporary}=await temporaryBoundary(t),out=path.join(temporary,'out');
 await mkdir(out,{mode:0o700});
 await chmod(out,0o755);
 await assert.rejects(packageAccountRootTrust(out),/Private owned/);
 await chmod(out,0o700);
 await chmod(temporary,0o777);
 try{await assert.rejects(packageAccountRootTrust(out),/Trusted temporary ancestry/);}
 finally{await chmod(temporary,0o700);}
 assert.deepEqual(await readdir(out),[]);
 assert.deepEqual(await readdir(temporary),['out']);
});

test('contents arriving just before publication survive and only this staging directory is cleaned',async t=>{
 const {temporary}=await temporaryBoundary(t),out=path.join(temporary,'out'),other=path.join(temporary,'.account-trust-package-unrelated');
 await mkdir(out,{mode:0o700});await mkdir(other,{mode:0o700});
 await writeFile(path.join(other,'kept'),'unrelated');
 const remove=fs.promises.rmdir;
 let intercepted=false;
 t.mock.method(fs.promises,'rmdir',async directory=>{
  if(directory===out){intercepted=true;await writeFile(path.join(out,'kept'),'preserve');}
  return remove(directory);
 });
 syncBuiltinESMExports();
 await assert.rejects(packageAccountRootTrust(out),error=>['ENOTEMPTY','EEXIST','EPERM'].includes(error.code));
 assert.equal(intercepted,true);
 assert.equal(await readFile(path.join(out,'kept'),'utf8'),'preserve');
 assert.equal(await readFile(path.join(other,'kept'),'utf8'),'unrelated');
 assert.deepEqual((await readdir(temporary)).sort(),[path.basename(other),'out'].sort());
});

test('a populated replacement after empty-placeholder removal is not clobbered by publication',async t=>{
 const {temporary}=await temporaryBoundary(t),out=path.join(temporary,'out');
 await mkdir(out,{mode:0o700});
 const remove=fs.promises.rmdir;
 let intercepted=false;
 t.mock.method(fs.promises,'rmdir',async directory=>{
  await remove(directory);
  if(directory===out){intercepted=true;await mkdir(out,{mode:0o700});await writeFile(path.join(out,'kept'),'preserve');}
 });
 syncBuiltinESMExports();
 await assert.rejects(packageAccountRootTrust(out),error=>['ENOTEMPTY','EEXIST','EPERM','EACCES'].includes(error.code));
 assert.equal(intercepted,true);
 assert.equal(await readFile(path.join(out,'kept'),'utf8'),'preserve');
 assert.deepEqual(await readdir(temporary),['out']);
});

test('a symlink substituted at removal cannot redirect writes outside the temporary boundary',async t=>{
 const {fixture,temporary}=await temporaryBoundary(t),out=path.join(temporary,'out'),outside=path.join(fixture,'outside');
 await mkdir(out,{mode:0o700});await mkdir(outside,{mode:0o700});
 await writeFile(path.join(outside,'kept'),'preserve');
 const remove=fs.promises.rmdir;
 let intercepted=false;
 t.mock.method(fs.promises,'rmdir',async directory=>{
  if(directory===out){intercepted=true;await remove(out);await symlink(outside,out,'junction');}
  return remove(directory);
 });
 syncBuiltinESMExports();
 // POSIX rejects rmdir on a symlink; Windows may remove the junction itself.
 // Either outcome must leave its destination untouched and clean staging.
 const published=await packageAccountRootTrust(out).then(()=>true,error=>{
  assert.ok(['ENOTDIR','ENOENT','EPERM','EACCES'].includes(error.code));return false;
 });
 assert.equal(intercepted,true);
 if(published)assert.deepEqual(await readdir(out),['sdk']);
 else assert.equal((await lstat(out)).isSymbolicLink(),true);
 assert.deepEqual(await readdir(outside),['kept']);
 assert.equal(await readFile(path.join(outside,'kept'),'utf8'),'preserve');
 assert.deepEqual(await readdir(temporary),['out']);
});
