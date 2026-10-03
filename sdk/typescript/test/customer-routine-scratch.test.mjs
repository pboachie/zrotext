// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rename, symlink, rm, writeFile, readFile } from 'node:fs/promises';
import { resolve, join, toNamespacedPath } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ownedScratch,fixtureLocalPath } from '../../assistant/fixture-scratch.mjs';
test('fixture local spelling preserves the owned path and never strips network or device namespaces',()=>{
 const local=resolve(tmpdir());
 assert.equal(fixtureLocalPath(local),local);
 assert.equal(fixtureLocalPath(toNamespacedPath(local)),local);
 for(const path of [String.raw`\\?\UNC`,String.raw`\\.`,String.raw`\\?\Volume{synthetic}`])assert.equal(fixtureLocalPath(path,'win32'),path);
});

test('fixture scratch rejects a repository anchor before creation',async()=>{
  await assert.rejects(ownedScratch(fileURLToPath(new URL('../../../',import.meta.url))),/unsafe fixture anchor/);
});
test('fixture scratch refuses replacement directory and preserves its contents',async()=>{
  const scope=await ownedScratch(), original=scope.path+'-retained';
  await rename(scope.path,original);
  try {
    await mkdir(scope.path); await writeFile(join(scope.path,'sentinel'),'synthetic');
    await assert.rejects(scope.remove(),/ownership changed/);
    assert.equal(await readFile(join(scope.path,'sentinel'),'utf8'),'synthetic');
  } finally { await rm(scope.path,{recursive:true}); await rm(original,{recursive:true}); }
});
test('fixture scratch rejects linked anchor and linked replacement without removing target',async()=>{
  const owner=await ownedScratch(), child=await ownedScratch(), original=child.path+'-retained';
  const link=join(owner.path,'linked');
  try {
    await symlink(owner.path,link,process.platform==='win32'?'junction':'dir');
    await assert.rejects(ownedScratch(resolve(link)),/unsafe fixture directory/);
    await rename(child.path,original);
    await symlink(owner.path,child.path,process.platform==='win32'?'junction':'dir');
    await assert.rejects(child.remove(),/unsafe fixture directory/);
    await writeFile(join(owner.path,'sentinel'),'synthetic');
    assert.equal(await readFile(join(owner.path,'sentinel'),'utf8'),'synthetic');
  } finally {
    await rm(link); await rm(child.path); await rm(original,{recursive:true}); await owner.remove();
  }
});
