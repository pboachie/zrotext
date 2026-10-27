// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp,mkdir,copyFile,writeFile,realpath,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url));

test('IDNA generation rejects altered regexp data before loading its module',async()=>{
  const stage=await mkdtemp(path.join(tmpdir(),'contact-idna-input-'));
  try{
    for(const folder of ['scripts','node_modules/punycode','node_modules/tr46/lib'])await mkdir(path.join(stage,folder),{recursive:true});
    for(const name of ['scripts/generate-contact-idna.mjs','node_modules/punycode/package.json',
      'node_modules/punycode/punycode.es6.js','node_modules/tr46/package.json'])await copyFile(path.join(root,name),path.join(stage,name));
    await writeFile(path.join(stage,'node_modules/tr46/lib/regexes.js'),"throw Error('Unverified module executed');\n");
    const result=spawnSync(process.execPath,[path.join(stage,'scripts/generate-contact-idna.mjs'),'--check'],{encoding:'utf8',timeout:10000});
    assert.equal(result.status,1,result.stderr);assert.match(result.stderr,/Unexpected IDNA regexp data/);
    assert.doesNotMatch(result.stderr,/Unverified module executed/);
  }finally{
    assert.equal(path.dirname(stage),path.resolve(tmpdir()));assert.ok(path.basename(stage).startsWith('contact-idna-input-'));
    assert.equal(await realpath(stage),stage);await rm(stage,{recursive:true,force:true});
  }
});
