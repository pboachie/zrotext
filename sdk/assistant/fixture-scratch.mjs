// SPDX-License-Identifier: AGPL-3.0-only
// Test-only ownership checks; the OS temporary anchor must be trusted.
import { mkdir, lstat, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, parse } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
// Rust canonicalization uses a verbatim local-drive spelling on Windows.
// Normalize only that spelling for fixture API arguments; never network/device paths.
export function fixtureLocalPath(path,platform=process.platform){
  return platform==='win32'&&/^\\\\\?\\[A-Za-z]:\\/.test(path)?path.slice(4):path;
}
const inside = (parent, child) => { const r=relative(parent,child); return r==='' || (!r.startsWith('..') && !parse(r).root); };
async function directory(path) {
  const stat=await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || resolve(await realpath(path))!==resolve(path)) throw Error('unsafe fixture directory');
  return stat;
}
const same = (a,b) => a.dev===b.dev && a.ino===b.ino && a.birthtimeMs===b.birthtimeMs;
export async function ownedScratch(anchor=tmpdir()) {
  anchor=resolve(anchor);
  if (anchor===parse(anchor).root || inside(repository,anchor)) throw Error('unsafe fixture anchor');
  const parent=await directory(anchor);
  const path=join(anchor,`zrotext-routine-${randomUUID()}`);
  await mkdir(path,{mode:0o700});
  const child=await directory(path);
  return Object.freeze({path,async remove(){
    if (dirname(path)!==anchor || !same(parent,await directory(anchor)) || !same(child,await directory(path))) throw Error('fixture ownership changed');
    await rm(path,{recursive:true,force:false});
  }});
}
