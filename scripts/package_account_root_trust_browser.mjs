// SPDX-License-Identifier: AGPL-3.0-only
// Package the maintained public-only graph. No build, fetch or automatic mount.
import {readFile,writeFile,lstat,realpath,readdir,mkdir,mkdtemp,rmdir,rename,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const files=Object.freeze(['draft02-manifest.js','draft02-trust-store.js','contact-reader-statement.js','contact-origin.js','contact-idna16.js','contact-idna16-table0.js','contact-idna16-table1.js']);
const required=['verifiedAccountArchiveStatementRecords02','Draft02TrustStore','verifyContactReaderStatement01','canonicalContactOrigin01','contactDomainASCII16','contactIdna16Table0','contactIdna16Table1'];
const dependencies=[[],['./draft02-manifest.js'],['./contact-origin.js','./draft02-manifest.js'],['./contact-idna16.js'],['./contact-idna16-table0.js','./contact-idna16-table1.js'],[],[]];
export function checkModule(name,bytes){
 if(!files.includes(name)||!(bytes instanceof Uint8Array)||bytes.length<1||bytes.length>131072)throw Error('Account trust module refused');
 const source=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const code=source.replace(/\/\*[\s\S]*?\*\//g,'').replace(/\/\/[^\r\n]*/g,'');
 if(/\bimport\s*\(|\bexport\s+[^;]*\bfrom\s*['"]/.test(code))throw Error('Account trust graph refused');
 const imports=[...code.matchAll(/\bimport\s+[^;]*?\bfrom\s*['"]([^'"]+)['"]\s*;/g)].map(m=>m[1]);
 const importTokens=[...code.matchAll(/\bimport\b/g)].length;
 const expected=dependencies[files.indexOf(name)];
 if(importTokens!==imports.length||imports.length!==expected.length||expected.some(v=>imports.filter(i=>i===v).length!==1)||!source.includes(required[files.indexOf(name)]))throw Error('Account trust graph refused');
 return source;
}
async function safeDirectory(directory,trustedAncestors=false){
 const absolute=path.resolve(directory);
 let cursor=absolute;
 for(;;){
  const s=await lstat(cursor);
  if(!s.isDirectory()||s.isSymbolicLink())throw Error('Owned directory required');
  // A sticky system temporary directory is allowed, but a different owner or
  // an unprotected writable ancestor must not control our generated paths.
  if(trustedAncestors&&typeof process.geteuid==='function'&&
     ((s.uid!==0&&s.uid!==process.geteuid())||((s.mode&0o022)!==0&&(s.mode&0o1000)===0)))throw Error('Trusted temporary ancestry required');
  const next=path.dirname(cursor);if(next===cursor)break;cursor=next;
 }
 if(await realpath(absolute)!==absolute)throw Error('Canonical directory required');return absolute;
}
export async function packageAccountRootTrust(output){
 if(typeof output!=='string'||!output||output.startsWith('--'))throw Error('Explicit output required');
 const configuredTemporaryRoot=path.resolve(os.tmpdir());
 const temporaryRoot=await safeDirectory(await realpath(configuredTemporaryRoot),true);
 const normalized=path.resolve(output);
 // Resolve only the independently configured system-temp prefix (for example
 // an OS-provided alias). Never realpath the caller's leaf to accept a link.
 const target=path.dirname(normalized)===configuredTemporaryRoot
  ?path.join(temporaryRoot,path.basename(normalized)):normalized;
 if(target===repo||target.startsWith(repo+path.sep)||repo.startsWith(target+path.sep))throw Error('External owned output required');
 // Bound the normalized CLI path before any I/O on it. Direct children have
 // no caller-selected intermediate ancestor that could redirect publication.
 if(!target.startsWith(temporaryRoot+path.sep)||path.dirname(target)!==temporaryRoot)throw Error('Output must be a direct child of the canonical system temporary directory');
 await safeDirectory(target,true);
 const original=await lstat(target);
 if(typeof process.geteuid==='function'&&(original.uid!==process.geteuid()||(original.mode&0o077)!==0))throw Error('Private owned output required');
 if((await readdir(target)).length)throw Error('Empty owned output required');
 const source=await safeDirectory(path.join(repo,'sdk/typescript/dist')),modules=[];
 for(const name of files){const p=path.join(source,name),s=await lstat(p);if(!s.isFile()||s.isSymbolicLink()||s.size>131072||await realpath(p)!==p)throw Error('Module source refused');const bytes=await readFile(p);checkModule(name,bytes);modules.push([name,bytes]);}
 // Only generated private paths receive file writes. Portable Node path APIs
 // do not defend against a malicious same-user/privileged process, so trusted
 // local control of the temporary hierarchy and build remains a prerequisite.
 const staging=await mkdtemp(path.join(temporaryRoot,'.account-trust-package-'));
 let published=false;
 try{
  await mkdir(path.join(staging,'sdk'));
  for(const [name,bytes]of modules)await writeFile(path.join(staging,'sdk',name),bytes,{flag:'wx'});
  await safeDirectory(target,true);
  const current=await lstat(target);
  if(current.dev!==original.dev||current.ino!==original.ino||current.uid!==original.uid||current.mode!==original.mode)throw Error('Output directory changed');
  if((await readdir(target)).length)throw Error('Empty owned output required');
  // rmdir checks emptiness atomically and does not follow a final symlink.
  // Removing the empty placeholder also permits directory rename on Windows.
  // rename cannot replace a populated directory, even if one races into place.
  await rmdir(target);
  await rename(staging,target);
  published=true;
 }finally{
  if(!published)await rm(staging,{recursive:true,force:true});
 }
 return Object.freeze({files:files.map(n=>'sdk/'+n),bytes:modules.reduce((n,[,b])=>n+b.length,0)});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 if(process.argv.length!==3)throw Error('One explicit owned output required');
 await packageAccountRootTrust(process.argv[2]);process.stdout.write('Packaged public account trust SDK. Mounting remains explicit.\n');
}
