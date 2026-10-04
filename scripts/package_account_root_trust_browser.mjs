// SPDX-License-Identifier: AGPL-3.0-only
// Package the maintained public-only graph. No build, fetch or automatic mount.
import {readFile,writeFile,lstat,realpath,readdir,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const files=Object.freeze(['draft02-manifest.js','draft02-trust-store.js','contact-reader-statement.js']);
const required=['verifiedAccountArchiveStatementRecords02','Draft02TrustStore','verifyContactReaderStatement01'];
export function checkModule(name,bytes){
 if(!files.includes(name)||!(bytes instanceof Uint8Array)||bytes.length<1||bytes.length>131072)throw Error('Account trust module refused');
 const source=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 const code=source.replace(/\/\*[\s\S]*?\*\//g,'').replace(/\/\/[^\r\n]*/g,'');
 if(/\bimport\s*\(|\bexport\s+[^;]*\bfrom\s*['"]/.test(code))throw Error('Account trust graph refused');
 const imports=[...code.matchAll(/\bimport\s+[^;]*?\bfrom\s*['"]([^'"]+)['"]\s*;/g)].map(m=>m[1]);
 const importTokens=[...code.matchAll(/\bimport\b/g)].length;
 if(importTokens!==imports.length||imports.length!==(name===files[0]?0:1)||imports.some(v=>v!=='./draft02-manifest.js')||!source.includes(required[files.indexOf(name)]))throw Error('Account trust graph refused');
 return source;
}
async function safeDirectory(directory){
 const absolute=path.resolve(directory);
 let cursor=absolute;
 for(;;){const s=await lstat(cursor);if(!s.isDirectory()||s.isSymbolicLink())throw Error('Owned directory required');const next=path.dirname(cursor);if(next===cursor)break;cursor=next;}
 if(await realpath(absolute)!==absolute)throw Error('Canonical directory required');return absolute;
}
export async function packageAccountRootTrust(output){
 if(typeof output!=='string'||!output||output.startsWith('--'))throw Error('Explicit output required');
 const target=path.resolve(output);
 if(target===repo||target.startsWith(repo+path.sep)||repo.startsWith(target+path.sep))throw Error('External owned output required');
 await safeDirectory(target);if((await readdir(target)).length)throw Error('Empty owned output required');
 const source=await safeDirectory(path.join(repo,'sdk/typescript/dist')),modules=[];
 for(const name of files){const p=path.join(source,name),s=await lstat(p);if(!s.isFile()||s.isSymbolicLink()||s.size>131072||await realpath(p)!==p)throw Error('Module source refused');const bytes=await readFile(p);checkModule(name,bytes);modules.push([name,bytes]);}
 await mkdir(path.join(target,'sdk'));
 for(const [name,bytes]of modules)await writeFile(path.join(target,'sdk',name),bytes,{flag:'wx'});
 return Object.freeze({files:files.map(n=>'sdk/'+n),bytes:modules.reduce((n,[,b])=>n+b.length,0)});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 if(process.argv.length!==3)throw Error('One explicit owned output required');
 await packageAccountRootTrust(process.argv[2]);process.stdout.write('Packaged public account trust SDK. Mounting remains explicit.\n');
}
