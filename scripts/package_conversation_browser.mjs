// SPDX-License-Identifier: AGPL-3.0-only
// Package the already-built SDK and lockfile-installed HPKE graph for a dormant same-origin mount.
// No bundler, dependency fetch, fixture, credential or automatic mount is included.
import { mkdir, readdir, readFile, writeFile, lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..");
/** Browser packages use existing global WebCrypto. Refuse the obsolete Node-only fallback.
 * The locked HPKE modules are the only modified vendor files; future dependency changes
 * must update the explicit shape check rather than silently granting another import.
 */
export function browserModule(name, source) {
 const expected = new Map([["vendor/common/src/algorithm.js",1],["vendor/common/src/utils/misc.js",2]]).get(name);
 if(expected===undefined)return source;
 const pattern=/import\(["']crypto["']\)/g;
 if([...source.matchAll(pattern)].length!==expected)throw Error("HPKE browser fallback shape changed");
 return source.replace(pattern,'Promise.reject(new Error("Browser WebCrypto required"))');
}
export async function packageOutput(args) {
 if(args.length===1&&args[0]==="--owned-setup-fixture"){
  // Only the explicit test consumer uses this fixed ignored build directory.
  // It must already own an empty leaf; never reuse existing package contents.
  const namespace=path.join(repo,"target"),output=path.join(namespace,"sealed-setup-browser-fixture");
  for(const directory of [namespace,output]){
   const metadata=await lstat(directory);
   if(!metadata.isDirectory()||metadata.isSymbolicLink()||await realpath(directory)!==directory)throw Error("Owned fixture directory required");
  }
  if((await readdir(output)).length)throw Error("Empty owned fixture directory required");
  return output;
 }
 if(args.length!==1||args[0].startsWith("--"))throw Error("Explicit browser asset output directory required");
 const output=path.resolve(args[0]);
 if(output===repo||output.startsWith(repo+path.sep))throw Error("Browser generated assets belong outside source tree");
 return output;
}
async function main() {
const output=await packageOutput(process.argv.slice(2));
const sources=[[path.join(repo,"sdk/typescript/dist"),"sdk"],[path.join(repo,"sdk/typescript/node_modules/@hpke/core/esm"),"vendor/core"],[path.join(repo,"sdk/typescript/node_modules/@hpke/common/esm"),"vendor/common"]];
async function copy(source,target){
 for(const entry of await readdir(source,{withFileTypes:true})){
  const next=path.posix.join(target,entry.name),from=path.join(source,entry.name);
  if(entry.isDirectory()){await copy(from,next);continue;}
  if(!entry.name.endsWith(".js"))continue;
  let code=await readFile(from,"utf8");
  for(const [name,destination] of [["@hpke/core","vendor/core/mod.js"],["@hpke/common","vendor/common/mod.js"]]){
   let relative=path.posix.relative(path.posix.dirname(next),destination);if(!relative.startsWith("."))relative="./"+relative;
   code=code.replaceAll('"'+name+'"',JSON.stringify(relative)).replaceAll("'"+name+"'",JSON.stringify(relative));
  }
  code=browserModule(next,code);
  const to=path.join(output,...next.split("/"));await mkdir(path.dirname(to),{recursive:true});await writeFile(to,code);
 }
}
for(const [source,target] of sources)await copy(source,target);
for(const name of ["core","common"]){const directory=path.join(repo,"sdk/typescript/node_modules/@hpke",name);for(const entry of await readdir(directory)){if(/^(LICENSE|COPYING)/i.test(entry)){const to=path.join(output,"vendor",name,entry);await mkdir(path.dirname(to),{recursive:true});await writeFile(to,await readFile(path.join(directory,entry)));}}}
await writeFile(path.join(output,"package.json"),JSON.stringify({private:true,type:"module"})+"\n");
process.stdout.write("Packaged browser SDK and installed HPKE ESM graph. Mounting remains explicit.\n");

}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href)await main();
