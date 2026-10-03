// SPDX-License-Identifier: AGPL-3.0-only
import { constants,lstatSync,realpathSync,openSync,closeSync,fstatSync,readFileSync } from 'node:fs';
import { dirname,isAbsolute,basename,resolve,sep,parse } from 'node:path';
const fail=()=>{throw Error('storage_unavailable');};
const identity=s=>process.platform==='win32'?[s.ino,s.birthtimeNs]:[s.dev,s.ino];
const same=(a,b)=>identity(a).every((v,i)=>v===identity(b)[i]);
const samePath=(a,b)=>process.platform==='win32'?resolve(a).toLowerCase()===resolve(b).toLowerCase():resolve(a)===resolve(b);
const privateEntry=(s,directory)=>{
  if(s.isSymbolicLink()||!(directory?s.isDirectory():s.isFile())||(!directory&&s.nlink!==1n))fail();
  if(process.platform!=='win32'&&(s.uid!==BigInt(process.getuid())||(s.mode&0o077n)!==0n))fail();
};
// Node SQLite accepts a pathname, not an externally verified file descriptor.
// This requires a customer-protected parent ACL and excludes hostile same-user
// mutation. Checks detect swaps; they cannot eliminate privileged TOCTOU races.
function guardedStore(path){
  if(typeof path!=='string'||!isAbsolute(path)||basename(path)==='.'||basename(path)==='..')fail();
  path=resolve(path);
  const parent=dirname(path),canonical=realpathSync(parent),parentStat=lstatSync(parent,{bigint:true});
  if(!samePath(canonical,parent))fail();privateEntry(parentStat,true);
  let fd;
  try{fd=openSync(path,constants.O_CREAT|constants.O_EXCL|constants.O_RDWR|(constants.O_NOFOLLOW??0),0o600);}
  catch(e){if(e.code!=='EEXIST')fail();fd=openSync(path,constants.O_RDONLY|constants.O_NONBLOCK|(constants.O_NOFOLLOW??0));}
  let file;try{file=fstatSync(fd,{bigint:true});privateEntry(file,false);}finally{closeSync(fd);}
  const verify=()=>{
    if(realpathSync(parent)!==canonical||!same(lstatSync(parent,{bigint:true}),parentStat))fail();
    privateEntry(lstatSync(parent,{bigint:true}),true);
    const current=lstatSync(path,{bigint:true});privateEntry(current,false);if(!same(file,current))fail();
    for(const suffix of ['-wal','-shm','-journal']){let sidecar;
      try{sidecar=lstatSync(path+suffix,{bigint:true});}catch(e){if(e.code==='ENOENT')continue;fail();}
      privateEntry(sidecar,false);
    }
  };
  verify();return Object.freeze({verify(){try{verify();}catch{fail();}}});
}
export function privateStore(path){try{return guardedStore(path);}catch{fail();}}
/** Protected customer configuration only. No configuration bytes reach stdout. */
function guardedConfiguration(path){
  if(typeof path!=='string'||!isAbsolute(path))fail();
  path=resolve(path);
  // Independent startup capability: launch from the selected private directory.
  // The config argument cannot select an unrelated filesystem subtree.
  const anchor=resolve(process.cwd());if(anchor===parse(anchor).root)fail();
  if(!path.startsWith(anchor+sep))throw Error('storage_unavailable');
  const anchorGuard=privateDirectory(anchor),parent=dirname(path);
  // Check the parent itself before using it as a filesystem capability.
  // Containment of the selected file must also hold for every derived path.
  if(parent!==anchor&&!parent.startsWith(anchor+sep))throw Error('storage_unavailable');
  const canonical=parent===anchor?anchorGuard.path:realpathSync(parent);
  if(canonical!==anchorGuard.path&&!canonical.startsWith(anchorGuard.path+sep))throw Error('storage_unavailable');
  const before=lstatSync(parent,{bigint:true});
  if(!samePath(canonical,parent))fail();privateEntry(before,true);
  const candidate=lstatSync(path,{bigint:true});privateEntry(candidate,false);
  const fd=openSync(path,constants.O_RDONLY|constants.O_NONBLOCK|(constants.O_NOFOLLOW??0));let bytes;
  try{const actual=fstatSync(fd,{bigint:true});privateEntry(actual,false);
    if(!same(candidate,actual)||actual.size<1n||actual.size>196608n)fail();
    bytes=readFileSync(fd);if(BigInt(bytes.length)!==actual.size||!same(lstatSync(parent,{bigint:true}),before)||!same(lstatSync(path,{bigint:true}),actual))fail();
    return bytes;
  }catch(error){bytes?.fill(0);throw Error('storage_unavailable');}finally{closeSync(fd);}
}
export function readPrivateConfiguration(path){try{return guardedConfiguration(path);}catch{fail();}}
function guardedDirectory(path){
  if(typeof path!=='string'||!isAbsolute(path))fail();path=resolve(path);
  const canonical=realpathSync(path),before=lstatSync(path,{bigint:true});
  if(!samePath(canonical,path))fail();privateEntry(before,true);
  return Object.freeze({path:canonical,verify(){try{const current=lstatSync(path,{bigint:true});privateEntry(current,true);
    if(realpathSync(path)!==canonical||!same(current,before))fail();}catch{fail();}}});
}
export function privateDirectory(path){try{return guardedDirectory(path);}catch{fail();}}
