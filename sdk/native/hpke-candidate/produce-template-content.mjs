// Test-only oracle from the independently pinned maintained TypeScript SDK.
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
const source=resolve(process.argv[2]??'');
const git=(...args)=>execFileSync('git',['-C',source,...args],{encoding:'utf8'}).trim();
if(git('rev-parse','HEAD')!=='72124e1a3ff28e782f870eeddbdc33cacf8ca3b4'||git('status','--porcelain'))throw Error('exact clean maintained source required');
const load=name=>import(pathToFileURL(resolve(source,'sdk/typescript/dist',name+'.js')).href);
const {canonicalTemplateBytes,templateDigest}=await load('template-contract');
const {previewEncryptedTemplate}=await load('encrypted-template');
const {estimateSegments}=await load('sms-segments');
const cases=[];
async function add(name,template,values={},mutate=raw=>raw){
 const content={v:1,template,values:{}};
 // Native canonical parsing uses ordinal key order, identical to JS sort for ASCII identifiers.
 content.values=Object.fromEntries(Object.keys(values).sort().map(k=>[k,values[k]]));
 const raw=mutate(JSON.stringify(content));const expected={accepted:false};
 try{const bytes=canonicalTemplateBytes(template,values);if(Buffer.from(bytes).toString('utf8')!==raw)throw Error('noncanonical');expected.accepted=true;expected.canonical=Buffer.from(bytes).toString('base64');expected.digest=await templateDigest(template,values);try{expected.preview=previewEncryptedTemplate({template,values});}catch{expected.preview=null;}}catch{}
 cases.push({name,raw:Buffer.from(raw).toString('base64'),expected});
}
await add('empty','');await add('literal','A local preview.');await add('values order','{{z}} {{A}} {{a}}',{z:'last',a:'lower',A:'upper'});
await add('single pass','{{x}}',{x:'{{y}}',y:'must not expand'});await add('missing','{{absent}}');
await add('unicode','Hello {{name}}',{name:'\u{1f331}'});await add('json escapes','{{x}}',{x:String.fromCharCode(34,92,8,12,10,13,9,1,127,0x2028,0x2029)});
await add('literal escape sequence','{{x}}',{x:'\\u2028 \\u2029'});await add('html chars','<>&');
for(const t of ['{','}','{{','{{x}','{{ x}}','{{x-y}}','{{0x}}','{{__proto__}}','{{prototype}}','{{constructor}}'])await add('bad token '+t,t);
for(const k of ['__proto__','prototype','constructor','bad-key','0key','a'.repeat(33)])await add('bad key '+k,'',Object.fromEntries([[k,'x']]));
await add('longest key','{{'+ 'a'.repeat(32)+'}}',{['a'.repeat(32)]:'yes'});
for(const n of [4096,4097])await add('template limit '+n,'x'.repeat(n));
for(const n of [2048,2049])await add('UTF16 template '+n,'\u{1f331}'.repeat(n));
for(const n of [512,513])await add('value limit '+n,'{{x}}',{x:'x'.repeat(n)});
for(const n of [256,257])await add('UTF16 value '+n,'{{x}}',{x:'\u{1f331}'.repeat(n)});
for(const n of [32,33])await add('entry limit '+n,'',Object.fromEntries(Array.from({length:n},(_,i)=>['k'+i,''])));
for(const n of [508,509])await add('aggregate limit '+n,'',Object.fromEntries(Array.from({length:8},(_,i)=>['k'+i,'x'.repeat(n)])));
await add('escaped content above transport maximum','\u0001'.repeat(4096),Object.fromEntries(Array.from({length:7},(_,i)=>['k'+i,'\u0001'.repeat(512)])));
await add('repeated output limit','{{x}}'.repeat(17),{x:'x'.repeat(512)});
for(const s of ['\ud800','\udfff']){await add('lone template',s);await add('lone value','{{x}}',{x:s});}
await add('duplicate version','x',{},raw=>raw.slice(0,-1)+',"v":1}');await add('noncanonical whitespace','x',{},raw=>' '+raw);await add('extra field','x',{},raw=>raw.slice(0,-1)+',"extra":true}');
const segments=[];
const samples=['','\n\r\f','\t','\u0000','\ud800','\udfff','\u007f',...Array.from({length:128},(_,i)=>String.fromCharCode(i)),...['\u00a3','\u00a5','\u00e9','\u0394','\u20ac','\u{1f331}','\u2028']];
for(const [text,limits] of [['x',[160,161,918,919]],['^',[80,81,459,460]],['\u4e00',[70,71,402,403]],['\u{1f331}',[35,36,201,202]]])for(const n of limits)samples.push(text.repeat(n));
for(const text of samples){let expected=null;try{expected=estimateSegments(text)}catch{};segments.push({units:Array.from({length:text.length},(_,i)=>text.charCodeAt(i)),expected});}
process.stdout.write(JSON.stringify({format:'native-template-content-v1',cases,segments}));
