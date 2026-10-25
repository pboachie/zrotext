// SPDX-License-Identifier: AGPL-3.0-only
// Public-only producer/consumer regression; no root signer or approval callback.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {displayedLineApprovalFingerprint} from './conversation-setup-server-browser.mjs';

const require=createRequire(import.meta.url);
const line=require('../../../web/owner/conversation-line-setup.js');
const vector=require('../../../crates/root-material/src/line_key_registration/vector.json');
const bytes=hex=>Uint8Array.from(Buffer.from(hex,'hex'));
const b64=value=>Buffer.from(value).toString('base64');
const hash=async value=>new Uint8Array(await crypto.subtle.digest('SHA-256',value));
const download='Download public RootLineRegister packet for existing offline approval';
const sessionNotice='Closing this page loses the approval key; an unactivated replacement requires fresh root approval.';
const fingerprint='11'.repeat(32),paired='22'.repeat(32);
const paragraph=(approval=fingerprint,phone=paired)=>`Line approval fingerprint: ${approval}. Existing paired phone fingerprint: ${phone}. ${sessionNotice}`;

async function actualSessionPublication(){
  const parsed=line.parseRegistration(bytes(vector.transcript));
  // Published P-256 4G point from the shared public registration fixture.
  const phone=bytes('04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6');
  const selection={enabled:true,sessionConsent:true,retentionConsent:false,completeSetConsent:false,
    account_id:parsed.account,device_id:parsed.device,line_id:parsed.line,nextGeneration:parsed.generation.toString(),
    rootFingerprint:vector.rootFingerprint,pairedFingerprint:vector.pairedSigningFingerprint,origin:parsed.origin};
  const emitted=[];let challengeRequests=0;
  const document={cookie:'__Host-zrotext_csrf=fixture',hidden:false,addEventListener(){},removeEventListener(){},
    createElement(tag){return {tag,children:[],append(...children){this.children.push(...children);},remove(){}};}};
  const window={location:{origin:parsed.origin},addEventListener(){},removeEventListener(){},
    confirm(){assert.fail('Publication must not invoke approval or signing');}};
  const fetch=async(path,options)=>{
    let value;
    if(path==='/v1/auth/session')value={account_id:parsed.account,user_id:parsed.user,session_id:parsed.session,role:'owner'};
    else if(path==='/v1/owner/conversation/sealed-line/bootstrap')value={v:1,untrusted_projection:true,
      account_id:parsed.account,user_id:parsed.user,session_id:parsed.session,device_id:parsed.device,line_id:parsed.line,
      expected_next_binding_generation:parsed.generation.toString(),root_pin:b64(parsed.rootPin),root_fingerprint:b64(parsed.rootFingerprint),
      current_device_signing_fingerprint:b64(parsed.pairedFingerprint),connection_epoch:parsed.connectionEpoch.toString(),
      deployment_epoch:parsed.deploymentEpoch.toString(),site_id:parsed.site,instance_id:parsed.instance,server_now_ms:parsed.issued.toString()};
    else if(path==='/v1/owner/conversation/sealed-line/owner-key/challenge'){
      challengeRequests++;
      const body=JSON.parse(options.body),point=Uint8Array.from(Buffer.from(body.approval_point,'base64'));
      const fingerprint=await hash(point),transcript=bytes(vector.transcript);
      const offset=Buffer.from(transcript).indexOf(Buffer.from(parsed.approvalPoint));assert.ok(offset>0);
      transcript.set(point,offset);transcript.set(fingerprint,offset+65);
      value={challenge_id:parsed.challenge,unsigned_statement:b64(transcript),issued_ms:parsed.issued.toString(),expires_ms:parsed.expires.toString(),
        root_pin:b64(parsed.rootPin),root_fingerprint:b64(parsed.rootFingerprint),current_device_signing_fingerprint:b64(parsed.pairedFingerprint),
        approval_fingerprint:b64(fingerprint)};
    }else assert.fail('Publication requested an unexpected operation');
    return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
  };
  const controller=line.create({enabled:true,document,window,host:{append:element=>emitted.push(element)},readSelection:()=>selection,
    fetch,URL:{createObjectURL:()=> 'blob:synthetic-fixture',revokeObjectURL(){}},monotonic:()=>0});
  try{
    const result=await controller.begin({size:phone.length,arrayBuffer:async()=>Uint8Array.from(phone).buffer});
    assert.equal(result.phase,'awaiting_root');assert.equal(challengeRequests,1);assert.equal(emitted.length,1);
    const paragraph=emitted[0].children.find(element=>element.tag==='p').textContent;
    const link=emitted[0].children.find(element=>element.tag==='a');
    assert.equal(link.download,'line-owner-key-registration.bin');assert.equal(link.textContent,download);
    return {paragraph,hostText:paragraph+'\n'+link.textContent,fingerprint:result.approvalFingerprint};
  }finally{controller.close();}
}

test('acceptance reads the actual product session approval fingerprint without signing',async()=>{
  const published=await actualSessionPublication();
  assert.equal(displayedLineApprovalFingerprint(published.paragraph),published.fingerprint);
  assert.equal(displayedLineApprovalFingerprint(published.hostText),published.fingerprint);
  assert.equal(/New session approval fingerprint: ([0-9a-f]{64})/.test(published.hostText),false,
    'The obsolete acceptance label no longer describes the actual product');
});

test('displayed approval accepts one exact public paragraph and its download line',()=>{
  for(const text of [paragraph(),...['\n','\r\n','\n\n','\r\n\r\n'].map(separator=>paragraph()+separator+download)]){
    assert.equal(displayedLineApprovalFingerprint(text),fingerprint);
  }
});

test('displayed approval rejects malformed fingerprints and framing',()=>{
  for(const text of [paragraph(fingerprint.slice(1)),paragraph(fingerprint+'0'),paragraph('AA'.repeat(32)),
    paragraph(fingerprint,paired.slice(1)),paragraph(fingerprint,paired+'0'),paragraph(fingerprint,'BB'.repeat(32)),
    paragraph().replace('. Existing paired',' Existing paired'),paragraph().replace(paired+'.',paired),
    paragraph().replace('Line approval fingerprint: ','Line approval fingerprint:\n'),
    paragraph().replace('Existing paired phone fingerprint: ','Existing paired phone fingerprint:\n')]){
    assert.throws(()=>displayedLineApprovalFingerprint(text));
  }
});

test('displayed approval refuses duplicate labels, lookalikes and unbounded or foreign input',()=>{
  for(const text of [paragraph()+'\n'+paragraph(),paragraph()+'\n'+paragraph('33'.repeat(32)),
    paragraph().replace('Line approval fingerprint:','New session approval fingerprint:'),
    'prefix '+paragraph(),paragraph().replace('Line approval','line approval'),
    paragraph().replace('Line approval','Line\u0000 approval'),
    'synthetic-private-canary\n'+paragraph(),paragraph()+'x'.repeat(4097),paragraph()+'é'.repeat(2049),
    null,undefined,42,{toString(){assert.fail('Foreign text must not be inspected');}}]){
    assert.throws(()=>displayedLineApprovalFingerprint(text));
  }
});
