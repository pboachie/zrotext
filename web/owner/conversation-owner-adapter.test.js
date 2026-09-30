// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {create}=require("./conversation-owner-adapter.js");
const scope={account:"a",session:"s",interval:"i",device:"d",line:"l",generation:"1",peer:"+12",reader:"r",manifest:"m"};
function fixture() {
 let current={phase:"active",scope:{...scope},validForMs:1000},calls=[],signed=0;
 let duringSign=()=>{},csrf="fixture-csrf";
 const custody={openSealed:async()=>"synthetic incoming",prepare:async(s,body)=>({s,body}),signReviewed:async(review,s,body)=>{
   assert.deepEqual(review,{s,body});signed++;await duringSign();return {opaque:"synthetic signed packet"};},close:()=>{current=null;}};
 const adapter=create({enabled:true,currentCsrf:()=>csrf,readAuthority:async()=>current,custody,endpoints:{read:event=>"/v1/owner/conversation/events/"+event,submit:"/v1/owner/conversation/send"},
 fetch:async(url,options)=>{calls.push({url,options});return {ok:true,headers:new Headers({"Content-Type":"application/vnd.zrotext.sealed.v1"}),arrayBuffer:async()=>new Uint8Array(500).buffer,json:async()=>({status:"queued"})};}});
 return {adapter,calls,custody,csrf:v=>{csrf=v;},get signed(){return signed;},replace:v=>{current=v;},duringSign:fn=>{duringSign=fn;}};
}
test("owner adapter defaults disabled and never fetches",async()=>{await assert.rejects(create({}).authority());});
test("cancelled review makes no signature or request",async()=>{const f=fixture();await f.adapter.prepare({scope,body:"exact synthetic"});assert.equal(f.signed,0);assert.equal(f.calls.length,0);});
test("one exact confirmation uses owner cookie and cannot replay",async()=>{const f=fixture(),candidate=await f.adapter.prepare({scope,body:"exact synthetic"});assert.deepEqual(await candidate.confirm(()=>{}),{status:"queued"});assert.equal(f.signed,1);assert.equal(f.calls.length,1);assert.equal(f.calls[0].options.credentials,"same-origin");assert.equal(f.calls[0].options.headers["x-zrotext-csrf"],"fixture-csrf");assert.equal(f.calls[0].options.redirect,"error");await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);});
test("edit during signing creates no submission",async()=>{const f=fixture();let changed=false;f.duringSign(()=>{changed=true;});const candidate=await f.adapter.prepare({scope,body:"exact synthetic"});await assert.rejects(candidate.confirm(()=>{if(changed)throw Error("revision changed");}));assert.equal(f.calls.length,0);});
test("account or session change and close reject stale confirmation",async()=>{const f=fixture(),candidate=await f.adapter.prepare({scope,body:"synthetic"});f.replace({phase:"active",scope:{...scope,session:"other"},validForMs:1000});await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.signed,0);f.adapter.close();await assert.rejects(f.adapter.authority());});
test("only verified bounded sealed content can become browser text",async()=>{const f=fixture();assert.equal(await f.adapter.read({scope,event:"synthetic"}),"synthetic incoming");await assert.rejects(f.adapter.read({scope,event:"../escape"}));assert.equal(f.calls.length,1);});

test("missing CSRF prevents custody preparation and all network",async()=>{const f=fixture();f.csrf(null);await assert.rejects(f.adapter.prepare({scope,body:"synthetic"}));await assert.rejects(f.adapter.read({scope,event:"synthetic"}));assert.equal(f.signed,0);assert.equal(f.calls.length,0);});
test("CSRF rotation during signing prevents submission",async()=>{const f=fixture();f.duringSign(()=>f.csrf("rotated-fixture-csrf"));const c=await f.adapter.prepare({scope,body:"synthetic"});await assert.rejects(c.confirm(()=>{}));assert.equal(f.calls.length,0);});
