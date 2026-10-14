# frozen_string_literal: true
require_relative 'owner_template'
require 'json'
require 'base64'
require 'securerandom'
include ZrotextCandidate
p=JSON.parse($stdin.read);f=p.fetch('Fixture');b=->(o,k){Base64.strict_decode64(o.fetch(k))}
pin=ManifestChain::RootPin.enroll(b.call(f,'rootPin'),b.call(f,'fingerprint'));manifest=ManifestChain.genesis02(b.call(f,'manifest'),pin,10000)
binding_of=lambda do |changed|
 o=f.fetch('binding');device=b.call(o,'device');device.setbyte(0,device.getbyte(0)^1) if changed
 OwnerTemplate::Binding.new(account:b.call(o,'account'),device:device,line:b.call(o,'line'),interval:b.call(o,'interval'),session:b.call(o,'session'),generation:o.fetch('generation'),peer:o.fetch('peer'),phone_reader:b.call(o,'phoneReader'),archive_reader:b.call(o,'archiveReader'))
end
wire=b.call(f,'envelope');store_scope=EncryptedTemplate::Scope.new(wire.byteslice(0,222));identity=SecureRandom.uuid;request=TemplateStore::SaveRequest.new(store_scope,identity,0,wire)
raise 'Save framing mismatch' unless request.revision==1 && request.headers.fetch('idempotency-key')==identity && request.body==wire && request.path=='/v1/owner/workflow/templates'
copy=request.body;copy.setbyte(0,copy.getbyte(0)^1);raise 'Mutable stored request' unless request.body==wire
raise 'Receipt mismatch' unless request.receipt('{"revision":1}')==1
['{"revision":1} ','{"revision":1,"revision":1}','{"revision":2}','{"revision":1,"sent":true}','[]','{"revision":1.0}'].each do |invalid|
 begin;request.receipt(invalid);raise 'Invalid receipt accepted';rescue ArgumentError;end
end
[-1,1,128].each do |revision|
 begin;TemplateStore::SaveRequest.new(store_scope,identity,revision,wire);raise 'Invalid CAS accepted';rescue ArgumentError;end
end
begin;TemplateStore::SaveRequest.new(store_scope,'',0,wire);raise 'Empty identity accepted';rescue ArgumentError;end
binding=binding_of.call(false);other=binding_of.call(true);current_calls=0;session_calls=0;client=nil
current=lambda do
 current_calls+=1;raise OwnerTemplate::Failure if p.fetch('CurrentFailAt',0)==current_calls
 sleep(p.fetch('SleepMS',0)/1000.0) if p.fetch('CurrentSleepAt',0)==current_calls
 mode=p.fetch('Mode');times=p.fetch('Now');at=times[[current_calls-1,times.size-1].min]
 OwnerTemplate::Current.new(binding:mode=='binding' ? other : binding,manifest:manifest,now_ms:at,valid_for_ms:p.fetch('ValidForMS'),owner_live:mode!='owner-dead',consent_live:mode!='consent-dead',active:mode!='inactive')
end
session=lambda do
 session_calls+=1;csrf=p.fetch('CSRF');csrf+='-changed' if p.fetch('SessionChangeAt',0)==session_calls
 OwnerTemplate::Session.new(origin:p.fetch('SessionOrigin',p.fetch('Origin')),cookie:p.fetch('Cookie'),csrf:csrf)
end
if p.key?('Lifecycle')
 require_relative 'lifecycle_test'
 OwnerTemplateLifecycleTest.run(p.fetch('Origin'),binding,b.call(f.fetch('scope'),'templateId'),session,p.fetch('Roots'))
 puts JSON.generate(lifecycle:4);exit
end
results=[];started=Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
 client=OwnerTemplate.new(origin:p.fetch('Origin'),binding:binding,template_id:b.call(f.fetch('scope'),'templateId'),current:current,session:session,enabled:p.fetch('Enabled'),timeout_ms:p.fetch('TimeoutMS'),additional_roots_pem:p.fetch('Roots'))
 p.fetch('Reads').times do
  begin;value=client.read_latest;results<<{accepted:true,digest:value.encrypted_digest,ack:value.request_acknowledged,pending:value.matches_pending};rescue OwnerTemplate::Failure=>e;results<<{accepted:false,code:e.code,unknown:e.unknown};end
 end
rescue OwnerTemplate::Failure=>e
 p.fetch('Reads').times {results<<{accepted:false,code:e.code,unknown:e.unknown}}
ensure
 client&.close
end
elapsed=Process.clock_gettime(Process::CLOCK_MONOTONIC)-started;sleep(p.fetch('SettleMS',0)/1000.0)
puts JSON.generate(results:results,elapsed:elapsed,currentCalls:current_calls,sessionCalls:session_calls)
