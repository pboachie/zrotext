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
binding=binding_of.call(false);other=binding_of.call(true);current_calls=0;session_calls=0;review_calls=0;client=nil;current_entered=Queue.new;current_release=Queue.new;review_entered=Queue.new;review_release=Queue.new
current=lambda do
 current_calls+=1
 if p.fetch('CurrentBlockAt',0)==current_calls;current_entered.push(true);Timeout.timeout(10){current_release.pop};end
 raise OwnerTemplate::Failure if p.fetch('CurrentFailAt',0)==current_calls
 sleep(p.fetch('SleepMS',0)/1000.0) if p.fetch('CurrentSleepAt',0)==current_calls
 mode=p.fetch('Mode');times=p.fetch('Now');at=times[[current_calls-1,times.size-1].min]
 OwnerTemplate::Current.new(binding:mode=='binding' ? other : binding,manifest:manifest,now_ms:at,valid_for_ms:p.fetch('ValidForMS'),owner_live:mode!='owner-dead',consent_live:mode!='consent-dead',active:mode!='inactive')
end
session=lambda do
 session_calls+=1;csrf=p.fetch('CSRF');csrf+='-changed' if p.fetch('SessionChangeAt',0)==session_calls
 OwnerTemplate::Session.new(origin:p.fetch('SessionOrigin',p.fetch('Origin')),cookie:p.fetch('Cookie'),csrf:csrf)
end
review=lambda do |_value|
 review_calls+=1
 if p.fetch('Ops').include?('race-prepare') && review_calls==1;review_entered.push(true);Timeout.timeout(10){review_release.pop};end
 sleep(p.fetch('ReviewSleepMS',0)/1000.0)
 raise 'Synthetic review refusal' if p.fetch('ReviewFail',false)
end
wire=Base64.strict_decode64(p.fetch('Envelope',f.fetch('envelope')));scope=EncryptedTemplate::Scope.new(wire.byteslice(0,222));ticket=nil
results=[];started=Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
 client=OwnerTemplate.new(origin:p.fetch('Origin'),binding:binding,template_id:b.call(f.fetch('scope'),'templateId'),current:current,session:session,review:review,enabled:p.fetch('Enabled'),timeout_ms:p.fetch('TimeoutMS'),additional_roots_pem:p.fetch('Roots'))
 p.fetch('Ops').each_with_index do |op,i|
  sleep(p.fetch('DelayMS',[]).fetch(i,0)/1000.0)
  result={accepted:false,unknown:false,ack:false,matches:false}
  begin
   case op
   when 'prepare'
    ticket=client.prepare_save(scope,p.fetch('RequestID'),p.fetch('Expected'),wire)
   when 'race-prepare'
    first=Thread.new {client.prepare_save(scope,p.fetch('RequestID'),p.fetch('Expected'),wire)}
    begin
     Timeout.timeout(3){review_entered.pop}
     begin;client.prepare_save(scope,p.fetch('RequestID'),p.fetch('Expected'),wire);raise 'Concurrent prepare accepted';rescue OwnerTemplate::Failure=>e;raise unless e.code=='busy';end
    ensure
     review_release.push(true)
    end
    ticket=first.value
   when 'close-commit'
    attempt=Thread.new {begin;client.commit(ticket);nil;rescue OwnerTemplate::Failure=>e;e;end}
    begin
     Timeout.timeout(3){current_entered.pop};client.close
    ensure
     current_release.push(true)
    end
    error=attempt.value;raise 'Closed commit acknowledged' unless error;raise error
   when 'commit','retry'
    ack=op=='commit' ? client.commit(ticket) : client.retry_unknown(ticket)
    result[:ack]=true;result[:digest]=ack.identity.encrypted_digest
   when 'read','verify'
    snapshot=op=='read' ? client.read_latest : client.verify_unknown(ticket)
    result[:ack]=snapshot.request_acknowledged;result[:matches]=snapshot.matches_pending;result[:digest]=snapshot.encrypted_digest
   when 'mutate';wire.setbyte(wire.bytesize-1,wire.getbyte(wire.bytesize-1)^1)
   when 'close';client.close
   else;raise 'Unknown operation'
   end
   result[:accepted]=true
  rescue OwnerTemplate::Failure=>e
   result[:unknown]=e.unknown;result[:code]=e.code
  end
  pending=client.pending;result[:pending]=!pending.nil?
  if pending;result[:pendingID]=pending.request_id;result[:pendingDigest]=pending.encrypted_digest;end
  results<<result
 end
ensure
 client&.close;review_release.push(true);current_release.push(true)
end
elapsed=Process.clock_gettime(Process::CLOCK_MONOTONIC)-started;sleep(p.fetch('SettleMS',0)/1000.0)
puts JSON.generate(results:results,elapsed:elapsed,currentCalls:current_calls,sessionCalls:session_calls,reviewCalls:review_calls)
