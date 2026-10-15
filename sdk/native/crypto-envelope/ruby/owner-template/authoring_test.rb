# frozen_string_literal: true
require_relative 'owner_template_authoring'
require 'json'
require 'base64'
include ZrotextCandidate
p=JSON.parse($stdin.read);f=p.fetch('Fixture');b=->(o,k){Base64.strict_decode64(o.fetch(k))}
pin=ManifestChain::RootPin.enroll(b.call(f,'rootPin'),b.call(f,'fingerprint'));m=ManifestChain.genesis02(b.call(f,'manifest'),pin,10000)
o=f.fetch('binding');binding=OwnerTemplate::Binding.new(account:b.call(o,'account'),device:b.call(o,'device'),line:b.call(o,'line'),interval:b.call(o,'interval'),session:b.call(o,'session'),generation:o.fetch('generation'),peer:o.fetch('peer'),phone_reader:b.call(o,'phoneReader'),archive_reader:b.call(o,'archiveReader'))
evil=Object.new
def evil.==(_other) = true
$authoring_seals=0
class << HpkeRecipient
 alias_method :authoring_original_seal_content,:seal_content
 def seal_content(*args);$authoring_seals+=1;authoring_original_seal_content(*args);end
end
currents=0;sessions=0;reviewed=0;metadata=0;client=nil;entered=Queue.new;release=Queue.new
current=-> {
 currents+=1;client&.close if p.fetch('ClientCloseAt',0)==currents
 sleep(p.fetch('SleepMS',0)/1000.0) if p.fetch('CurrentSleepAt',0)==currents
 raise OwnerTemplate::Failure if p.fetch('CurrentFailAt',0)==currents
 times=p.fetch('Now');now=times[[currents-1,times.size-1].min]
 OwnerTemplate::Current.new(binding:binding,manifest:m,now_ms:now,valid_for_ms:p.fetch('ValidForMS'),owner_live:!(p.fetch('OwnerLost',false) && reviewed>0),consent_live:true,active:true)
}
session=-> {
 sessions+=1;csrf=p.fetch('CSRF');csrf+='-changed' if p.fetch('SessionChangeAt',0)==sessions || (p.fetch('CSRFChanged',false) && reviewed>0)
 OwnerTemplate::Session.new(origin:p.fetch('Origin'),cookie:p.fetch('Cookie'),csrf:csrf)
}
draft=-> {OwnerTemplate::DraftState.new(epoch:1+(reviewed>0 && p.fetch('EpochChanged',false) ? 1 : 0),revision:1+(reviewed>0 && p.fetch('RevisionChanged',false) ? 1 : 0),custody_live:p.fetch('EvilCustody',false) ? evil : (p.fetch('CustodyLive') && !(reviewed>0 && p.fetch('CustodyLost',false))))}
review=->(_) {reviewed+=1;if p.fetch('ReviewBlock',false);entered.push(true);release.pop;end;sleep(p.fetch('ReviewSleepMS',0)/1000.0);p.fetch('EvilReview',false) ? evil : p.fetch('Decision')}
author=OwnerTemplate::Authoring.new(origin:p.fetch('Origin'),binding:binding,template_id:b.call(f.fetch('scope'),'templateId'),current:current,session:session,enabled:p.fetch('Enabled'),timeout_ms:p.fetch('TimeoutMS'),additional_roots_pem:p.fetch('Roots'),draft:draft,draft_review:review,ciphertext_review:->(_) {metadata+=1})
client=author.client;wire=b.call(f,'envelope');scope=EncryptedTemplate::Scope.new(wire.byteslice(0,222));content=nil
begin;content=TemplateContent.new(p.fetch('Template'),p.fetch('Values'));rescue TemplateContent::Failure;end
ticket=nil
if p.fetch('PriorSaved',false) || p.fetch('PriorUnknown',false)
 ticket=client.prepare_save(scope,'00000000-0000-0000-0000-000000000041',0,wire)
 if p.fetch('PriorUnknown',false);begin;client.commit(ticket);raise 'Expected unknown';rescue OwnerTemplate::Failure=>e;raise unless e.unknown;end;end
end
results=[];started=Process.clock_gettime(Process::CLOCK_MONOTONIC)
prepare=-> {begin;raise OwnerTemplate::Failure unless content;next_ticket=author.prepare('00000000-0000-0000-0000-000000000041',0,scope,content,1,1);ticket=next_ticket;results<<true;rescue OwnerTemplate::Failure;results<<false;end}
begin
 if p.fetch('ReviewBlock',false)
  worker=Thread.new {prepare.call};Timeout.timeout(10){entered.pop}
  begin
   if p.fetch('ForeignReview',false);ticket=client.prepare_save(scope,'00000000-0000-0000-0000-000000000041',0,wire)
   else;begin;author.prepare('00000000-0000-0000-0000-000000000041',0,scope,content,1,1);raise 'Concurrent author accepted';rescue OwnerTemplate::Failure=>e;raise unless e.code=='busy';end;end
  ensure;release.push(true);end
  worker.join
 else
  p.fetch('Repeat').times {prepare.call}
 end
 elapsed=Process.clock_gettime(Process::CLOCK_MONOTONIC)-started;sleep(p.fetch('DelayMS',0)/1000.0);ack=false
 if p.fetch('Commit',false) && ticket;begin;p.fetch('PriorUnknown',false) ? client.retry_unknown(ticket) : client.commit(ticket);ack=true;rescue OwnerTemplate::Failure;end;end
 fresh=false;read=false
 if p.fetch('ProbeExpired',false)
  begin;client.prepare_save(scope,'00000000-0000-0000-0000-000000000042',0,wire);fresh=true;rescue OwnerTemplate::Failure;end
  begin;client.read_latest;read=true;rescue OwnerTemplate::Failure;end
 end
 sleep(p.fetch('SettleMS',0)/1000.0)
 puts JSON.generate(accepted:results,ack:ack,fresh:fresh,read:read,reviewed:reviewed,metadata:metadata,seals:$authoring_seals,currentCalls:currents,elapsed:elapsed)
ensure
 author.close
end
