# frozen_string_literal: true
require_relative 'owner_template_opening'
require 'json'
require 'base64'
require 'securerandom'
include ZrotextCandidate
require 'tmpdir'
if ARGV==['--probe']
 begin;ProtectedRecipient.probe;puts JSON.generate(available:true);rescue ArgumentError;puts JSON.generate(available:false);end
 exit
end
owner=nil;recipient=nil;receipt=nil
begin
 if ARGV==['--hardware']
  ProtectedRecipient.probe;receipt=File.join(Dir.tmpdir,'zrotext-opening-owned-'+SecureRandom.hex(16)+'.json')
  owner=ProtectedRecipient.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0600) { |file| file.write(JSON.generate(pending_alias:name));file.flush;file.fsync } }
  recipient=ProtectedRecipient.open(owner.alias_name,owner.public_point)
  puts JSON.generate(public:owner.public_point.unpack1('H*'));STDOUT.flush
 elsif !ARGV.empty?;raise 'Unsupported argument';end
p=JSON.parse($stdin.read);f=p.fetch('Fixture');raise 'Native scalar exposed' if recipient && f.key?('archiveScalar');b=->(o,k){Base64.strict_decode64(o.fetch(k))}
pin=ManifestChain::RootPin.enroll(b.call(f,'rootPin'),b.call(f,'fingerprint'));manifest=ManifestChain.genesis02(b.call(f,'manifest'),pin,10000)
binding_of=lambda do |changed|
 o=f.fetch('binding');device=b.call(o,'device');device.setbyte(0,device.getbyte(0)^1) if changed
 OwnerTemplate::Binding.new(account:b.call(o,'account'),device:device,line:b.call(o,'line'),interval:b.call(o,'interval'),session:b.call(o,'session'),generation:o.fetch('generation'),peer:o.fetch('peer'),phone_reader:b.call(o,'phoneReader'),archive_reader:b.call(o,'archiveReader'))
end
binding=binding_of.call(false);other=binding_of.call(true);current_calls=0;session_calls=0;client=nil
current=lambda do
 current_calls+=1;recipient&.close if p.fetch('ProviderCloseAt',0)==current_calls;client&.close if p.fetch('ClientCloseAt',0)==current_calls;raise OwnerTemplate::Failure if p.fetch('CurrentFailAt',0)==current_calls
 sleep(p.fetch('SleepMS',0)/1000.0) if p.fetch('CurrentSleepAt',0)==current_calls
 mode=p.fetch('Mode');times=p.fetch('Now');at=times[[current_calls-1,times.size-1].min]
 OwnerTemplate::Current.new(binding:mode=='binding' ? other : binding,manifest:manifest,now_ms:at,valid_for_ms:p.fetch('ValidForMS'),owner_live:mode!='owner-dead',consent_live:mode!='consent-dead',active:mode!='inactive')
end
session=lambda do
 session_calls+=1;csrf=p.fetch('CSRF');csrf+='-changed' if p.fetch('SessionChangeAt',0)==session_calls
 OwnerTemplate::Session.new(origin:p.fetch('SessionOrigin',p.fetch('Origin')),cookie:p.fetch('Cookie'),csrf:csrf)
end
results=[];started=Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
 client=OwnerTemplate.new(origin:p.fetch('Origin'),binding:binding,template_id:b.call(f.fetch('scope'),'templateId'),current:current,session:session,enabled:p.fetch('Enabled'),timeout_ms:p.fetch('TimeoutMS'),additional_roots_pem:p.fetch('Roots'),review:->(_) {})
 if p.fetch('SetupPending',false)
  wire=b.call(f,'envelope');ticket=client.prepare_save(EncryptedTemplate::Scope.new(wire.byteslice(0,222)),'00000000-0000-0000-0000-000000000041',0,wire)
  begin;client.commit(ticket);raise 'Expected unknown';rescue OwnerTemplate::Failure=>e;raise unless e.unknown;end
  current_calls=session_calls=0
 end
 client.close if p.key?('ClientInitiallyClosed')
 opening=OwnerTemplate::Opening.new(client:client,origin:p.fetch('Origin'),binding:p.key?('DedicatedMismatch') ? other : binding,template_id:b.call(f.fetch('scope'),'templateId'),current:current,session:session,enabled:p.fetch('Enabled'),timeout_ms:p.fetch('TimeoutMS'),additional_roots_pem:p.fetch('Roots'))
 scalar=recipient ? ("\x00".b*31+"\x01".b) : b.call(f,'archiveScalar');scalar.setbyte(31,scalar.getbyte(31)^1) if p.fetch('WrongKey',false)
 der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC)]).to_der
 key=OpenSSL::PKey.read(der)
 p.fetch('Reads').times do
  begin;value=recipient ? opening.open_latest(recipient) : opening.open_latest_software(key);results<<{accepted:true,digest:value.encrypted_digest,ack:value.request_acknowledged,pending:value.matches_pending,text:value.preview.fetch(:text),segments:value.preview.fetch(:estimate)};rescue OwnerTemplate::Failure=>e;results<<{accepted:false,code:e.code,unknown:e.unknown};end
 end
rescue OwnerTemplate::Failure=>e
 p.fetch('Reads').times {results<<{accepted:false,code:e.code,unknown:e.unknown}}
ensure
 opening&.close;client&.close
end
elapsed=Process.clock_gettime(Process::CLOCK_MONOTONIC)-started;sleep(p.fetch('SettleMS',0)/1000.0)
puts JSON.generate(results:results,elapsed:elapsed,currentCalls:current_calls,sessionCalls:session_calls)

ensure
 recipient&.close
 if owner
  name=owner.alias_name;point=nil;begin;point=owner.public_point;ensure;owner.delete_created;end
  begin;key=ProtectedRecipient.open(name,point);key.close;raise 'Deleted key reopened';rescue ArgumentError;end
  File.open(receipt,'wb') { |file| file.write(JSON.generate(owned_key_deleted:true));file.flush;file.fsync }
  puts JSON.generate(owned_key_deleted:true);STDOUT.flush
 end
end
