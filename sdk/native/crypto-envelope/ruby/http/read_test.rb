# frozen_string_literal: true
require_relative 'original_read'
require 'tmpdir'
require_relative '../custody/protected_recipient'
include ZrotextCandidate
owner=nil;receipt=nil
begin
  if ARGV==['--hardware']
    ProtectedRecipient.probe
    receipt=File.join(Dir.tmpdir,'zrotext-managed-read-owned-'+SecureRandom.hex(16)+'.json')
    owner=ProtectedRecipient.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0600) { |file| file.write(JSON.generate(pending_alias:name));file.flush;file.fsync } }
    puts JSON.generate(public:owner.public_point.unpack1('H*'));STDOUT.flush
  elsif !ARGV.empty?
    raise 'Unsupported argument'
  end
input=JSON.parse($stdin.read); f=input.fetch('Fixture'); b=lambda { |name| Base64.strict_decode64(f.fetch(name)) }
raise 'Native scalar exposed' if owner && f.key?('originalScalar')
root=ManifestChain::RootPin.enroll(b.call('rootPin'),b.call('fingerprint'))
prior=ManifestChain.genesis02(b.call('predecessor'),root,10000); active=ManifestChain.continue_chain(b.call('activation'),prior,2,10000)
scope=OriginalReplyReader::Scope.new(b.call('account'),b.call('device'),b.call('line'),b.call('interval'),b.call('connector'),b.call('readGrant'),b.call('originalReader'),'+12')
Dir.mktmpdir('zrotext-managed-current-') do |folder|
  path=File.join(folder,'history.dat')
  checkpoint=OriginalReplyCheckpoint.create(path,b.call('rootPin'),b.call('fingerprint'),scope,[prior,active],10000)
  transport=OriginalHTTP.new(origin:input.fetch('Origin'),timeout_ms:4000,additional_roots_pem:input.fetch('Roots'))
  client=OriginalCurrentClient.new(transport:transport,checkpoint:checkpoint,pin:b.call('rootPin'),fingerprint:b.call('fingerprint'),scope:scope,now:10000)
  index=0
  clock=lambda do
    if index.zero?
      begin
        client.current(credential:input.fetch('Grant'),clock:-> {10000});raise 'Reentrant current accepted'
      rescue OriginalHTTP::Failure
        # Must fail before any additional HTTP request.
      end
    end
    time=input.fetch('Clock')[[index,input.fetch('Clock').size-1].min];index+=1;time
  end
  key=owner || HpkeRecipient.software(OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(b.call('originalScalar')),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC)]).to_der))
  result={ok:false}
  begin
    value=client.read_with_recipient(credential:input.fetch('Grant'),event:b.call('event'),recipient:key,clock:clock,baseline:input.fetch('Baseline'))
    result.merge!(ok:true,plaintext:value.plaintext,digest:value.envelope_digest.unpack1('H*'),baseline:value.accepted_manifest_version,version:value.authority.manifest.version)
  rescue OriginalHTTP::Failure
    # Only operation under test may refuse.
  end
  reopened=OriginalReplyCheckpoint.open(path,b.call('rootPin'),b.call('fingerprint'),scope)
  saved=reopened.snapshot(scope,50000)
  result.merge!(revision:saved.revision,floor:saved.comparison_ms,history:saved.history.size,rollback_refused:false)
  begin
    reopened.snapshot(scope,saved.comparison_ms-1)
  rescue ArgumentError
    result[:rollback_refused]=true
  end
  puts JSON.generate(result)
end
ensure
  if owner
    name=owner.alias_name;point=nil
    begin;point=owner.public_point;ensure;owner.delete_created;end
    begin;key=ProtectedRecipient.open(name,point);key.close;raise 'Deleted key reopened';rescue ArgumentError;end
    File.open(receipt,'wb') { |file| file.write(JSON.generate(owned_key_deleted:true));file.flush;file.fsync }
    puts JSON.generate(owned_key_deleted:true);STDOUT.flush
  end
end
