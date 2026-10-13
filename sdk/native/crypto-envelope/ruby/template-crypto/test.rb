# frozen_string_literal: true
require_relative 'encrypted_template'
require 'json'
require 'base64'
require 'tmpdir'
require_relative '../custody/protected_recipient'
include ZrotextCandidate
boundary=OpenSSL::PKey::EC.generate('prime256v1');point=boundary.public_key.to_octet_string(:uncompressed)
[1,31,32,33,32768].each do |size|
 plain="\x07".b*size;wrap=HpkeRecipient.seal_content(point,''.b,''.b,plain)
 raise 'Content boundary mismatch' unless HpkeRecipient.open_content(boundary,point,wrap.byteslice(0,65),''.b,''.b,wrap.byteslice(65..))==plain
 accepted=false
 begin;HpkeRecipient.open(boundary,point,wrap.byteslice(0,65),''.b,''.b,wrap.byteslice(65..));accepted=true;rescue ArgumentError;end
 raise 'CEK boundary widened' unless accepted==(size==32)
end
[0,32769].each do |size|
 begin;HpkeRecipient.seal_content(point,''.b,''.b,"\x07".b*size);raise 'Content size accepted';rescue ArgumentError;end
end
owner=nil;receipt=nil
begin
  if ARGV==['--hardware']
    ProtectedRecipient.probe
    receipt=File.join(Dir.tmpdir,'zrotext-managed-template-owned-'+SecureRandom.hex(16)+'.json')
    owner=ProtectedRecipient.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0600) { |file| file.write(JSON.generate(pending_alias:name));file.flush;file.fsync } }
    puts JSON.generate(public:owner.public_point.unpack1('H*'));STDOUT.flush
  elsif !ARGV.empty?
    raise 'Unsupported argument'
  end
input=JSON.parse($stdin.read);f=input.fetch('Fixture');b=->(o,k){Base64.strict_decode64(o.fetch(k))}
raise 'Native scalar exposed' if owner && f.key?('archiveScalar')
pin=ManifestChain::RootPin.enroll(b.call(f,'rootPin'),b.call(f,'fingerprint'));manifest=ManifestChain.genesis02(b.call(f,'manifest'),pin,10000)
recipient=if owner;owner.method(:open_content);else
  key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(b.call(f,'archiveScalar')),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC)]).to_der)
  HpkeRecipient.software_content(key)
end
results=input.fetch('Cases').map do |c|
  result={accepted:false};calls=0
  source=lambda do
    at=calls;calls+=1;raise EncryptedTemplate::Failure if at>0 && c.fetch('FailFinal')
    EncryptedTemplate::Authority.new(manifest:manifest,now_ms:c.fetch('Clock')[[at,c.fetch('Clock').size-1].min])
  end
  content=c.fetch('Mode')=='seal' ? TemplateContent.parse(b.call(c,'Canonical')) : nil
  begin
    s=c.fetch('Scope');scope=EncryptedTemplate::Scope.capture(account:b.call(s,'accountId'),device:b.call(s,'deviceId'),line:b.call(s,'lineId'),interval:b.call(s,'intervalId'),template:b.call(s,'templateId'),binding:s.fetch('bindingGeneration'),revision:s.fetch('revision'),expires:s.fetch('expiresMs'),trust:s.fetch('trustGeneration'),version:s.fetch('manifestVersion'),peer_digest:b.call(s,'peerDigest'),reader:b.call(s,'readerId'),manifest_digest:b.call(s,'manifestDigest'))
    value=content ? EncryptedTemplate.seal(scope,content,source) : EncryptedTemplate.open(scope,b.call(c,'Envelope'),recipient,source).canonical
    result.merge!(accepted:true);result[content ? :envelope : :canonical]=Base64.strict_encode64(value)
  rescue EncryptedTemplate::Failure
    # Only tested operation may refuse.
  end
  result[:calls]=calls;result
end
puts JSON.generate(cases:results);STDOUT.flush

ensure
  if owner
    name=owner.alias_name;point=nil
    begin;point=owner.public_point;ensure;owner.delete_created;end
    begin;key=ProtectedRecipient.open(name,point);key.close;raise 'Deleted key reopened';rescue ArgumentError;end
    File.open(receipt,'wb') { |file| file.write(JSON.generate(owned_key_deleted:true));file.flush;file.fsync }
    puts JSON.generate(owned_key_deleted:true);STDOUT.flush
  end
end
