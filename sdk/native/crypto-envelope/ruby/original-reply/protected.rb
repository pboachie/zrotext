# frozen_string_literal: true
require_relative '../original_reply_reader'
require_relative '../custody/protected_recipient'
include ZrotextCandidate
if ARGV==['--probe']
  begin;ProtectedRecipient.probe;rescue ArgumentError,LoadError;exit 77;end
  exit 0
end
raise 'Pending receipt required' unless ARGV.size==1
receipt=ARGV.fetch(0);owner=nil;checks=0
refuse=lambda do |&action|
  begin;action.call;rescue ArgumentError,OpenSSL::OpenSSLError;checks+=1;next;end
  raise 'Expected refusal'
end
begin
  owner=ProtectedRecipient.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0600) { |file| file.write(name+"\n");file.flush;file.fsync } }
  puts owner.public_point.unpack1('H*');STDOUT.flush
  f=STDIN.each_line.to_h { |line| name,hex=line.strip.split("\t");[name,[hex].pack('H*')] };raise 'Native scalar present' if f.key?('originalScalar')
  prior=ManifestChain.genesis02(f.fetch('predecessor'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
  active=ManifestChain.continue_chain(f.fetch('activation'),prior,2,10000);successor=ManifestChain.continue_chain(f.fetch('successor'),active,2,10000);revoked=ManifestChain.continue_chain(f.fetch('revoked'),active,2,10000)
  scope=OriginalReplyReader::Scope.new(*f.values_at('account','device','line','interval','connector','readGrant','originalReader'),'+12')
  selection=OriginalReplyReader.verify_selection(*f.values_at('selection','approval','installation'),active,10000,scope)
  authority=lambda { |m| OriginalReplyReader::Authority.new(scope:scope,revision:'1',now_ms:10000,expires_ms:20000,manifest:m) }
  opening=lambda { |recipient,source| OriginalReplyReader.open_with_recipient(f.fetch('inbound'),f.fetch('event'),active,selection,scope,recipient,source) }
  expected=f.fetch('text').dup.force_encoding(Encoding::UTF_8)
  [active,successor].each { |current| calls=0;raise 'Native open' unless opening.call(owner,->{calls+=1;authority.call(current)})==expected && calls==2;checks+=1 }
  name=owner.alias_name;point=owner.public_point;reopened=ProtectedRecipient.open(name,point)
  begin
    raise 'Reopened' unless opening.call(reopened,->{authority.call(active)})==expected;checks+=1;refuse.call { reopened.delete_created }
  ensure;reopened.close;end
  refuse.call { opening.call(reopened,->{authority.call(active)}) }
  refuse.call { opening.call(owner,->{authority.call(revoked)}) }
  calls=0;refuse.call { opening.call(owner,->{calls+=1;a=authority.call(active);a.revision='2' if calls==2;a}) };raise 'Final check' unless calls==2
  wrong=OpenSSL::PKey::EC.generate('prime256v1').public_key.to_octet_string(:uncompressed)
  refuse.call { key=ProtectedRecipient.open(name,wrong);key.close }
  owner.delete_created;owner=nil;File.delete(receipt)
  refuse.call { key=ProtectedRecipient.open(name,point);key.close }
  puts "QUALIFIED: Ruby protected original reply #{checks} controls passed"
ensure
  if owner;owner.delete_created;File.delete(receipt);owner.close;end
end
