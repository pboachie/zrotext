# frozen_string_literal: true
require_relative '../original_reply_reader'
include ZrotextCandidate
f=STDIN.each_line.to_h { |line| name,hex=line.strip.split("\t");[name,[hex].pack('H*')] }
prior=ManifestChain.genesis02(f.fetch('predecessor'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
active=ManifestChain.continue_chain(f.fetch('activation'),prior,2,10000)
successor=ManifestChain.continue_chain(f.fetch('successor'),active,2,10000)
revoked=ManifestChain.continue_chain(f.fetch('revoked'),active,2,10000)
scope=OriginalReplyReader::Scope.new(*f.values_at('account','device','line','interval','connector','readGrant','originalReader'),'+12')
raw,approval,installation=f.values_at('selection','approval','installation')
selection=OriginalReplyReader.verify_selection(raw,approval,installation,active,10000,scope)
checks=0
refuse=lambda do |&action|
  begin
    action.call
  rescue ArgumentError,OpenSSL::OpenSSLError
    checks+=1;next
  end
  raise 'Expected refusal'
end
raw.bytesize.times do |i|
  bad=raw.dup;bad.setbyte(i,bad.getbyte(i)^1);refuse.call { OriginalReplyReader.verify_selection(bad,approval,installation,active,10000,scope) }
end
high=lambda { |value| value.byteslice(0,32)+[format('%064x',ManifestChain::ORDER-value.byteslice(32,32).unpack1('H*').to_i(16))].pack('H*') }
refuse.call { OriginalReplyReader.verify_selection(raw,high.call(approval),installation,active,10000,scope) }
refuse.call { OriginalReplyReader.verify_selection(raw,approval,high.call(installation),active,10000,scope) }
[0,20000,2**63-1].each { |when_ms| refuse.call { OriginalReplyReader.verify_selection(raw,approval,installation,active,when_ms,scope) } }
refuse.call { OriginalReplyReader.verify_selection(raw,approval,installation,prior,10000,scope) }
wrong=f.fetch('connector').dup;wrong.setbyte(0,wrong.getbyte(0)^1)
wrong_scope=OriginalReplyReader::Scope.new(*f.values_at('account','device','line','interval'),wrong,*f.values_at('readGrant','originalReader'),'+12')
refuse.call { OriginalReplyReader.verify_selection(raw,approval,installation,active,10000,wrong_scope) }
scalar=f.fetch('originalScalar')
recipient=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC)]).to_der)
authority=lambda { |m| OriginalReplyReader::Authority.new(scope:scope,revision:'1',now_ms:10000,expires_ms:20000,manifest:m) }
opening=lambda { |bytes,source,key=recipient,event=f.fetch('event')| OriginalReplyReader.open_software(bytes,event,active,selection,scope,key,source) }
[active,successor].each do |current|
  calls=0;value=opening.call(f.fetch('inbound'),->{calls+=1;authority.call(current)});raise 'Open' unless value==f.fetch('text').dup.force_encoding(Encoding::UTF_8) && calls==2;checks+=1
end
changes=[{revision:'2'},{now_ms:9999},{now_ms:20000},{expires_ms:10000},{scope:wrong_scope},{manifest:successor},{manifest:revoked}]
changes.each do |change|
  calls=0
  refuse.call { opening.call(f.fetch('inbound'),->{calls+=1;value=authority.call(active);change.each { |k,v| value[k]=v } if calls==2;value}) }
  raise 'Final callback missing' unless calls==2
end
# Observe the actual owned body buffer without changing crypto or authority code.
captured=nil;calls=0
trace=TracePoint.new(:return) { |event| captured=event.return_value if event.method_id==:open && event.path.end_with?('/candidate_body.rb') }
trace.enable do
  refuse.call { opening.call(f.fetch('inbound'),->{calls+=1;a=authority.call(active);a.revision='2' if calls==2;a}) }
end
raise 'Plaintext remained after final refusal' unless captured.is_a?(String) && !captured.empty? && captured.bytes.all?(&:zero?)
checks+=1
['archiveOnly','inbound'].each do |name|
  calls=0;refuse.call { opening.call(f.fetch(name),->{calls+=1;authority.call(name=='inbound' ? revoked : active)}) };raise 'Early refusal' unless calls==1
end
bad_event=f.fetch('event').dup;bad_event.setbyte(0,bad_event.getbyte(0)^1)
refuse.call { opening.call(f.fetch('inbound'),->{raise 'Wrong event called source'},recipient,bad_event) }
wrong_key=OpenSSL::PKey::EC.generate('prime256v1');refuse.call { opening.call(f.fetch('inbound'),->{authority.call(active)},wrong_key) }
raw.setbyte(0,raw.getbyte(0)^1);approval.setbyte(0,approval.getbyte(0)^1);installation.setbyte(0,installation.getbyte(0)^1);f.fetch('account').setbyte(0,0)
raise 'Aliased proof' unless opening.call(f.fetch('inbound'),->{authority.call(active)})==f.fetch('text').dup.force_encoding(Encoding::UTF_8)
puts "Ruby original replies: #{checks} controls passed"
