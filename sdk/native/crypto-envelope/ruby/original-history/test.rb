# frozen_string_literal: true
require_relative 'original_reply_checkpoint'
include ZrotextCandidate
mode,path=ARGV;f=STDIN.each_line.to_h { |line| name,hex=line.strip.split("\t");[name,[hex].pack('H*')] }
scope=OriginalReplyReader::Scope.new(*f.values_at('account','device','line','interval','connector','readGrant','originalReader'),'+12')
prior=ManifestChain.genesis02(f.fetch('predecessor'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
active=ManifestChain.continue_chain(f.fetch('activation'),prior,2,10000);successor=ManifestChain.continue_chain(f.fetch('successor'),active,2,10000);revoked=ManifestChain.continue_chain(f.fetch('revoked'),active,2,10000);history=[prior,active,successor]
checks=0;refuse=lambda do |&block|
  begin;block.call;rescue ArgumentError,IOError,SystemCallError,OpenSSL::OpenSSLError;checks+=1;next;end
  raise 'Expected history refusal'
end
opening=lambda { |target=path,s=scope| OriginalReplyCheckpoint.open(target,f.fetch('rootPin'),f.fetch('fingerprint'),s) }
case mode
when '--partial'
  File.open(path,'ab') { |file| file.write("\x00\x00".b);file.flush;file.fsync;exit! 19 }
when '--advance'
  j=opening.call
  begin;j.accept(scope,history,3,10006) { |_m,n| n };puts 'CAS won';rescue ArgumentError;exit 3;end
  exit
when '--verify'
  raise 'Child CAS state' unless opening.call.snapshot(scope,10006).revision==4;puts 'Restart CAS verified';exit
when '--refused'
  refuse.call { opening.call };puts 'Interrupted append refused';exit
end
refuse.call { opening.call };j=OriginalReplyCheckpoint.create(path,f.fetch('rootPin'),f.fetch('fingerprint'),scope,[prior,active],10000)
refuse.call { OriginalReplyCheckpoint.create(path,f.fetch('rootPin'),f.fetch('fingerprint'),scope,[prior,active],10000) }
wrong=f.fetch('readGrant').dup;wrong.setbyte(0,wrong.getbyte(0)^1);wrong_scope=OriginalReplyReader::Scope.new(*f.values_at('account','device','line','interval','connector'),wrong,f.fetch('originalReader'),'+12')
refuse.call { opening.call(path,wrong_scope) };refuse.call { j.snapshot(scope,9999) };refuse.call { j.snapshot(scope,2**63-1) }
read=j.snapshot(scope,10001);raise 'Snapshot mutated floor' unless read.revision==1 && read.comparison_ms==10000;checks+=1
refuse.call { j.accept(scope,history,0,10001) { raise 'CAS before fence' } }
refuse.call { j.accept(scope,history,1,10001) { raise ArgumentError,'Fence refused' } }
refuse.call { j.accept(scope,history,1,10001) { 9999 } };refuse.call { j.accept(scope,history,1,10001) { 2**63-1 } }
raise 'Failed fence committed' unless j.snapshot(scope,10000).revision==1;checks+=1
next_state=j.accept(scope,history,1,10002) { 10003 };raise 'Advance' unless next_state.revision==2 && next_state.comparison_ms==10003;checks+=1
refuse.call { j.snapshot(scope,10002) };refuse.call { j.accept(scope,[prior,active,revoked],2,10003) { |_m,n| n } };refuse.call { j.accept(scope,[prior,active],2,10003) { |_m,n| n } }
reopened=opening.call;restored=reopened.snapshot(scope,10004).history
selection=OriginalReplyReader.verify_selection(*f.values_at('selection','approval','installation'),restored[1],10000,scope)
key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(f.fetch('originalScalar')),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC)]).to_der)
committed=reopened.accept(scope,history,2,10004) { 10005 }
plain=OriginalReplyReader.open_software(f.fetch('inbound'),f.fetch('event'),restored[1],selection,scope,key,->{OriginalReplyReader::Authority.new(scope:scope,revision:'1',now_ms:10005,expires_ms:20000,manifest:committed.history[2])})
raise 'Restored opening' unless plain==f.fetch('text').dup.force_encoding(Encoding::UTF_8);checks+=1
bytes=File.binread(path);bad=path+'.bad'
[0,4,98,130,161,162,166,174,182,bytes.bytesize-33,bytes.bytesize-1].each do |at|
  copy=bytes.dup;copy.setbyte(at,copy.getbyte(at)^1);File.binwrite(bad,copy);refuse.call { opening.call(bad) }
end
File.delete(bad);refuse.call { reopened.snapshot(scope,10004) }
puts "Ruby original history #{checks} controls passed"
