# frozen_string_literal: true
require 'base64'
require 'tmpdir'
require_relative 'compose02'
include ZrotextCandidate
$checks=0
def check(value) = (raise 'Composition02 assertion' unless value; $checks+=1)
def refuses
  yield
rescue ArgumentError,OpenSSL::OpenSSLError,EncodingError
  $checks+=1
else
  raise 'Invalid composition02 accepted'
end
def emit(value) = puts('ENVELOPE '+Base64.strict_encode64(value))
if ARGV.length==4 && ARGV[0]=='--replay'
  f=File.readlines(ARGV[2]).to_h { |line| key,hex=line.strip.split("\t");[key,[hex].pack('H*')] }
  m=ManifestChain.genesis02(f.fetch('manifest'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
  point=m.key_records.find { |k| k.getbyte(0)==5 }.byteslice(33,65);signer=ProtectedSigner.open(File.read(ARGV[1]).strip,point)
  begin
    r={manifest:m,now_ms:10000,message:'1'.b*16,device:f.fetch('device'),line:f.fetch('line'),observed_ms:10000,expires_ms:20000,peer:'+12',content:'Native composed02 🌱',signer:signer,recipients:m.key_records.select { |k| [1,2].include?(k.getbyte(0)) }.map { |k| [k.getbyte(0),k.byteslice(1,32)] }}
    check(f.fetch('expected')==Compose02.compose_or_replay(ARGV[3],f.fetch('rootPin'),f.fetch('fingerprint'),current:-> { [m,11000] },**r))
  ensure;signer.close;end
  exit
end
if ARGV==['--probe']
  begin;ProtectedSigner.probe;rescue ArgumentError,Fiddle::DLError;exit 77;end
  exit
end
raise ArgumentError,'Pending receipt required' unless ARGV.length==1
receipt=ARGV[0];owner=nil;deleted=false
begin
  owner=ProtectedSigner.create { |name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0o600) { |f| f.write(name+"\n");f.flush;f.fsync } }
  point=owner.public_point;puts point.unpack1('H*');STDOUT.flush
  f=STDIN.read.lines.to_h { |line| name,hex=line.strip.split("\t");[name,[hex].pack('H*')] }
  manifest=ManifestChain.genesis02(f.fetch('manifest'),ManifestChain::RootPin.enroll(f.fetch('rootPin'),f.fetch('fingerprint')),10000)
  r={manifest:manifest,now_ms:10000,message:'1'.b*16,device:f.fetch('device'),line:f.fetch('line'),observed_ms:10000,expires_ms:20000,peer:'+12',content:'Native composed02 🌱',signer:owner,recipients:manifest.key_records.select { |k| [1,2].include?(k.getbyte(0)) }.map { |k| [k.getbyte(0),k.byteslice(1,32)] }}
  first=Compose02.fresh(**r);second=Compose02.fresh(**r);check(first!=second);emit(first);emit(second)
  emit(Compose02.fresh(**r.merge(message:"\0".b*16,observed_ms:0,expires_ms:1)))
  [{message:''},{device:''},{line:"\0".b*16},{device:"\0".b*16},{now_ms:100000},{now_ms:9999},{observed_ms:-1},{expires_ms:10000},{expires_ms:910001},{peer:'+01'},{content:''},{content:"\ufeffbad"},{content:"bad\0"},{content:"\xed\xa0\x80".b.force_encoding('UTF-8')},{content:'x'*32769},{recipients:r[:recipients].take(1)},{recipients:[r[:recipients][0]]*2},{recipients:[[1,"\0".b*32],r[:recipients][1]]}].each { |change| refuses { Compose02.fresh(**r.merge(change)) } }
  Dir.mktmpdir('zrotext-retry02-') do |dir|
    journal=File.join(dir,'outbound');now=10000;current=-> { [manifest,now] }
    call=->(request=r,source=current) { Compose02.compose_or_replay(journal,f.fetch('rootPin'),f.fetch('fingerprint'),current:source,**request) }
    committed=call.call;emit(committed);check(committed==call.call)
    now=11000;check(committed==call.call);now=10000;refuses { call.call };now=11000
    refuses { call.call(r,nil) };refuses { call.call(r.merge(content:'changed')) };refuses { call.call(r.merge(observed_ms:0)) }
    now=20000;refuses { call.call };now=11000
    retained=ManifestChain.continue_chain(f.fetch('currentRetained'),manifest,2,11000);revoked=ManifestChain.continue_chain(f.fetch('currentRevoked'),manifest,2,11000)
    check(committed==call.call(r,-> { [retained,11000] }));refuses { call.call(r,-> { [revoked,11000] }) }
    fixture=File.join(dir,'fixture.tsv');File.write(fixture,f.merge('expected'=>committed).map { |key,value| key+"\t"+value.unpack1('H*')+"\n" }.join)
    check(system(RbConfig.ruby,__FILE__,'--replay',receipt,fixture,journal))
    stable=File.binread(journal);File.open(journal,'ab') { |file| file.write('x') };refuses { call.call };File.binwrite(journal,stable)
    a=Thread.new { call.call };b=Thread.new { call.call };check(a.value==b.value)
    rotated=ManifestChain.rotate02(f.fetch('transition'),f.fetch('newManifest'),manifest,f.fetch('newPoint'),11000);rotated_request=r.merge(manifest:rotated,now_ms:11000);refuses { call.call(r,-> { [rotated,11000] }) }
    File.delete(journal);rotated_bytes=call.call(rotated_request,-> { [rotated,11000] });check(rotated_bytes==call.call(rotated_request,-> { [rotated,11000] }));puts('ROTATED '+Base64.strict_encode64(rotated_bytes))
    binary_tail=File.binread(journal)+"\x1a".b;File.binwrite(journal,binary_tail);refuses { call.call };check(File.binread(journal)==binary_tail);File.binwrite(journal,binary_tail.byteslice(0,binary_tail.bytesize-1))
    File.delete(journal);calls=0;refuses { call.call(r,-> { calls+=1;raise ArgumentError,'Simulated postcommit authority loss' if calls==6;[manifest,11000] }) };check(calls==6);saved=File.binread(journal);check(call.call==saved.byteslice(270,saved.bytesize-302))
  end
  refuses { owner.sign_envelope03(first.byteslice(0,first.bytesize-64)) };refuses { owner.sign_envelope02("\0".b*493) }
  owner.delete_created;deleted=true;refuses { Compose02.fresh(**r) };File.delete(receipt)
  puts "QUALIFIED: #{$checks} native Ruby profile02 composition checks passed; owned key deleted"
ensure
  if owner
    begin;unless deleted;owner.delete_created;File.delete(receipt);end;ensure;owner.close;end
  end
end

