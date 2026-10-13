# frozen_string_literal: true
require 'json'
require 'base64'
require 'open3'
require 'tmpdir'
require 'rbconfig'
require_relative 'compose03'
include ZrotextCandidate

def check(value)
  raise 'Composition assertion' unless value
  $checks+=1
end
def refuses
  yield
rescue ArgumentError,OpenSSL::OpenSSLError,EncodingError
  $checks+=1
else
  raise 'Invalid composition accepted'
end
def bytes(f,name) = Base64.strict_decode64(f.fetch(name))
def record(value) = value.transform_values { |v| v.is_a?(String) ? Base64.strict_decode64(v) : v }
def inputs(f,signer)
  prior=ManifestChain.genesis02(bytes(f,'signed02'),ManifestChain::RootPin.enroll(bytes(f,'rootPin'),bytes(f,'fingerprint')),10000)
  proof=Election03.verify(bytes(f,'bundle'),bytes(f,'core'),record(f.fetch('accepted')),prior,bytes(f,'signed02'),bytes(f,'signed03'),bytes(f,'deviceSigningPoint'),bytes(f,'ownerApprovalPoint'))
  {manifest:proof.accepted_manifest,proof:proof,authority:-> { [record(f.fetch('authority')),30000] },message:bytes(f,'message'),observed_ms:30000,expires_ms:40000,peer:'+12',content:'Native composed 🌱',signer:signer,recipients:proof.accepted_manifest.key_records.select { |k| [1,2].include?(k.getbyte(0)) }.map { |k| [k.getbyte(0),k.byteslice(1,32)] }}
end
def node(directory,script,input=nil,*args)
  out,err,status=Open3.capture3({'NODE_OPTIONS'=>nil,'NODE_PATH'=>nil},'node',File.join(directory,script),*args,stdin_data:input.to_s)
  raise "Independent producer/consumer failed: #{err}" unless status.success?
  JSON.parse(out)
end
def consume(directory,fixture,envelope)
  check(node(directory,'consume-native03.mjs',JSON.generate(fixture:fixture,envelope:Base64.strict_encode64(envelope),expectedText:'Native composed 🌱'))=={'verified'=>true,'openedRecipients'=>2})
end

if [5,6].include?(ARGV.length) && ARGV[0]=='--replay'
  f=JSON.parse(File.read(ARGV[1]));signer=ProtectedSigner.open(ARGV[3],[ARGV[4]].pack('H*'))
  begin
    request=inputs(f,signer)
    request=request.merge(authority:-> { [record(f.fetch('authority')),Integer(ARGV[5])] }) if ARGV.length==6
    puts Base64.strict_encode64(Compose03.compose_or_replay(ARGV[2],bytes(f,'rootPin'),bytes(f,'fingerprint'),**request))
  ensure
    signer.close
  end
  exit
end
raise ArgumentError,'Producer directory and new pending receipt required' unless ARGV.length==2
begin
  ProtectedSigner.probe
rescue ArgumentError,Fiddle::DLError
  puts 'UNQUALIFIED: signing capability unavailable before creation'
  exit
end
$checks=0
receipt=File.expand_path(ARGV[1]);folder=Dir.mktmpdir('zrotext-ruby-compose-');owner=nil;deleted=false
begin
  owner=ProtectedSigner.create { |alias_name| File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0o600) { |f| f.write(alias_name+"\n");f.flush;f.fsync } }
  point=owner.public_point;check(point.bytesize==65)
  reopened=ProtectedSigner.open(owner.alias_name,point)
  begin
    check(reopened.public_point==point);refuses { reopened.delete_created }
  ensure
    reopened.close
  end
  wrong=OpenSSL::PKey::EC.generate('prime256v1').public_key.to_octet_string(:uncompressed)
  refuses { ProtectedSigner.open(owner.alias_name,wrong).close }
  refuses { owner.sign_envelope03("\x00".b*493) }
  refuses { owner.call(point,point,''.b,''.b,''.b) }
  fixture=node(ARGV[0],'produce-election03.mjs',nil,'--signer-point',point.unpack1('H*'))
  request=inputs(fixture,owner);pin=bytes(fixture,'rootPin');fp=bytes(fixture,'fingerprint')
  # A valid empty journal whose checksum ends in DOS EOF must survive its first
  # RDWR open. The CRT can truncate that byte before a later binmode call.
  binary_journal=File.join(folder,'binary-end.bin');header='ZTJ4'.b+pin+fp
  comparison=(30000...40000).find { |n| OpenSSL::Digest::SHA256.digest(header+[n].pack('Q>')).getbyte(-1)==26 }
  check(!comparison.nil?);clock=[comparison].pack('Q>');before=header+clock+OpenSSL::Digest::SHA256.digest(header+clock)
  File.binwrite(binary_journal,before);binary_request=request.merge(authority:-> { [record(fixture.fetch('authority')),comparison] })
  binary_envelope=Compose03.compose_or_replay(binary_journal,pin,fp,**binary_request)
  stable_binary=File.binread(binary_journal);check(stable_binary.start_with?(before));consume(ARGV[0],fixture,binary_envelope)
  check(Compose03.compose_or_replay(binary_journal,pin,fp,**binary_request)==binary_envelope);check(File.binread(binary_journal)==stable_binary)
  File.delete(binary_journal)
  a=Compose03.fresh(**request);b=Compose03.fresh(**request);check(a!=b);consume(ARGV[0],fixture,a);consume(ARGV[0],fixture,b)
  ['',"\ufeffbad","bad\0","\xed\xa0\x80".b.force_encoding('UTF-8'),'x'*32769].each { |text| refuses { Compose03.fresh(**request.merge(content:text)) } }
  [{message:"\0".b*16},{observed_ms:8000},{observed_ms:30001},{expires_ms:60001},{peer:'+01'},{recipients:request[:recipients].take(1)},{recipients:request[:recipients]*2}].each { |change| refuses { Compose03.fresh(**request.merge(change)) } }
  revoked=record(fixture.fetch('authority')).merge('bindingGeneration'=>99)
  refuses { Compose03.fresh(**request.merge(authority:-> { [revoked,30000] })) }
  reads=0;refuses { Compose03.fresh(**request.merge(authority:-> { reads+=1;[record(fixture.fetch('authority')),reads==1 ? 30000 : 40000] })) };check(reads==2)
  journal=File.join(folder,'outbound.bin');committed=Compose03.compose_or_replay(journal,pin,fp,**request)
  check(committed==Compose03.compose_or_replay(journal,pin,fp,**request));consume(ARGV[0],fixture,committed)
  refuses { Compose03.compose_or_replay(journal,pin,fp,**request.merge(content:'different')) }
  refuses { Compose03.compose_or_replay(journal,pin,fp,**request.merge(authority:-> { [revoked,30000] })) }
  fixture_path=File.join(folder,'fixture.json');File.write(fixture_path,JSON.generate(fixture))
  output,error,status=Open3.capture3(RbConfig.ruby,__FILE__,'--replay',fixture_path,journal,owner.alias_name,point.unpack1('H*'))
  raise "Replay process failed: #{error}" unless status.success?
  check(Base64.strict_decode64(output.strip)==committed)
  concurrent=request.merge(message:SecureRandom.random_bytes(16));threads=2.times.map { Thread.new { Compose03.compose_or_replay(journal,pin,fp,**concurrent) } };check(threads.map(&:value).uniq.length==1)
  after_reads=0;interrupted=request.merge(message:SecureRandom.random_bytes(16))
  refuses { Compose03.compose_or_replay(journal,pin,fp,**interrupted.merge(authority:-> { after_reads+=1;[after_reads==4 ? revoked : record(fixture.fetch('authority')),30000] })) };check(after_reads==4)
  length=File.size(journal);Compose03.compose_or_replay(journal,pin,fp,**interrupted);check(File.size(journal)==length)
  partial=File.join(folder,'partial.bin');File.binwrite(partial,File.binread(journal)+"\x01\x02\x03".b);refuses { Compose03.compose_or_replay(partial,pin,fp,**request) }
  check(Compose03.compose_or_replay(journal,pin,fp,**request.merge(authority:-> { [record(fixture.fetch('authority')),31000] }))==committed)
  output,error,status=Open3.capture3(RbConfig.ruby,__FILE__,'--replay',fixture_path,journal,owner.alias_name,point.unpack1('H*'),'30000')
  check(!status.success? && error.include?('Candidate composition refused') && output.empty?)
  check(Compose03.compose_or_replay(journal,pin,fp,**request.merge(authority:-> { [record(fixture.fetch('authority')),31000] }))==committed)
  # Persist the later postcommit comparison too, not only the entry comparison.
  later_reads=0;later=request.merge(message:SecureRandom.random_bytes(16),authority:-> { later_reads+=1;[record(fixture.fetch('authority')),later_reads==4 ? 32000 : 31000] })
  Compose03.compose_or_replay(journal,pin,fp,**later);check(later_reads==4)
  refuses { Compose03.compose_or_replay(journal,pin,fp,**request.merge(authority:-> { [record(fixture.fetch('authority')),31000] })) }
  torn=File.binread(journal);torn.setbyte(130,torn.getbyte(130)^1);File.binwrite(partial,torn)
  refuses { Compose03.compose_or_replay(partial,pin,fp,**request.merge(authority:-> { [record(fixture.fetch('authority')),32000] })) }
  alias_name=owner.alias_name;owner.delete_created;deleted=true
  refuses { owner.sign_envelope03(a.byteslice(0,a.bytesize-64)) };refuses { ProtectedSigner.open(alias_name,point).close }
  File.delete(receipt);[journal,fixture_path,partial].each { |path| File.delete(path) };Dir.rmdir(folder)
  puts "QUALIFIED: #{$checks} native Ruby composition/replay checks passed; owned key deleted"
ensure
  if owner
    begin
      unless deleted
        owner.delete_created;File.delete(receipt)
      end
    ensure
      owner.close
    end
  end
end
