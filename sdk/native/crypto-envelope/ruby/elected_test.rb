# frozen_string_literal: true
require_relative 'elected_reader03'
$checks=0
def check(value)
  raise 'Elected assertion' unless value
  $checks+=1
end
def refuses
  begin
    yield
  rescue ArgumentError, OpenSSL::OpenSSLError
    $checks+=1;return
  end
  raise 'Invalid elected envelope accepted'
end
wire={};accepted={};authority={}
STDIN.each_line do |line|
  f=line.strip.split("\t");value=f[1]=='b' ? [f[2]].pack('H*') : Integer(f[2])
  if f[0].start_with?('accepted.')
    accepted[f[0].delete_prefix('accepted.')]=value
  elsif f[0].start_with?('authority.')
    authority[f[0].delete_prefix('authority.')]=value
  else
    wire[f[0]]=value
  end
end
chain=ZrotextCandidate::ManifestChain;election=ZrotextCandidate::Election03;reader=ZrotextCandidate::ElectedReader03
prior=chain.genesis02(wire['signed02'],chain::RootPin.enroll(wire['rootPin'],wire['fingerprint']),10000)
proof=election.verify(wire['bundle'],wire['core'],accepted,prior,wire['signed02'],wire['signed03'],wire['deviceSigningPoint'],wire['ownerApprovalPoint']);manifest=proof.accepted_manifest
key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([
  OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(wire['readerScalar']),
  OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC),
  OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(wire['readerPoint'])],1,:CONTEXT_SPECIFIC)
]).to_der)
source=-> {[authority,30000]}
check(reader.open_software(wire['envelope'],manifest,proof,source,wire['message'],'+12',key).b==wire['text'])
refuses {reader.open_software(wire['envelope'],manifest,proof,source,wire['message'],'+13',key)}
refuses {reader.open_software(wire['envelope'],manifest,proof,source,"\x00".b*16,'+12',key)}
calls=0;expires=-> {calls+=1;[authority,calls==1 ? 30000 : 40000]}
refuses {reader.open_software(wire['envelope'],manifest,proof,expires,wire['message'],'+12',key)};check(calls==2)
revoked=authority.merge('selectedReaderKeyId'=>"\x00".b*32);count=0;revoke=-> {count+=1;[count==1 ? authority : revoked,30000]}
refuses {reader.open_software(wire['envelope'],manifest,proof,revoke,wire['message'],'+12',key)};check(count==2)
refuses {reader.open_software(wire['envelope'],manifest,proof,-> {[revoked,30000]},wire['message'],'+12',nil)}
[4,5,10,26,42,58,74,82,114,146,154,164,wire['envelope'].bytesize-1].each do |at|
  changed=wire['envelope'].dup;changed.setbyte(at,changed.getbyte(at)^1);refuses {reader.open_software(changed,manifest,proof,source,wire['message'],'+12',key)}
end
puts "#{$checks} elected reader checks passed"
