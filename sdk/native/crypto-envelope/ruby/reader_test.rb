# frozen_string_literal: true
require_relative 'sealed_reader02'
$checks=0
def check(value)
  raise 'Reader assertion' unless value
  $checks+=1
end
def refuses
  begin
    yield
  rescue ArgumentError, OpenSSL::OpenSSLError
    $checks+=1;return
  end
  raise 'Reader accepted invalid input'
end
rows=0
STDIN.each_line do |line|
  f=line.strip.split("\t");now=Integer(f[1]);d=f.drop(2).map { |v| [v].pack('H*') }
  manifest=ZrotextCandidate::ManifestChain.genesis02(d[2],ZrotextCandidate::ManifestChain::RootPin.enroll(d[0],d[1]),now)
  key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([
    OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(d[4]),
    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC),
    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(d[6])],1,:CONTEXT_SPECIFIC)
  ]).to_der)
  reader=ZrotextCandidate::SealedReader02
  current=->(a,v,h,_w) {a==manifest.account && v==manifest.version && h==manifest.digest}
  check(reader.open(d[3],manifest,now,2,d[5],key,current).b==d[7])
  signer=manifest.key_records.find { |r| r.getbyte(0)==4 };check(ZrotextCandidate::SignedEnvelope.verify(d[8],2,signer.byteslice(33,65)).kind==2)
  backdated_calls=0;refuses {reader.open(d[8],manifest,now,2,d[5],key,->(_a,_v,_h,_w) {backdated_calls+=1;true})};check(backdated_calls==0)
  refuses {reader.open(d[3],manifest,now,2,d[5],key,->(_a,_v,_h,_w) {false})}
  calls=0;refuses {reader.open(d[3],manifest,now,2,d[5],key,->(_a,_v,_h,_w) {calls+=1;calls==1})};check(calls==2)
  refuses {reader.open(d[3],manifest,now-1,2,d[5],key,current)}
  refuses {reader.open(d[3],manifest,manifest.expires_ms,2,d[5],key,current)}
  refuses {reader.open(d[3],manifest,now,1,d[5],key,current)}
  [4,10,26,42,58,74,82,114,146,d[3].bytesize-1].each do |at|
    changed=d[3].dup;changed.setbyte(at,changed.getbyte(at)^1);refuses {reader.open(changed,manifest,now,2,d[5],key,current)}
  end
  wrong=d[5].dup;wrong.setbyte(0,wrong.getbyte(0)^1);refuses {reader.open(d[3],manifest,now,2,wrong,key,current)}
  rows+=1
end
check(rows==2)
puts "#{$checks} reader checks passed"
