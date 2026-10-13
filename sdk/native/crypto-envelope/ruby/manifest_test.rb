# frozen_string_literal: true
require_relative 'manifest_chain'
Chain=ZrotextCandidate::ManifestChain
$checks=0
def check(value)
  raise 'Manifest assertion' unless value
  $checks+=1
end
def refuses
  begin
    yield
  rescue ArgumentError, OpenSSL::PKey::PKeyError
    $checks+=1;return
  end
  raise 'Accepted invalid provenance'
end
def hex(value) = [value].pack('H*')
rows=0
STDIN.each_line do |line|
  f=line.strip.split("\t");now=Integer(f[1]);pin=hex(f[2]);fingerprint=hex(f[3]);manifest=hex(f[4])
  root=Chain::RootPin.enroll(pin,fingerprint);original=Chain.genesis02(manifest,root,now)
  check(original.digest==hex(f[5]));check(original.profile==2 && original.version==1)
  check(Chain.continue_chain(manifest,original,2,now).digest==original.digest)
  exposed=original.bytes;exposed.setbyte(0,0);check(original.bytes.getbyte(0)==90)
  wrong=fingerprint.dup;wrong.setbyte(0,wrong.getbyte(0)^1);refuses {Chain::RootPin.enroll(pin,wrong)}
  refuses {Chain.genesis02(manifest,root,original.expires_ms)}
  refuses {Chain.genesis02(manifest,root,0)}
  refuses {Chain.continue_chain(manifest,original,2,now-1)}
  [0,21,29,53,85,150,151,manifest.bytesize-1].each do |at|
    altered=manifest.dup;altered.setbyte(at,altered.getbyte(at)^1);refuses {Chain.genesis02(altered,root,now)}
  end
  refuses {Chain.genesis02(manifest.byteslice(0,manifest.bytesize-1),root,now)}
  if f.size==10
    first=hex(f[6]);following=hex(f[7]);alternate=hex(f[8]);later=Integer(f[9])
    p3=Chain.continue_chain(first,original,3,now);check(p3.profile==3 && p3.version==2)
    successor=Chain.continue_chain(following,p3,3,later);check(successor.version==3)
    check(Chain.continue_chain(alternate,p3,3,later).digest==p3.digest)
    refuses {Chain.continue_chain(following,original,3,now)};refuses {Chain.continue_chain(manifest,p3,2,now)}
    refuses {Chain.continue_chain(first,original,3,original.expires_ms)};refuses {Chain.continue_chain(first,successor,3,later)}
  end
  rows+=1
end
check(rows==2)
puts "#{$checks} manifest checks passed"
