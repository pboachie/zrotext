# frozen_string_literal: true
require_relative 'election03'
$checks=0
def check(value)
  raise 'Election assertion' unless value
  $checks+=1
end
def refuses
  begin
    yield
  rescue ArgumentError, OpenSSL::OpenSSLError
    $checks+=1;return
  end
  raise 'Invalid election accepted'
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
chain=ZrotextCandidate::ManifestChain;election=ZrotextCandidate::Election03
pin=chain::RootPin.enroll(wire['rootPin'],wire['fingerprint']);prior=chain.genesis02(wire['signed02'],pin,10000)
verify=->(bundle,record) {election.verify(bundle,wire['core'],record,prior,wire['signed02'],wire['signed03'],wire['deviceSigningPoint'],wire['ownerApprovalPoint'])}
proof=verify.call(wire['bundle'],accepted);current=election.require_current(proof,proof.accepted_manifest,authority,30000)
check(current.number('manifestVersion')==2);check(current.field('accountId')==prior.account)
exposed=current.field('accountId');exposed.setbyte(0,exposed.getbyte(0)^1);check(current.field('accountId')==prior.account)
authority.each do |name,value|
  changed=authority.dup
  if value.is_a?(String)
    bytes=value.dup;bytes.setbyte(0,bytes.getbyte(0)^1);changed[name]=bytes
  else
    changed[name]=0
  end
  refuses {election.require_current(proof,proof.accepted_manifest,changed,30000)}
end
refuses {election.require_current(proof,prior,authority,30000)}
refuses {election.require_current(proof,proof.accepted_manifest,authority,0)}
refuses {election.require_current(proof,proof.accepted_manifest,authority,60000)}
[0,56,72,88,136,184,256,288,320,352,384,400,432,464,496,500,564,627].each do |at|
  changed=wire['bundle'].dup;changed.setbyte(at,changed.getbyte(at)^1);refuses {verify.call(changed,accepted)}
end
accepted.each do |name,value|
  next if name=='newBindingId'
  changed=accepted.dup
  if value.is_a?(String)
    bytes=value.dup;bytes.setbyte(0,bytes.getbyte(0)^1);changed[name]=bytes
  else
    changed[name]=0
  end
  refuses {verify.call(wire['bundle'],changed)}
end
[500,564].each do |at|
  changed=wire['bundle'].dup;changed.setbyte(at,changed.getbyte(at)^1);rebound=accepted.dup;rebound['electionBundleSha256']=OpenSSL::Digest::SHA256.digest(changed)
  refuses {verify.call(changed,rebound)}
end
accepted['accountId'].setbyte(0,accepted['accountId'].getbyte(0)^1)
check(election.require_current(proof,proof.accepted_manifest,authority,30000).field('accountId')==prior.account)
puts "#{$checks} election checks passed"
