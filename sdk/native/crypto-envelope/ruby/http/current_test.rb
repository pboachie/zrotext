# frozen_string_literal: true
require_relative 'original_current'
require 'tmpdir'
include ZrotextCandidate
input=JSON.parse($stdin.read); f=input.fetch('Fixture'); b=lambda { |name| Base64.strict_decode64(f.fetch(name)) }
root=ManifestChain::RootPin.enroll(b.call('rootPin'),b.call('fingerprint'))
prior=ManifestChain.genesis02(b.call('predecessor'),root,10000); active=ManifestChain.continue_chain(b.call('activation'),prior,2,10000)
scope=OriginalReplyReader::Scope.new(b.call('account'),b.call('device'),b.call('line'),b.call('interval'),b.call('connector'),b.call('readGrant'),b.call('originalReader'),'+12')
Dir.mktmpdir('zrotext-managed-current-') do |folder|
  path=File.join(folder,'history.dat')
  checkpoint=OriginalReplyCheckpoint.create(path,b.call('rootPin'),b.call('fingerprint'),scope,[prior,active],10000)
  transport=OriginalHTTP.new(origin:input.fetch('Origin'),timeout_ms:1000,additional_roots_pem:input.fetch('Roots'))
  client=OriginalCurrentClient.new(transport:transport,checkpoint:checkpoint,pin:b.call('rootPin'),fingerprint:b.call('fingerprint'),scope:scope,now:10000)
  index=0
  clock=lambda do
    if index.zero?
      begin
        client.current(credential:input.fetch('Grant'),clock:-> {10000});raise 'Reentrant current accepted'
      rescue OriginalHTTP::Failure
        # Must fail before any additional HTTP request.
      end
    end
    if input.fetch('Conflict') && index==2
      other=OriginalReplyCheckpoint.open(path,b.call('rootPin'),b.call('fingerprint'),scope)
      old=other.snapshot(scope,10000);other.accept(scope,old.history,old.revision,10000) { |_m,n| n }
    end
    time=input.fetch('Clock')[[index,input.fetch('Clock').size-1].min];index+=1;time
  end
  result={ok:false}
  begin
    value=client.current(credential:input.fetch('Grant'),clock:clock).authority
    result.merge!(ok:true,now:value.now_ms,version:value.manifest.version)
  rescue OriginalHTTP::Failure
    # Only the operation under test may refuse; fixture setup above must pass.
  end
  if input.fetch('Retry')
    begin
      client.current(credential:input.fetch('Grant'),clock:-> {10000});result[:stale_refused]=false
    rescue OriginalHTTP::Failure
      result[:stale_refused]=true
    end
  end
  reopened=OriginalReplyCheckpoint.open(path,b.call('rootPin'),b.call('fingerprint'),scope)
  saved=reopened.snapshot(scope,50000)
  result.merge!(revision:saved.revision,floor:saved.comparison_ms,history:saved.history.size,rollback_refused:false)
  begin
    reopened.snapshot(scope,saved.comparison_ms-1)
  rescue ArgumentError
    result[:rollback_refused]=true
  end
  puts JSON.generate(result)
end
