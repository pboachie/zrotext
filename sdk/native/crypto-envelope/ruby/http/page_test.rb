# frozen_string_literal: true
require_relative 'original_page'
require 'tmpdir'
include ZrotextCandidate
input=JSON.parse($stdin.read); f=input.fetch('Fixture'); b=lambda { |name| Base64.strict_decode64(f.fetch(name)) }
root=ManifestChain::RootPin.enroll(b.call('rootPin'),b.call('fingerprint'))
prior=ManifestChain.genesis02(b.call('predecessor'),root,10000); active=ManifestChain.continue_chain(b.call('activation'),prior,2,10000)
scope=OriginalReplyReader::Scope.new(b.call('account'),b.call('device'),b.call('line'),b.call('interval'),b.call('connector'),b.call('readGrant'),b.call('originalReader'),'+12')
Dir.mktmpdir('zrotext-managed-current-') do |folder|
  path=File.join(folder,'history.dat')
  checkpoint=OriginalReplyCheckpoint.create(path,b.call('rootPin'),b.call('fingerprint'),scope,[prior,active],10000)
  transport=OriginalHTTP.new(origin:input.fetch('Origin'),timeout_ms:4000,additional_roots_pem:input.fetch('Roots'))
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
    time=input.fetch('Clock')[[index,input.fetch('Clock').size-1].min];index+=1;time
  end
  cursor=nil
  if (c=input['Cursor'])
    h=c.fetch('Event').pack('C*').unpack1('H*');cursor=OriginalCurrentClient::PageCursor.new(event_id:[h[0,8],h[8,4],h[12,4],h[16,4],h[20,12]].join('-'),accepted_at_ms:c.fetch('AcceptedAt'))
  end
  result={ok:false}
  begin
    value=client.page(credential:input.fetch('Grant'),cursor:cursor,limit:input.fetch('Limit'),clock:clock)
    events=value.events.map { |r| {event:r['event_id'].delete('-'),at:r['accepted_at_ms'],observed:r['observed_at_ms'],historical:r['historical_manifest_version'],activation:r['activation_manifest_version'],disposition:r['disposition'],requests:r['active_request_ids'].map { |id| id.delete('-') }} }
    next_cursor=value.next_cursor && {event:value.next_cursor.event_id.delete('-'),at:value.next_cursor.accepted_at_ms}
    result.merge!(ok:true,events:events,next:next_cursor,now:value.authority.authority.now_ms,version:value.authority.authority.manifest.version)
  rescue OriginalHTTP::Failure
    # Only operation under test may refuse.
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
