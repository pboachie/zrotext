# frozen_string_literal: true
require_relative 'original_owner_review'
include ZrotextCandidate
input=JSON.parse($stdin.read);f=input.fetch('Fixture');b=lambda { |name| Base64.strict_decode64(f.fetch(name)) }
root=ManifestChain::RootPin.enroll(b.call('rootPin'),b.call('fingerprint'));prior=ManifestChain.genesis02(b.call('predecessor'),root,10000);active=ManifestChain.continue_chain(b.call('activation'),prior,2,10000)
scope=OriginalReplyReader::Scope.new(b.call('account'),b.call('device'),b.call('line'),b.call('interval'),b.call('connector'),b.call('readGrant'),b.call('originalReader'),'+12')
path=File.join(input.fetch('Directory'),'reply.db')
checkpoint=input.fetch('Resume') ? OriginalReplyCheckpoint.open(path,b.call('rootPin'),b.call('fingerprint'),scope) : OriginalReplyCheckpoint.create(path,b.call('rootPin'),b.call('fingerprint'),scope,[prior,active],10000)
transport=OriginalHTTP.new(origin:input.fetch('Origin'),timeout_ms:1000,additional_roots_pem:input.fetch('Roots'))
client=OriginalCurrentClient.new(transport:transport,checkpoint:checkpoint,pin:b.call('rootPin'),fingerprint:b.call('fingerprint'),scope:scope,now:10000)
file=File.join(input.fetch('Directory'),'intent.bin');result={ok:false,unknown:false}
begin
  unless input.fetch('Resume')
    request="\x00".b*15+[input.fetch('Invalid') ? 0 : 1].pack('C');selected=input.fetch('Active') ? "\x00".b*15+"\x02".b : nil
    intent=client.prepare_owner_review(event:b.call('event'),request:request,active_request:selected)
    raw=intent.bytes;snapshot=intent.bytes;raw.setbyte(0,raw.getbyte(0)^1);raise 'Intent alias' unless intent.bytes==snapshot
    File.open(file,File::WRONLY|File::CREAT|File::EXCL,0600) { |stream| stream.write(snapshot);stream.flush;stream.fsync }
  end
  raw=File.binread(file);corrupt=input.fetch('Corrupt');raw.setbyte(corrupt,raw.getbyte(corrupt)^1) if corrupt>=0;raw=raw.byteslice(0,raw.bytesize-1) if corrupt==-2
  intent=client.restore_owner_review(raw);result[:record]=intent.bytes.unpack1('H*');index=0
  clock=lambda do
    if index.zero?
      begin;client.current(credential:input.fetch('Grant'),clock:-> {10000});raise 'Reentrant current accepted';rescue OriginalHTTP::Failure;end
    end
    time=input.fetch('Clock')[[index,input.fetch('Clock').size-1].min];index+=1;time
  end
  method=input.fetch('Status') ? :status_owner_review : :consume_owner_review
  value=client.public_send(method,credential:input.fetch('Grant'),intent:intent,clock:clock)
  result.merge!(ok:true,event:value.event.unpack1('H*'),consumption:value.consumption.unpack1('H*'),active:value.active_request&.unpack1('H*'),now:value.authority.authority.now_ms)
rescue OriginalHTTP::Failure => error
  result.merge!(unknown:error.unknown,error:error.message)
end
saved=checkpoint.snapshot(scope,50000);result.merge!(revision:saved.revision,floor:saved.comparison_ms);puts JSON.generate(result)
