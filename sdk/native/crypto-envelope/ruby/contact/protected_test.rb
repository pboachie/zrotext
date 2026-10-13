# frozen_string_literal: true
# Test-only synthetic root enrollment: private signing is used only to construct
# genuine evidence for independent maintained verification, never exported API.
require 'json'
require 'base64'
require_relative 'protected_contact_signer'
include ZrotextCandidate
f=JSON.parse(STDIN.read);parser=ContactOrigin.new(ARGV.fetch(0));receipt=ARGV.fetch(1)
d=->(key){Base64.strict_decode64(f.fetch(key))};b64=->(bytes){Base64.strict_encode64(bytes)}
write=->(value){File.open(receipt,'w'){|file|file.write(JSON.generate(value));file.flush;file.fsync}}
key=nil;borrowed=nil;controls=0;alias_name=nil;point=nil
begin
  key=ProtectedContactSigner.create{|created_alias|alias_name=created_alias;write.call({alias:created_alias,state:'pending'})}
  point=key.public_point;alias_name=key.alias_name
  setup=->(label,unsigned){unsigned+key.send(:sign_digest,OpenSSL::Digest::SHA256.digest(ContactField.domain(label)+[unsigned.bytesize].pack('N')+unsigned))}
  root_id=ContactField.sha(ContactField.domain('ZTSE/key/v1')+"\x01\x01".b+point)
  pin="ZTRP\x02".b+d.call('account')+[1].pack('Q>')+point
  f['rootPin']=b64.call(pin);f['fingerprint']=b64.call(ContactField.sha(ContactField.domain('ZTSE/root-pin/v2')+pin))
  m=d.call('manifest').byteslice(0,d.call('manifest').bytesize-64);m[85,65]=point
  m.getbyte(150).times{|i|at=151+i*149;if m.getbyte(at)==6 then m[at+1,32]=root_id;m[at+33,65]=point end}
  f['manifest']=b64.call(setup.call('ZTSE/manifest/v2',m));next_m=m.dup;next_m[29,8]=[2].pack('Q>');next_m[53,32]=ContactField.sha(m)
  f['nextManifest']=b64.call(setup.call('ZTSE/manifest/v2',next_m))
  %w[statement nextStatement].each do |name|
    raw=d.call(name);unsigned=raw.byteslice(0,raw.bytesize-64);at=40+unsigned.byteslice(38,2).unpack1('n')+24
    unsigned[at,32]=d.call('fingerprint');unsigned[at+32,32]=ContactField.sha(name=='statement' ? m : next_m)
    f[name]=b64.call(setup.call('ZT/contact-reader/authorization/v1',unsigned))
  end
  trust=ManifestChain::RootPin.enroll(d.call('rootPin'),d.call('fingerprint'));first=ManifestChain.genesis02(d.call('manifest'),trust,10000)
  second=ManifestChain.continue_chain(d.call('nextManifest'),first,2,10000)
  expected=ContactField::Expected.new(account:d.call('account'),origin:f['origin'],root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
  prepared=[];outputs=[]
  %w[name notes replacement].each do |name|
    which=name=='replacement' ? 'nextStatement' : 'statement';manifest=name=='replacement' ? second : first
    statement=ContactField.verify_statement(d.call(which),manifest,account:d.call('account'),origin:f['origin'],root_fingerprint:d.call('fingerprint'),parser:parser)
    raw=d.call(name);unsigned=raw.byteslice(0,raw.bytesize-64);unsigned[102,32]=manifest.digest;unsigned[134,32]=statement.digest;unsigned[214,32]=root_id
    prepared<<[statement,unsigned];value=ContactField.produce_protected(key,statement,expected,unsigned)
    outputs<<{statement:which,bytes:b64.call(value.bytes)};controls+=1
  end
  borrowed=ProtectedContactSigner.open(alias_name,point);statement,unsigned=prepared.first
  ContactField.produce_protected(borrowed,statement,expected,unsigned);controls+=1
  borrowed.close
  begin ContactField.produce_protected(borrowed,statement,expected,unsigned);raise 'closed signer accepted';rescue ArgumentError;controls+=1 end
  signatures=0;original_sign=key.method(:sign_digest)
  key.define_singleton_method(:sign_digest){|digest|signatures+=1;original_sign.call(digest)}
  cancelled=Array.new(4){ContactField::Cancellation.new};refused=Array.new(4,false)
  key.instance_variable_get(:@lock).synchronize do
    callers=4.times.map do |i|
      Thread.new do
        begin ContactField.produce_protected(key,statement,expected,unsigned,cancelled:cancelled[i])
        rescue ArgumentError;refused[i]=true end
      end
    end
    admitted=Process.clock_gettime(Process::CLOCK_MONOTONIC)+2
    sleep(0.01) until ContactField.instance_variable_get(:@admission).synchronize{ContactField.instance_variable_get(:@outstanding)==4} || Process.clock_gettime(Process::CLOCK_MONOTONIC)>admitted
    raise 'four workers not admitted' unless ContactField.instance_variable_get(:@outstanding)==4
    sleep(0.2);cancelled.each(&:cancel)
    callers.each_with_index{|caller,i|raise 'provider wait defeated cancellation' unless caller.join(1) && refused[i]}
    raise 'unsettled workers released admission' unless ContactField.instance_variable_get(:@outstanding)==4
    begin ContactField.produce_protected(key,statement,expected,unsigned);raise 'fifth worker admitted';rescue ArgumentError;controls+=1 end
  end
  finish=Process.clock_gettime(Process::CLOCK_MONOTONIC)+2
  sleep(0.01) until ContactField.instance_variable_get(:@admission).synchronize{ContactField.instance_variable_get(:@outstanding)==0} || Process.clock_gettime(Process::CLOCK_MONOTONIC)>finish
  raise 'worker admission leaked' unless ContactField.instance_variable_get(:@outstanding)==0
  raise 'cancelled provider signed late' unless signatures==0
  controls+=1
  timed_out=false;began=Process.clock_gettime(Process::CLOCK_MONOTONIC)
  key.instance_variable_get(:@lock).synchronize do
    caller_thread=Thread.new do
      begin ContactField.produce_protected(key,statement,expected,unsigned)
      rescue ArgumentError;timed_out=true end
    end
    joined=caller_thread.join(12);elapsed=Process.clock_gettime(Process::CLOCK_MONOTONIC)-began
    raise 'provider deadline/retained admission failed' unless joined && timed_out && elapsed>=9.5 && elapsed<=12 && ContactField.instance_variable_get(:@outstanding)==1
  end
  finish=Process.clock_gettime(Process::CLOCK_MONOTONIC)+2
  sleep(0.01) until ContactField.instance_variable_get(:@admission).synchronize{ContactField.instance_variable_get(:@outstanding)==0} || Process.clock_gettime(Process::CLOCK_MONOTONIC)>finish
  raise 'timed out worker did not settle' unless ContactField.instance_variable_get(:@outstanding)==0
  raise 'expired provider signed late' unless signatures==0
  controls+=1
  puts JSON.generate({fixture:f,outputs:outputs,controls:controls})
ensure
  borrowed&.close
  if key
    key.delete_created
    if point
      begin ProtectedContactSigner.open(alias_name,point);raise 'deleted signer reopened';rescue ArgumentError;end
    end
    write.call({alias:alias_name,state:'owned_key_deleted'})
  end
end
