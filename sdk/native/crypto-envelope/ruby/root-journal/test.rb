# frozen_string_literal: true
require 'tmpdir'
require 'open3'
require 'rbconfig'
require_relative 'root_journal'
require_relative '../sealed_reader02'
include ZrotextCandidate
$checks=0
def check(value) = (raise 'Root assertion' unless value;$checks+=1)
def refuses
  yield
rescue ArgumentError,OpenSSL::OpenSSLError,EOFError
  $checks+=1
else
  raise 'Invalid root history accepted'
end
raw=STDIN.read
f=raw.lines.to_h { |row| k,v=row.strip.split("\t");[k,k=='now_ms' ? Integer(v) : [v].pack('H*')] }
now=f.fetch('now_ms');pin=f.fetch('old_root_pin_b64');fp=f.fetch('old_root_fingerprint_b64');old=f.fetch('old_manifest_b64');transition=f.fetch('transition_b64');point=f.fetch('new_root_point_b64');fresh=f.fetch('new_manifest_b64')
if ARGV.length==1
  snapshot=RootJournal.new(ARGV[0],pin,fp,{2=>point}).snapshot(now);check(snapshot[0]==2 && snapshot[1].generation==2);puts 'restored';exit
end
prior=ManifestChain.genesis02(old,ManifestChain::RootPin.enroll(pin,fp),now)
rotated=ManifestChain.rotate02(transition,fresh,prior,point,now);check(rotated.generation==2 && rotated.version==1 && !rotated.descends_from(prior));check(ManifestChain.continue_chain(fresh,rotated,2,now).digest==rotated.digest)
refuses { ManifestChain.continue_chain(fresh,prior,2,now) };refuses { ManifestChain.genesis02(fresh,ManifestChain::RootPin.enroll(pin,fp),now) };refuses { ManifestChain::RootPin.enroll(f.fetch('new_root_pin_b64'),f.fetch('new_root_fingerprint_b64')) }
[prior.root_point,"\0".b*65].each { |expected| refuses { ManifestChain.rotate02(transition,fresh,prior,expected,now) } }
refuses { ManifestChain.rotate02(transition,fresh,prior,point,now-1) };refuses { ManifestChain.rotate02(transition,old,prior,point,now) }
[transition,fresh].each_with_index do |bytes,kind|
  bytes.bytesize.times do |at|
    changed=bytes.dup;changed.setbyte(at,changed.getbyte(at)^1)
    refuses { ManifestChain.rotate02(kind==0 ? changed : transition,kind==1 ? changed : fresh,prior,point,now) }
  end
end
[215,279].each do |at|
  changed=transition.dup;s=changed.byteslice(at+32,32).unpack1('H*').to_i(16);changed[at+32,32]=[ (ManifestChain::ORDER-s).to_s(16).rjust(64,'0') ].pack('H*');refuses { ManifestChain.rotate02(changed,fresh,prior,point,now) }
end
folder=Dir.mktmpdir('zrotext-root-journal-');path=File.join(folder,'roots.bin');copy=File.join(folder,'copy.bin')
begin
  mutable=point.dup;store=RootJournal.new(path,pin,fp,{2=>mutable});mutable.replace("\0".b*65)
  check(store.accept(old,0,now)[0]==1);before=File.binread(path)
  refuses { store.accept(old,1,now,transition:transition) };check(File.binread(path)==before)
  contenders=2.times.map { Thread.new { begin;store.accept(fresh,1,now,transition:transition);true;rescue ArgumentError;false;end } };check(contenders.map(&:value).sort_by(&:to_s)==[false,true])
  output,error,status=Open3.capture3(RbConfig.ruby,__FILE__,path,stdin_data:raw);raise error unless status.success?;check(output.strip=='restored')
  refuses { RootJournal.new(path,pin,fp,{}).snapshot(now) };refuses { RootJournal.new(path,pin,fp,{2=>prior.root_point}).snapshot(now) }
  check(store.snapshot(now+1)[1].generation==2);refuses { RootJournal.new(path,pin,fp,{2=>point}).snapshot(now) }
  File.binwrite(copy,File.binread(path)+"\1\2\3".b);refuses { RootJournal.new(copy,pin,fp,{2=>point}).snapshot(now+1) }
  damaged=File.binread(path);damaged.setbyte(130,damaged.getbyte(130)^1);File.binwrite(copy,damaged);refuses { RootJournal.new(copy,pin,fp,{2=>point}).snapshot(now+1) }
  File.binwrite(copy,''.b);refuses { RootJournal.new(copy,pin,fp,{2=>point}).snapshot(now+1) }
  dynamic=File.join(folder,'dynamic.bin');d=->(k) { f.fetch('dynamic.'+k) };native=RootJournal.new(dynamic,d.call('rootPin'),d.call('fingerprint'),{2=>d.call('newPoint')})
  old_value=native.accept(d.call('manifest'),0,10000)[1];new_value=native.accept(d.call('newManifest'),1,11000,transition:d.call('transition'))[1];native.accept(d.call('newSuccessor'),2,11000)
  selected=RootJournal.new(dynamic,d.call('rootPin'),d.call('fingerprint'),{2=>d.call('newPoint')}).snapshot(11000)[1]
  archive=new_value.key_records.find { |k| k.getbyte(0)==2 }.byteslice(33,65)
  key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(d.call('archiveScalar')),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(archive)],1,:CONTEXT_SPECIFIC)]).to_der)
  current=->(a,v,h,_w) { a==selected.account && v==selected.version && h==selected.digest }
  check(SealedReader02.open_historical_archive(d.call('newInbound'),new_value,selected,11000,d.call('reader'),key,current)==d.call('text').force_encoding('UTF-8'))
  called=0;refuses { SealedReader02.open_historical_archive(d.call('inbound'),old_value,selected,11000,d.call('reader'),key,->(*) { called+=1;true }) };check(called==0)
  refuses { SealedReader02.open_historical_archive(d.call('newInbound'),new_value,selected,11000,d.call('reader'),key,->(*) { false }) }
  changing=File.join(folder,'changing.bin');live_store=RootJournal.new(changing,d.call('rootPin'),d.call('fingerprint'),{2=>d.call('newPoint')});live_store.accept(d.call('manifest'),0,10000);live_store.accept(d.call('newManifest'),1,11000,transition:d.call('transition'))
  callbacks=0
  live=->(a,v,h,_w) do
    callbacks+=1;live_store.accept(d.call('newSuccessor'),2,11000) if callbacks==2
    actual=live_store.snapshot(11000)[1];a==actual.account && v==actual.version && h==actual.digest
  end
  refuses { SealedReader02.open_historical_archive(d.call('newInbound'),new_value,new_value,11000,d.call('reader'),key,live) };check(callbacks==2)
  File.delete(changing);File.delete(dynamic)
  puts "Ruby root transition/journal: #{$checks} checks passed"
ensure
  [path,copy].each { |file| File.delete(file) if File.exist?(file) };Dir.rmdir(folder)
end
