# frozen_string_literal: true
require 'tmpdir'
require 'open3'
require_relative 'election_journal'
require_relative '../elected_reader03'
include ZrotextCandidate
$checks=0
def check(value) = (raise 'Election journal assertion' unless value;$checks+=1)
def refuses
  yield
rescue ArgumentError,OpenSSL::OpenSSLError,IOError
  $checks+=1
else
  raise 'Election journal should refuse'
end
raw_input=STDIN.read;wire={};accepted={};authority={}
raw_input.each_line do |line|
  f=line.strip.split("\t");value=f[1]=='b' ? [f[2]].pack('H*') : Integer(f[2])
  if f[0].start_with?('accepted.');accepted[f[0].delete_prefix('accepted.')]=value
  elsif f[0].start_with?('authority.');authority[f[0].delete_prefix('authority.')]=value
  else;wire[f[0]]=value;end
end
external_core=wire['core'].dup;expected=ElectionJournal::Expectations.new(external_core,accepted,wire['deviceSigningPoint'],wire['ownerApprovalPoint']);external_core.setbyte(0,external_core.getbyte(0)^1)
if ARGV.length==1
  restored=ElectionJournal.new(ARGV[0],wire['rootPin'],wire['fingerprint'],expected).snapshot(30000);check(restored[0]==2 && restored[2]);exit
end
Dir.mktmpdir('zrotext-election-') do |dir|
  path=File.join(dir,'journal');journal=ElectionJournal.new(path,wire['rootPin'],wire['fingerprint'],expected)
  check(journal.accept(wire['signed02'],0,10000)[0]==1);refuses { journal.accept(wire['signed03'],1,10000) }
  628.times { |at| changed=wire['bundle'].dup;changed.setbyte(at,changed.getbyte(at)^1);refuses { journal.accept(wire['signed03'],1,accepted['acceptedAtMs'],bundle:changed) } }
  check(journal.snapshot(10000)[0]==1);selected=journal.accept(wire['signed03'],1,accepted['acceptedAtMs'],bundle:wire['bundle']);check(selected[0]==2 && selected[2])
  restored=ElectionJournal.new(path,wire['rootPin'],wire['fingerprint'],expected).snapshot(30000);check(restored[1].version==2)
  refuses { ElectionJournal.new(path,wire['rootPin'],wire['fingerprint'],nil).snapshot(30000) }
  wrong=accepted.dup;binding=wrong['newBindingId'].dup;binding.setbyte(0,binding.getbyte(0)^1);wrong['newBindingId']=binding
  changed=ElectionJournal::Expectations.new(wire['core'],wrong,wire['deviceSigningPoint'],wire['ownerApprovalPoint']);refuses { ElectionJournal.new(path,wire['rootPin'],wire['fingerprint'],changed).snapshot(30000) }
  _,status=Open3.capture2(RbConfig.ruby,__FILE__,path,stdin_data:raw_input);check(status.success?)
  key=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(wire['readerScalar']),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC),OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(wire['readerPoint'])],1,:CONTEXT_SPECIFIC)]).to_der)
  check(ElectedReader03.open_software(wire['envelope'],restored[1],restored[2],-> { [authority,30000] },wire['message'],'+12',key).b==wire['text'])
  original=File.binread(path);binary_tail=original+"\x1a".b;File.binwrite(path,binary_tail);refuses { journal.snapshot(30000) };check(File.binread(path)==binary_tail);File.binwrite(path,original)
  refuses { journal.snapshot(29999) };stable=File.binread(path);File.open(path,'ab') { |file| file.write('x') };refuses { journal.snapshot(30000) };File.binwrite(path,stable);torn=stable.dup;torn.setbyte(130,torn.getbyte(130)^1);File.binwrite(path,torn);refuses { journal.snapshot(30000) };File.binwrite(path,'');refuses { journal.snapshot(30000) };File.binwrite(path,stable)
  refuses { journal.accept(wire['successor'],1,30000) }
  tasks=2.times.map { Thread.new { begin;journal.accept(wire['successor'],2,30000);true;rescue ArgumentError;false;end } };check(tasks.count { |t| t.value }==1)
  check(journal.snapshot(30000)[1].version==3);refuses { journal.accept(wire['signed02'],3,30000) };refuses { journal.accept(wire['signed03'],3,30000,bundle:wire['bundle']) }
  journal.snapshot(30001);refuses { ElectionJournal.new(path,wire['rootPin'],wire['fingerprint'],expected).snapshot(30000) }
  live=ElectionJournal.new(File.join(dir,'lifecycle'),wire['rootPin'],wire['fingerprint'],expected);live.accept(wire['signed02'],0,10000);active=live.accept(wire['signed03'],1,accepted['acceptedAtMs'],bundle:wire['bundle']);calls=0
  current=-> { now=live.snapshot(30000);raise ArgumentError,'Selection changed' unless now[1].digest==active[1].digest;calls+=1;live.accept(wire['successor'],2,30000) if calls==1;[authority,30000] }
  refuses { ElectedReader03.open_software(wire['envelope'],active[1],active[2],current,wire['message'],'+12',key) };check(calls==1 && live.snapshot(30000)[0]==3)
end
puts "#{$checks} Ruby durable election checks passed"
