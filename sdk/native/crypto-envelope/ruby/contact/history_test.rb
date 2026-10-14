# frozen_string_literal: true
require_relative 'contact_local_history'
# Restart, CAS, replay, fork, terminal and reduction controls over real signed history.
$checks=0
module ZrotextCandidate
  def self.refuse
    yield
    raise AssertionError,'Expected history refusal'
  rescue ZrotextCandidate::ContactLocalHistory::Refused, IOError, ArgumentError
    $checks+=1
  end
  class AssertionError<StandardError;end
end
include ZrotextCandidate
asset,path,origin,mode=ARGV[0],ARGV[1],ARGV[2],ARGV[3]
f={}
$stdin.each_line{|line|key,value=line.chomp.split("\t",2);f[key]=[value].pack('H*')}
parser=ContactOrigin.new(asset)
pin=f['rootPin'];fingerprint=f['fingerprint'];account=f['account'];contact=f['contact'];routing=f['routing']
first=ManifestChain.genesis02(f['manifest'],ManifestChain::RootPin.enroll(pin,fingerprint),10000)
second=ManifestChain.continue_chain(f['nextManifest'],first,2,10000)
s1=ContactField.verify_statement(f['statement'],first,account:account,origin:origin,root_fingerprint:fingerprint,parser:parser)
s2=ContactField.verify_statement(f['nextStatement'],second,account:account,origin:origin,root_fingerprint:fingerprint,parser:parser)
expected=ContactField::Expected.new(account:account,origin:origin,root_fingerprint:fingerprint,contact:contact,routing:routing,parser:parser)
name=ContactField.verify(f['name'],s1,contact:contact,routing:routing)
notes=ContactField.verify(f['notes'],s1,contact:contact,routing:routing)
replacement=ContactField.verify(f['replacement'],s2,contact:contact,routing:routing)
create=ContactMutation.transition(nil,ContactMutation.verify(f['create'],s1,expected),[name,notes])
update=ContactMutation.transition(create,ContactMutation.verify(f['update'],s2,expected),[replacement])
clear=ContactMutation.transition(update,ContactMutation.verify(f['clear'],s2,expected),[])
scalar="\x00".b*31+"\x07".b
fork_key=OpenSSL::PKey::EC.new(OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ObjectId.new('prime256v1',0,:EXPLICIT),OpenSSL::ASN1::BitString.new(first.root_point,1,:EXPLICIT)]).to_der)
fork_unsigned=f['update'].byteslice(0,304).dup
fork_unsigned[54,16]="\x42".b*16
fork_field_unsigned=f['replacement'].byteslice(0,f['replacement'].bytesize-64).dup
fork_field_unsigned[198,16]="\x42".b*16
fork_field=ContactField.verify(ContactField.produce_software(fork_key,s2,expected,fork_field_unsigned).bytes,s2,contact:contact,routing:routing)
fork_unsigned[272,32]=fork_field.digest
fork=ContactMutation.produce_software(fork_key,s2,expected,fork_unsigned,legacy:0,previous:create,previous_statement:s1,replacements:[fork_field])
case mode
when '--partial'
  File.open(path,'ab'){|file|file.write("\x00\x00".b);file.fsync}
  exit!(19)
when '--seed'
  j=ContactLocalHistory.create(path,pin,fingerprint,account,origin,8,[first],10000)
  j.accept(nil,[first],create,s1)
  puts 'Seeded revision one'
when '--advance'
  j=ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)
  holder=j.lookup(contact).token
  begin
    j.accept(holder,[first,second],update,s2);puts 'CAS won'
  rescue ZrotextCandidate::ContactLocalHistory::Refused
    exit 3
  end
when '--compete'
  j=ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)
  holder=j.lookup(contact).token
  begin
    j.accept(holder,[first,second],fork,s2);puts 'unexpected fork win'
  rescue ZrotextCandidate::ContactLocalHistory::Refused
    exit 3
  end
when '--verify'
  j=ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)
  raise AssertionError,'Child CAS state' unless j.lookup(contact).metadata.revision==2
  puts 'Restart CAS verified'
when '--refused'
  ZrotextCandidate.refuse{ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)}
  puts 'Interrupted append refused'
else
  ZrotextCandidate.refuse{ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)}
  j=ContactLocalHistory.create(path,pin,fingerprint,account,origin,8,[first],10000)
  ZrotextCandidate.refuse{ContactLocalHistory.create(path,pin,fingerprint,account,origin,8,[first],10000)}
  wrong_fp=fingerprint.dup;wrong_fp.setbyte(0,wrong_fp.getbyte(0)^1)
  ZrotextCandidate.refuse{ContactLocalHistory.open(path,pin,wrong_fp,account,origin,8)}
  wrong_account=account.dup;wrong_account.setbyte(0,wrong_account.getbyte(0)^1)
  ZrotextCandidate.refuse{ContactLocalHistory.open(path,pin,fingerprint,wrong_account,origin,8)}
  raise AssertionError,'Unobserved' unless j.lookup(contact).reason=='unobserved'
  ZrotextCandidate.refuse{j.accept(nil,[first],update,s2)}
  saved=j.accept(nil,[first],create,s1)
  raise AssertionError,'Cold create' unless saved.accepted? && saved.metadata.revision==1
  holder=saved.token
  replay=j.accept(holder,[first],create,s1)
  raise AssertionError,'Replay' unless replay.accepted? && replay.metadata.revision==1
  ZrotextCandidate.refuse{j.accept(nil,[first],create,s1)}
  advanced=j.accept(holder,[first,second],fork,s2)
  raise AssertionError,'Root advance' unless advanced.accepted? && advanced.metadata.revision==2 && advanced.metadata.manifest_version==2
  ZrotextCandidate.refuse{j.accept(advanced.token,[first,second],update,s2)}
  reduced=ContactLocalHistory.open(path,pin,fingerprint,account,origin,8,reduction:true)
  reduced_row=reduced.lookup(contact)
  raise AssertionError,'Reduction lookup' if reduced_row.accepted? || reduced_row.reason!='reduction_only'
  ZrotextCandidate.refuse{reduced.accept(reduced_row.token,[first,second],update,s2)}
  raise AssertionError,'Reduction stop' unless reduced.mark_unavailable(reduced_row.token).reason=='local_stop'
  reduced.close
  ZrotextCandidate.refuse{j.mark_unavailable(advanced.token)}
  raise AssertionError,'Terminal lookup' unless j.lookup(contact).reason=='local_stop'
  ZrotextCandidate.refuse{j.accept(j.lookup(contact).token,[first,second],clear,s2)}
  j.close
  ZrotextCandidate.refuse{j.lookup(contact)}
  reopened=ContactLocalHistory.open(path,pin,fingerprint,account,origin,8)
  raise AssertionError,'Terminal restart' unless reopened.lookup(contact).reason=='local_stop'
  ZrotextCandidate.refuse{reopened.accept(holder,[first,second],update,s2)}
  reopened.close
  other=contact.dup;other.setbyte(0,other.getbyte(0)^1)
  expected_other=ContactField::Expected.new(account:account,origin:origin,root_fingerprint:fingerprint,contact:other,routing:routing,parser:parser)
  reissue=lambda do |template|
    unsigned=template.byteslice(0,template.bytesize-64).dup;unsigned[22,16]=other;unsigned[198,16]="\x42".b*16
    ContactField.verify(ContactField.produce_software(fork_key,s1,expected_other,unsigned).bytes,s1,contact:other,routing:routing)
  end
  other_name=reissue.call(f['name']);other_notes=reissue.call(f['notes'])
  other_unsigned=f['create'].byteslice(0,304).dup;other_unsigned[22,16]=other;other_unsigned[54,16]="B".b*16
  other_unsigned[231,32]=other_name.digest;other_unsigned[272,32]=other_notes.digest
  other_create=ContactMutation.produce_software(fork_key,s1,expected_other,other_unsigned,previous:nil,previous_statement:nil,replacements:[other_name,other_notes])
  bounded_path=path+'.bounded'
  bounded=ContactLocalHistory.create(bounded_path,pin,fingerprint,account,origin,1,[first],10000)
  bounded.accept(nil,[first],create,s1)
  ZrotextCandidate.refuse{bounded.accept(nil,[first],other_create,s1)}
  bounded.close;File.delete(bounded_path)
  bytes=File.binread(path);bad=path+'.bad'
  [0,4,98,130,161,bytes.bytesize-33,bytes.bytesize-1].each do |at|
    copy=bytes.dup;copy.setbyte(at,copy.getbyte(at)^1);File.binwrite(bad,copy)
    ZrotextCandidate.refuse{ContactLocalHistory.open(bad,pin,fingerprint,account,origin,8)}
  end
  File.delete(bad)
  puts "Ruby contact history #{$checks} controls passed"
end
