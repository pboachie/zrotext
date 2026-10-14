# frozen_string_literal: true
require_relative '../composition/compose03'
require 'base64'
include ZrotextCandidate
def open_policy(wire,proof,authority,now,envelope)
    reader=OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([
      OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(wire.fetch('readerScalar')),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')],0,:CONTEXT_SPECIFIC),
      OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(wire.fetch('readerPoint'))],1,:CONTEXT_SPECIFIC)
    ]).to_der)
    return ElectedReader03.open_software(envelope,proof.accepted_manifest,proof,-> { [authority,now] },wire.fetch('message'),'+12',reader)
end
if ARGV==['--probe']
  begin
    ProtectedSigner.probe
  rescue ArgumentError,Fiddle::DLError
    exit 77
  end
  exit
end
raise ArgumentError,'External pending receipt required' unless ARGV.length==1
reader_mode=ARGV==['--readers'];receipt=ARGV[0];owner=nil
begin
  unless reader_mode
  owner=ProtectedSigner.create do |name|
    File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0o600) { |file| file.write(name+"\n");file.flush;file.fsync }
  end
  puts owner.public_point.unpack1('H*');STDOUT.flush
  end
  count=0
  STDIN.read.gsub("\r\n","\n").strip.split("\n\n").each do |block|
    lines=block.lines.map(&:strip);head=lines.shift.split("\t")
    raise 'Policy header' unless head.length==5
    name,expected=head;accept=expected=='true';observed,now,expires=head.drop(2).map { |n| Integer(n) }
    wire={};accepted={};authority={}
    lines.each do |line|
      key,kind,value=line.split("\t");value=kind=='b' ? [value].pack('H*') : Integer(value)
      if key.start_with?('accepted.') then accepted[key.delete_prefix('accepted.')]=value
      elsif key.start_with?('authority.') then authority[key.delete_prefix('authority.')]=value
      else wire[key]=value end
    end
    # Verify signed evidence before the expected composition-refusal catch.
    prior=ManifestChain.genesis02(wire.fetch('signed02'),ManifestChain::RootPin.enroll(wire.fetch('rootPin'),wire.fetch('fingerprint')),10000)
    proof=Election03.verify(wire.fetch('bundle'),wire.fetch('core'),accepted,prior,wire.fetch('signed02'),wire.fetch('signed03'),wire.fetch('deviceSigningPoint'),wire.fetch('ownerApprovalPoint'))
    recipients=proof.accepted_manifest.key_records.select { |key| key.getbyte(0).between?(1,3) }.map { |key| [key.getbyte(0),key.byteslice(1,32)] }
    if reader_mode
      SignedEnvelope.verify(wire.fetch('envelope'),3,wire.fetch('signerPoint'))
      begin
        opened=open_policy(wire,proof,authority,now,wire.fetch('envelope'))
      rescue ArgumentError,OpenSSL::OpenSSLError
        raise "Accepted reader policy refused: #{name}" if accept
        puts "READ #{name} refused";count+=1;next
      end
      raise "Reader policy mismatch: #{name}" unless accept && opened.b==wire.fetch('bodyText')
      puts "READ #{name} accepted";count+=1;next
    end
    request={manifest:proof.accepted_manifest,proof:proof,authority:-> { [authority,now] },message:wire.fetch('message'),observed_ms:observed,expires_ms:expires,peer:'+12',content:wire.fetch('bodyText').dup.force_encoding(Encoding::UTF_8),signer:owner,recipients:recipients}
    begin
      envelope=Compose03.fresh(**request)
    rescue ArgumentError,OpenSSL::OpenSSLError
      raise "Accepted policy refused: #{name}" if accept
      puts "REFUSED #{name}";count+=1;next
    end
    raise "Policy rejection missing: #{name}" unless accept
    raise "Native policy self-open: #{name}" unless open_policy(wire,proof,authority,now,envelope).b==wire.fetch('bodyText')
    puts "ENVELOPE #{name} #{Base64.strict_encode64(envelope)}";count+=1
  end
  puts "#{reader_mode ? 'READERS: ' : 'QUALIFIED: '}#{count} Ruby signed time-policy cases passed"
ensure
  if owner then owner.delete_created;File.delete(receipt);owner.close end
end
