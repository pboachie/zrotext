# frozen_string_literal: true
require 'json'
require 'base64'
require 'open3'
require_relative 'protected_recipient'
require_relative '../sealed_reader02'
require_relative '../elected_reader03'
include ZrotextCandidate

def check(value)
  raise 'Protected recipient assertion' unless value
  $checks += 1
end
def refuses
  yield
rescue ArgumentError, OpenSSL::OpenSSLError
  $checks += 1
else
  raise 'Missing protected refusal'
end
def fixture(directory,script,point)
  output,error,status=Open3.capture3({'NODE_OPTIONS'=>nil,'NODE_PATH'=>nil},'node',File.join(directory,script),'--recipient-point',point.unpack1('H*'))
  raise "Independent producer failed: #{error}" unless status.success?
  JSON.parse(output)
end
def bytes(record,name) = Base64.strict_decode64(record.fetch(name))
def record(value) = value.transform_values { |v| v.is_a?(String) ? Base64.strict_decode64(v) : v }

raise ArgumentError,'Expected producer directory and fresh external receipt' unless ARGV.length == 2
begin
  ProtectedRecipient.probe
rescue ArgumentError, Fiddle::DLError
  puts 'UNQUALIFIED: read-only PCP unavailable; no creation attempted'
  exit 0
end
$checks=0
owner=nil
deleted=false
receipt=File.expand_path(ARGV[1])
begin
  owner=ProtectedRecipient.create do |alias_name|
    File.open(receipt,File::WRONLY|File::CREAT|File::EXCL,0o600) do |f|
      f.write(alias_name+"\n"); f.flush; f.fsync
    end
  end
  point=owner.public_point
  check(point.bytesize == 65 && point.getbyte(0) == 4)
  reopened=ProtectedRecipient.open(owner.alias_name,point)
  begin
    check(reopened.public_point == point)
    refuses { reopened.delete_created }
  ensure
    reopened.close
  end
  wrong=OpenSSL::PKey::EC.generate('prime256v1').public_key.to_octet_string(:uncompressed)
  refuses { ProtectedRecipient.open(owner.alias_name,wrong).close }
  f=fixture(ARGV[0],'produce-fixture.mjs',point)
  check(!f.key?('archiveScalar'))
  manifest=ManifestChain.genesis02(bytes(f,'manifest'),ManifestChain::RootPin.enroll(bytes(f,'rootPin'),bytes(f,'fingerprint')),10000)
  current=->(a,v,d,w) { a == manifest.account && v == manifest.version && d == manifest.digest }
  %w[inbound outbound].each do |kind|
    check(SealedReader02.open_with_recipient(bytes(f,kind),manifest,10000,2,bytes(f,'reader'),owner,current) == f.fetch('text'))
  end
  refuses { SealedReader02.open_with_recipient(bytes(f,'inbound'),manifest,10000,2,bytes(f,'reader'),owner,->(*) { false }) }
  e=fixture(ARGV[0],'produce-election03.mjs',point)
  check(!e.key?('readerScalar'))
  prior=ManifestChain.genesis02(bytes(e,'signed02'),ManifestChain::RootPin.enroll(bytes(e,'rootPin'),bytes(e,'fingerprint')),10000)
  proof=Election03.verify(bytes(e,'bundle'),bytes(e,'core'),record(e.fetch('accepted')),prior,bytes(e,'signed02'),bytes(e,'signed03'),bytes(e,'deviceSigningPoint'),bytes(e,'ownerApprovalPoint'))
  source=-> { [record(e.fetch('authority')),30000] }
  check(ElectedReader03.open_with_recipient(bytes(e,'envelope'),proof.accepted_manifest,proof,source,bytes(e,'message'),'+12',owner) == e.fetch('bodyText'))
  refuses { ElectedReader03.open_with_recipient(bytes(e,'envelope'),proof.accepted_manifest,proof,source,bytes(e,'message'),'+13',owner) }
  alias_name=owner.alias_name
  owner.delete_created; deleted=true
  refuses { owner.public_point }
  refuses { ElectedReader03.open_with_recipient(bytes(e,'envelope'),proof.accepted_manifest,proof,source,bytes(e,'message'),'+12',owner) }
  refuses { ProtectedRecipient.open(alias_name,point).close }
  File.delete(receipt)
  puts "QUALIFIED: #{$checks} native Ruby PCP checks passed; owned key deleted"
ensure
  if owner
    begin
      unless deleted
        owner.delete_created
        File.delete(receipt)
      end
    ensure
      owner.close
    end
  end
end
