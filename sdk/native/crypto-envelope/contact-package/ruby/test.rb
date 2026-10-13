# frozen_string_literal: true
require 'json'
require 'base64'
require 'zrotext_native_candidate'
include ZrotextCandidate
if ARGV[1]=='--probe'
  begin ProtectedContactSigner.probe;rescue ArgumentError;exit 77 end
  exit
end
key=nil;alias_name=nil;point=nil;receipt=ARGV[2]
record=->(state){File.open(receipt,'w'){|file|file.write(JSON.generate({alias:alias_name,state:state}));file.flush;file.fsync}}
begin
if ARGV[1]=='--hardware'
  key=ProtectedContactSigner.create{|value|alias_name=value;record.call('pending')};point=key.public_point
  puts JSON.generate({alias:alias_name,public:Base64.strict_encode64(point)});STDOUT.flush
end
parser=ContactOrigin.new(ARGV.fetch(0))
results=JSON.parse(STDIN.read).map do |request|
  begin
    operation=request.fetch('operation')
    next({accepted:parser.accepts?(request.fetch('origin'))}) if operation=='origin'
    f=request.fetch('fixture');d=->(key){Base64.strict_decode64(f.fetch(key))};which=request.fetch('statement','statement')
    pin=ManifestChain::RootPin.enroll(d.call('rootPin'),d.call('fingerprint'));manifest=ManifestChain.genesis02(d.call('manifest'),pin,10000)
    manifest=ManifestChain.continue_chain(d.call('nextManifest'),manifest,2,10000) if which=='nextStatement'
    statement=ContactField.verify_statement(d.call(which),manifest,account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),parser:parser)
    next({accepted:true}) if operation=='statement'
    raw=d.call(request.fetch('field','name'))
    if operation=='verify'
      verified=ContactField.verify(raw,statement,contact:d.call('contact'),routing:d.call('routing'))
    elsif operation=='produce'
      if key
        unsigned=raw.byteslice(0,raw.bytesize-64);unsigned[102,32]=manifest.digest;unsigned[134,32]=statement.digest
        unsigned[214,32]=OpenSSL::Digest::SHA256.digest("ZTSE/key/v1\0".b+"\x01\x01".b+point)
        expected=ContactField::Expected.new(account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
        borrowed=ProtectedContactSigner.open(alias_name,point)
        begin
          refused=false;begin borrowed.delete_created;rescue ArgumentError;refused=true end
          raise 'borrowed deletion accepted' unless refused
          borrowed.close if request['closed']==true
          cancelled=ContactField::Cancellation.new;cancelled.cancel if request['cancel']==true
          verified=ContactField.produce_protected(borrowed,statement,expected,unsigned,cancelled:cancelled)
        ensure borrowed.close end
      else
      scalar=request.key?('scalar') ? Base64.strict_decode64(request['scalar']) : ("\x00".b*31+"\x07".b)
      der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ObjectId.new('prime256v1',0,:EXPLICIT),OpenSSL::ASN1::BitString.new(manifest.root_point,1,:EXPLICIT)]).to_der
      software_key=OpenSSL::PKey.read(der);expected=ContactField::Expected.new(account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
      cancelled=ContactField::Cancellation.new;cancelled.cancel if request['cancel']==true
      verified=ContactField.produce_software(software_key,statement,expected,raw.byteslice(0,raw.bytesize-64),cancelled:cancelled)
      end
    else
      raise 'Unknown probe mode'
    end
    {accepted:true,bytes:Base64.strict_encode64(verified.bytes)}
  rescue StandardError
    {accepted:false}
  end
end
puts JSON.generate(results)

ensure
  if key
    key.delete_created
    if point
      refused=false;begin reopened=ProtectedContactSigner.open(alias_name,point);reopened.close;rescue ArgumentError;refused=true end
      raise 'deleted key reopened' unless refused
    end
    record.call('owned_key_deleted');puts JSON.generate({owned_key_deleted:true});STDOUT.flush
  end
end
