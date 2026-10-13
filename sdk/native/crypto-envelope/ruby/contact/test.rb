# frozen_string_literal: true
require 'json'
require 'base64'
require_relative 'contact_field'
include ZrotextCandidate
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
      scalar=request.key?('scalar') ? Base64.strict_decode64(request['scalar']) : ("\x00".b*31+"\x07".b)
      der=OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(1),OpenSSL::ASN1::OctetString.new(scalar),OpenSSL::ASN1::ObjectId.new('prime256v1',0,:EXPLICIT),OpenSSL::ASN1::BitString.new(manifest.root_point,1,:EXPLICIT)]).to_der
      key=OpenSSL::PKey.read(der);expected=ContactField::Expected.new(account:d.call('account'),origin:f.fetch('origin'),root_fingerprint:d.call('fingerprint'),contact:d.call('contact'),routing:d.call('routing'),parser:parser)
      cancelled=ContactField::Cancellation.new;cancelled.cancel if request['cancel']==true
      verified=ContactField.produce_software(key,statement,expected,raw.byteslice(0,raw.bytesize-64),cancelled:cancelled)
    else
      raise 'Unknown probe mode'
    end
    {accepted:true,bytes:Base64.strict_encode64(verified.bytes)}
  rescue StandardError
    {accepted:false}
  end
end
puts JSON.generate(results)
