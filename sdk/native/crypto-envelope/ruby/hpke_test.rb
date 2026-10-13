# frozen_string_literal: true
require_relative 'hpke_recipient'

checks = 0
vectors = 0
rejects = lambda do |&action|
  begin
    action.call
  rescue OpenSSL::OpenSSLError, ArgumentError
    checks += 1
    next
  end
  raise 'Invalid wrap accepted'
end
$stdin.each_line do |line|
  fields = line.chomp.split("\t", -1)
  raise 'Fixture fields' unless fields.length == 9
  data = fields.drop(2).map { |hex| [hex].pack('H*') }
  # RFC5915 scalar import exists only in the interoperability test adapter.
  key_der = OpenSSL::ASN1::Sequence.new([
    OpenSSL::ASN1::Integer.new(1), OpenSSL::ASN1::OctetString.new(data[0]),
    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::ObjectId.new('prime256v1')], 0, :CONTEXT_SPECIFIC),
    OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::BitString.new(data[1])], 1, :CONTEXT_SPECIFIC)
  ]).to_der
  key = OpenSSL::PKey.read(key_der)
  plaintext = ZrotextCandidate::HpkeRecipient.open(key,*data[1..5])
  raise 'Cross-client plaintext mismatch' unless plaintext == data[6]
  plaintext.replace("\x00".b * plaintext.bytesize)
  checks += 1; vectors += 1
  prime = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'.to_i(16)
  negated = data[1].dup
  negated[33,32] = [(prime-data[1].byteslice(33,32).unpack1('H*').to_i(16)).to_s(16).rjust(64,'0')].pack('H*')
  begin
    ZrotextCandidate::HpkeRecipient.open(key,negated,data[2],data[3],data[4],"\x00".b*48)
    raise 'Unbound recipient'
  rescue ArgumentError => error
    raise unless error.message == 'Recipient key binding'
    checks += 1
  end
  (1..5).each do |index|
    changed = data.map(&:dup)
    if changed[index].empty?
      changed[index] = "\x01".b
    else
      changed[index].setbyte(changed[index].bytesize-1, changed[index].getbyte(changed[index].bytesize-1)^1)
    end
    rejects.call { ZrotextCandidate::HpkeRecipient.open(key,*changed[1..5]) }
  end
  ["\x00".b*65, "\x04".b+"\x00".b*64, "\x00".b*33].each do |bad|
    rejects.call { ZrotextCandidate::HpkeRecipient.open(key,data[1],bad,*data[3..5]) }
  end
  rejects.call { ZrotextCandidate::HpkeRecipient.open(key,data[1],data[2],"\x00".b*36865,data[4],data[5]) }
  rejects.call { ZrotextCandidate::HpkeRecipient.open(key,data[1],data[2],data[3],"\x00".b*36865,data[5]) }
  rejects.call { ZrotextCandidate::HpkeRecipient.open(key,*data[1..4],"\x00".b*47) }
end
raise 'Missing profile component vectors' unless vectors >= 2
puts "Ruby HPKE: #{checks} checks on #{vectors} vectors passed"
