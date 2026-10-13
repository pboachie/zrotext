# frozen_string_literal: true
require 'openssl'

module ZrotextCandidate
  # RFC9180 base-mode, sequence-zero primitive; does not establish manifest authority.
  module HpkeRecipient
    KEM = "KEM\x00\x10".b.freeze
    SUITE = "HPKE\x00\x10\x00\x01\x00\x01".b.freeze
    module_function

    def extract(suite, salt, label, input)
      OpenSSL::HMAC.digest('SHA256', salt, 'HPKE-v1'.b + suite + label.b + input)
    end

    def expand(suite, key, label, info, size)
      block = OpenSSL::HMAC.digest('SHA256', key, [size].pack('n') + 'HPKE-v1'.b + suite + label.b + info + "\x01".b)
      block.byteslice(0, size)
    ensure
      block&.replace("\x00".b * block.bytesize)
    end

    def point(bytes)
      raise ArgumentError, 'P256 point encoding' unless bytes.bytesize == 65 && bytes.getbyte(0) == 4
      group = OpenSSL::PKey::EC::Group.new('prime256v1')
      value = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(bytes, 2))
      raise ArgumentError, 'P256 point not on curve' if value.infinity? || !value.on_curve?
      algorithm = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'), OpenSSL::ASN1::ObjectId.new('prime256v1')])
      OpenSSL::PKey.read(OpenSSL::ASN1::Sequence.new([algorithm, OpenSSL::ASN1::BitString.new(bytes)]).to_der)
    end

    # recipient is an authorized native OpenSSL key; no hardware/exportability assertion.
    def open(recipient, public_point, encapsulated, info, aad, ciphertext)
      raise ArgumentError, 'Candidate wrap bounds' if info.bytesize > 36864 || aad.bytesize > 36864 || ciphertext.bytesize != 48
      pk, enc, context_info, authenticated, encrypted = [public_point, encapsulated, info, aad, ciphertext].map { |v| v.b.dup }
      expected_public = point(pk)
      raise ArgumentError, 'Recipient key binding' unless recipient.public_to_der == expected_public.public_to_der
      ephemeral = point(enc)
      secrets = []
      dh = recipient.derive(ephemeral); secrets << dh
      raise ArgumentError, 'P256 shared secret width' unless dh.bytesize == 32
      prk = extract(KEM, ''.b, 'eae_prk', dh); secrets << prk
      shared = expand(KEM, prk, 'shared_secret', enc + pk, 32); secrets << shared
      context = "\x00".b + extract(SUITE, ''.b, 'psk_id_hash', ''.b) + extract(SUITE, ''.b, 'info_hash', context_info)
      schedule = extract(SUITE, shared, 'secret', ''.b); secrets << schedule
      key = expand(SUITE, schedule, 'key', context, 16); secrets << key
      nonce = expand(SUITE, schedule, 'base_nonce', context, 12); secrets << nonce
      cipher = OpenSSL::Cipher.new('aes-128-gcm').decrypt
      cipher.key = key; cipher.iv = nonce
      cipher.auth_tag = encrypted.byteslice(32,16); cipher.auth_data = authenticated
      plaintext = cipher.update(encrypted.byteslice(0,32))
      plaintext << cipher.final
      success = true
      plaintext
    ensure
      secrets&.each { |value| value.replace("\x00".b * value.bytesize) }
      plaintext&.replace("\x00".b * plaintext.bytesize) unless success
    end
  end
end
