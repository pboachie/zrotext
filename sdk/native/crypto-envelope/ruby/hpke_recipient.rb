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
      raise ArgumentError, 'Candidate wrap bounds' unless ciphertext.bytesize==48
      open_content(recipient,public_point,encapsulated,info,aad,ciphertext)
    end

    def open_content(recipient,public_point,encapsulated,info,aad,ciphertext)
      raise ArgumentError, 'Candidate content bounds' if info.bytesize > 36864 || aad.bytesize > 36864 || !ciphertext.bytesize.between?(17,32784)
      pk, enc, context_info, authenticated, encrypted = [public_point, encapsulated, info, aad, ciphertext].map { |v| v.b.dup }
      expected_public = point(pk)
      raise ArgumentError, 'Recipient key binding' unless recipient.public_to_der == expected_public.public_to_der
      ephemeral = point(enc)
      dh = recipient.derive(ephemeral)
      open_content_agreement(dh, pk, enc, context_info, authenticated, encrypted)
    ensure
      dh&.replace("\x00".b * dh.bytesize)
    end

    # Trusted adapter primitive; shared DH alone makes no custody assertion.
    def open_agreement(shared_dh, pk, enc, context_info, authenticated, encrypted)
      raise ArgumentError, 'Candidate agreement bounds' unless encrypted.bytesize==48
      open_content_agreement(shared_dh,pk,enc,context_info,authenticated,encrypted)
    end

    def open_content_agreement(shared_dh,pk,enc,context_info,authenticated,encrypted)
      crypt_content(shared_dh,pk,enc,context_info,authenticated,encrypted,false)
    end

    def seal_content(pk,info,aad,plain)
      raise ArgumentError, 'Candidate content bounds' unless plain.bytesize.between?(1,32768)
      ephemeral=OpenSSL::PKey::EC.generate('prime256v1');enc=ephemeral.public_key.to_octet_string(:uncompressed);dh=ephemeral.derive(point(pk))
      enc+crypt_content(dh,pk,enc,info,aad,plain,true)
    ensure
      dh&.replace("\x00".b*dh.bytesize)
    end

    def crypt_content(shared_dh,pk,enc,context_info,authenticated,encrypted,seal)
      raise ArgumentError, 'Candidate agreement bounds' if context_info.bytesize > 36864 || authenticated.bytesize > 36864 || !(seal ? encrypted.bytesize.between?(1,32768) : encrypted.bytesize.between?(17,32784))
      point(pk); point(enc)
      secrets = []
      dh = shared_dh.b.dup; secrets << dh
      raise ArgumentError, 'P256 shared secret width' unless dh.bytesize == 32
      prk = extract(KEM, ''.b, 'eae_prk', dh); secrets << prk
      shared = expand(KEM, prk, 'shared_secret', enc + pk, 32); secrets << shared
      context = "\x00".b + extract(SUITE, ''.b, 'psk_id_hash', ''.b) + extract(SUITE, ''.b, 'info_hash', context_info)
      schedule = extract(SUITE, shared, 'secret', ''.b); secrets << schedule
      key = expand(SUITE, schedule, 'key', context, 16); secrets << key
      nonce = expand(SUITE, schedule, 'base_nonce', context, 12); secrets << nonce
      cipher = OpenSSL::Cipher.new('aes-128-gcm');seal ? cipher.encrypt : cipher.decrypt
      cipher.key = key; cipher.iv = nonce
      cipher.auth_tag = encrypted.byteslice(-16,16) unless seal
      cipher.auth_data = authenticated
      plaintext = cipher.update(seal ? encrypted : encrypted.byteslice(0,encrypted.bytesize-16))
      plaintext << cipher.final
      plaintext << cipher.auth_tag if seal
      success = true
      plaintext
    ensure
      secrets&.each { |value| value.replace("\x00".b * value.bytesize) }
      plaintext&.replace("\x00".b * plaintext.bytesize) unless success
    end

    def software_content(recipient) = ->(*arguments) { open_content(recipient, *arguments) }

    def software(recipient) = ->(*arguments) { open(recipient, *arguments) }
  end
end
