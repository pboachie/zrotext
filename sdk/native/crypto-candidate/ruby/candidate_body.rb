# SPDX-License-Identifier: AGPL-3.0-only
# frozen_string_literal: true
require 'openssl'

module Zrotext
  module CandidateBody
    class BodyError < ArgumentError
      attr_reader :reason
      def initialize(reason)
        @reason = reason
        super("candidate body: #{reason}")
      end
    end

    # Symmetric primitive only. The caller must verify all envelope authority and recover the authorized key first.
    def self.open(content_key:, nonce:, verified_aad:, ciphertext:)
      unless [content_key, nonce, verified_aad, ciphertext].all? { |x| x.is_a?(String) } &&
             content_key.bytesize == 32 && nonce.bytesize == 12 && verified_aad.bytesize.between?(1, 36864) &&
             ciphertext.bytesize.between?(17, 32784)
        raise BodyError, 'shape'
      end
      plaintext = nil
      begin
        cipher = OpenSSL::Cipher.new('aes-256-gcm')
        cipher.decrypt
        cipher.key = content_key.b
        cipher.iv = nonce.b
        cipher.auth_tag = ciphertext.byteslice(-16, 16).b
        cipher.auth_data = verified_aad.b
        plaintext = cipher.update(ciphertext.byteslice(0, ciphertext.bytesize - 16).b)
        plaintext << cipher.final # authenticate before any decoding or plaintext return
        decode(plaintext)
      rescue OpenSSL::Cipher::CipherError
        raise BodyError, 'authentication'
      ensure
        plaintext&.replace("\0" * plaintext.bytesize)
      end
    end

    def self.decode(bytes)
      raise BodyError, 'length' unless bytes.is_a?(String) && bytes.bytesize.between?(1, 32768)
      raise BodyError, 'nul' if bytes.b.include?("\0")
      raise BodyError, 'bom' if bytes.b.start_with?("\xef\xbb\xbf".b)
      text = bytes.dup.force_encoding(Encoding::UTF_8)
      raise BodyError, 'utf8' unless text.valid_encoding?
      text
    end
  end
end
