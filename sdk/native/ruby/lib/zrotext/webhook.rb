# SPDX-License-Identifier: AGPL-3.0-only
# frozen_string_literal: true

require 'openssl'

module Zrotext
  module Webhook
    class VerificationError < ArgumentError
      attr_reader :reason

      def initialize(reason)
        @reason = reason
        super("webhook verification failed: #{reason}")
      end
    end

    # Body must be the raw request string, not parsed or re-serialized JSON.
    def self.verify(signing_key:, timestamp:, signature:, body:, now_seconds: Time.now.to_i)
      unless timestamp.is_a?(String) && timestamp.ascii_only? && /\A(?:0|[1-9][0-9]{0,15})\z/.match?(timestamp)
        raise VerificationError, 'bad_timestamp'
      end
      seconds = Integer(timestamp, 10)
      unless now_seconds.is_a?(Integer) && now_seconds.between?(seconds - 300, seconds + 300)
        raise VerificationError, 'timestamp_out_of_window'
      end
      unless signature.is_a?(String) && signature.ascii_only? && /\Av1=[0-9a-f]{64}\z/.match?(signature)
        raise VerificationError, 'bad_signature_format'
      end
      unless signing_key.is_a?(String) && signing_key.bytesize == 32
        raise ArgumentError, 'signing_key must contain 32 decoded bytes'
      end
      raise ArgumentError, 'body must contain raw bytes' unless body.is_a?(String)

      expected = OpenSSL::HMAC.digest('SHA256', signing_key.b, timestamp.b + '.'.b + body.b)
      actual = [signature.delete_prefix('v1=')].pack('H*')
      raise VerificationError, 'signature_mismatch' unless OpenSSL.fixed_length_secure_compare(expected, actual)

      nil
    end
  end
end
