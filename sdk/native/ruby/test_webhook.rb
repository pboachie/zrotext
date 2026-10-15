# SPDX-License-Identifier: AGPL-3.0-only
# frozen_string_literal: true
require_relative 'lib/zrotext/webhook'

KEY = '0123456789abcdef0123456789abcdef'
SIGNATURE = 'v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405'
BODY = '{"event":"test"}'

count = 0
File.readlines(ARGV.fetch(0), chomp: true).drop(1).each do |line|
  row = line.split("\t")
  actual = 'ok'
  begin
    Zrotext::Webhook.verify(signing_key: KEY, timestamp: row[1], signature: row[2],
                            body: [row[3]].pack('H*'), now_seconds: Integer(row[4]))
  rescue Zrotext::Webhook::VerificationError => error
    actual = error.reason
  end
  raise "#{row[0]}: #{actual}" unless actual == row[5]
  count += 1
end

def rejects(reason, **overrides)
  defaults = { signing_key: KEY, timestamp: '1700000000', signature: SIGNATURE,
               body: BODY, now_seconds: 1700000000 }
  begin
    Zrotext::Webhook.verify(**defaults.merge(overrides))
  rescue Zrotext::Webhook::VerificationError => error
    raise unless error.reason == reason
    return
  end
  raise "Expected #{reason}"
end

['', "1700000000\n", ' 1700000000', '1e9'].each { |value| rejects('bad_timestamp', timestamp: value) }
rejects('bad_signature_format', signature: SIGNATURE + "\n")
rejects('signature_mismatch', signing_key: "\0" * 32)
rejects('bad_timestamp', timestamp: "\xff".dup.force_encoding('UTF-8'))
rejects('bad_signature_format', signature: "\xff".dup.force_encoding('UTF-8'))
puts "Ruby: #{count} shared vectors and 8 rejection checks passed"
