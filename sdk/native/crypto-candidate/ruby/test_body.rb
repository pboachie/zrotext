# SPDX-License-Identifier: AGPL-3.0-only
# frozen_string_literal: true
require_relative 'candidate_body'
count = 0
File.readlines(ARGV.fetch(0), chomp: true).each do |line|
  row = line.split("\t", -1)
  actual = 'accept'
  begin
    result = if row[1] == 'text'
               Zrotext::CandidateBody.decode([row[5]].pack('H*'))
             else
               Zrotext::CandidateBody.open(content_key: [row[2]].pack('H*'), nonce: [row[3]].pack('H*'),
                                           verified_aad: [row[4]].pack('H*'), ciphertext: [row[5]].pack('H*'))
             end
    raise "#{row[0]}: plaintext mismatch" unless result.b.unpack1('H*') == row[7]
  rescue Zrotext::CandidateBody::BodyError => error
    actual = error.reason
  end
  raise "#{row[0]}: #{actual} expected #{row[6]}" unless actual == row[6]
  count += 1
end
raise 'Incomplete candidate body corpus' if count < 47
puts "Ruby candidate body: #{count} cases passed"
