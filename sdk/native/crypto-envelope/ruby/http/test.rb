# frozen_string_literal: true
require_relative 'original_http'
require 'securerandom'
p = JSON.parse($stdin.read)
state = 'unavailable'
start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
begin
  client = ZrotextCandidate::OriginalHTTP.new(origin: p.fetch('Origin'), timeout_ms: p.fetch('Timeout'), additional_roots_pem: p.fetch('Roots'))
  method = p.fetch('Method')
  request = {method: method, accepted_manifest_version: p['Invalid'] == 'version' ? 0 : 1}
  id = SecureRandom.uuid
  request[:event_id] = p['Invalid'] == 'uuid' ? 'invalid' : id if %w[read consume].include?(method)
  request[:consumption_id] = id if method == 'status'
  request.merge!(limit: 2, cursor: nil) if method == 'page'
  request.merge!(request_id: id, active_request_id: nil) if method == 'consume'
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  wire = client.exchange(credential: p.fetch('Grant'), **request)
  raise 'invalid test result' unless JSON.parse(wire.untrusted_json)['untrusted']
  state = 'untrusted'
rescue ZrotextCandidate::OriginalHTTP::Failure => e
  state = e.unknown ? 'unknown' : 'unavailable'
end
puts JSON.generate(state: state, elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - start)
