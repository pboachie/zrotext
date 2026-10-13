# frozen_string_literal: true
require 'base64'
require 'json'
require 'net/http'
require 'openssl'
require 'timeout'
require 'uri'

# Candidate wire transport only. Neither JSON nor a server proof is trusted here.
module ZrotextCandidate
class OriginalHTTP
  class Failure < StandardError
    attr_reader :unknown
    def initialize(unknown = false)
      @unknown = unknown
      super(unknown ? 'original reply outcome unknown' : 'original reply unavailable')
    end
  end
  class UniqueObject < Hash
    def []=(key, value)
      raise Failure if key?(key)
      super
    end
  end
  Wire = Struct.new(:untrusted_json, keyword_init: true)
  MAX = 524_288
  SAFE = 9_007_199_254_740_991
  UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/

  # Additional CA roots are independently trusted application configuration.
  def initialize(origin:, timeout_ms:, additional_roots_pem: '')
    raise Failure unless timeout_ms.is_a?(Integer) && (1..10_000).cover?(timeout_ms)
    raise Failure unless origin.is_a?(String) && origin.ascii_only? && !origin.match?(/[\x00-\x20\x7f\\?#@]/)
    uri = URI.parse(origin)
    raise Failure unless uri.scheme == 'https' && uri.host && !uri.userinfo && ['', '/'].include?(uri.path)
    @uri = URI.parse(origin.delete_suffix('/') + '/v1/reply-events')
    @timeout = timeout_ms / 1000.0
    @store = OpenSSL::X509::Store.new
    @store.set_default_paths
    unless additional_roots_pem.empty?
      certs = additional_roots_pem.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
      raise Failure if certs.empty?
      certs.each { |pem| @store.add_cert(OpenSSL::X509::Certificate.new(pem)) }
    end
  rescue Failure
    raise
  rescue StandardError
    raise Failure.new, cause: nil
  end

  def self.uuid!(value)
    raise Failure unless value.is_a?(String) && UUID.match?(value) && value.delete('-') != '0' * 32
    value
  end

  def self.body(method:, accepted_manifest_version:, **fields)
    raise Failure unless accepted_manifest_version.is_a?(Integer) && (1..SAFE).cover?(accepted_manifest_version)
    out = { 'v' => 1, 'method' => method, 'accepted_manifest_version' => accepted_manifest_version }
    expected = case method
               when 'current' then []
               when 'read' then [:event_id]
               when 'status' then [:consumption_id]
               when 'page' then [:limit, :cursor]
               when 'consume' then [:event_id, :request_id, :active_request_id]
               else raise Failure
               end
    raise Failure unless fields.keys.sort == expected.sort
    fields.each do |key, value|
      case key
      when :limit
        raise Failure unless value.is_a?(Integer) && (1..32).cover?(value)
      when :cursor
        unless value.nil?
          raise Failure unless value.is_a?(Hash) && value.keys.sort == [:accepted_at_ms, :event_id]
          uuid!(value[:event_id])
          time = value[:accepted_at_ms]
          raise Failure unless time.is_a?(Integer) && (1..SAFE).cover?(time)
        end
      when :active_request_id
        uuid!(value) unless value.nil?
      else uuid!(value)
      end
      out[key.to_s] = value
    end
    if method == 'consume'
      out['params'] = { 'event_id' => out.delete('event_id'), 'request_id' => out.delete('request_id'),
                        'active_request_id' => out.delete('active_request_id'), 'descriptor' => nil }
    end
    JSON.generate(out)
  rescue Failure
    raise
  rescue StandardError
    raise Failure.new, cause: nil
  end

  # Owner-review consume only: no output credential or automatic descriptor.
  def exchange(credential:, **request)
    attempted = false
    raise Failure unless credential.is_a?(String) && /\Aztr_[A-Za-z0-9_-]{43}\z/.match?(credential)
    decoded = Base64.urlsafe_decode64(credential[4..] + '=')
    raise Failure unless decoded.bytesize == 32 && Base64.urlsafe_encode64(decoded, padding: false) == credential[4..]
    body = self.class.body(**request)
    http = Net::HTTP.new(@uri.host, @uri.port, nil) # Explicitly ignore environment proxies.
    http.use_ssl = true
    http.min_version = OpenSSL::SSL::TLS1_2_VERSION
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_hostname = true
    http.cert_store = @store
    http.max_retries = 0
    http.open_timeout = http.read_timeout = http.write_timeout = @timeout
    message = Net::HTTP::Post.new(@uri.request_uri)
    message['Authorization'] = 'Bearer ' + credential
    message['Content-Type'] = 'application/json'
    message['Cache-Control'] = 'no-store'
    message.body = body
    raw = +''
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    attempted = true
    Timeout.timeout(@timeout) do
      http.start do |session|
        session.request(message) do |response|
          raise Failure unless response.code.to_i.between?(200, 299) && response.content_type == 'application/json'
          raise Failure if response.content_length && response.content_length > MAX
          response.read_body do |chunk|
            raise Failure if raw.bytesize + chunk.bytesize > MAX
            raw << chunk
          end
          raise Failure if response.content_length && raw.bytesize != response.content_length
        end
      end
    end
    raw.force_encoding(Encoding::UTF_8)
    raise Failure unless raw.valid_encoding?
    parsed = JSON.parse(raw, object_class: UniqueObject, max_nesting: 64, allow_nan: false)
    raise Failure unless parsed.is_a?(Hash) && parsed.keys.sort == %w[kind result] && parsed['kind'] == request[:method]
    result = Wire.new(untrusted_json: JSON.generate(parsed['result']).freeze).freeze
    raise Failure if Process.clock_gettime(Process::CLOCK_MONOTONIC) - started >= @timeout
    result
  rescue StandardError
    raise Failure.new(attempted && request[:method] == 'consume'), cause: nil
  end
end
end
