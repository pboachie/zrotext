# frozen_string_literal: true
require 'json'
require 'zrotext_sdk'

input = JSON.parse($stdin.read)
auth = input.fetch('auth') ? {
  'ownerSession' => { '__Host-zrotext_session' => 'synthetic-session', '__Host-zrotext_csrf' => 'synthetic-csrf', 'origin' => 'https://example.test' },
  'bearerAuth' => 'synthetic-bearer', 'workflowCredential' => 'ztw_synthetic'
} : {}
client = ZrotextSdk::ZrotextClient.new(base_url: input.fetch('base'), auth: auth, timeout_ms: 1500, validate_responses: 'strict')
options = { idempotency_key: input['key'] }
if input['confirm']
  preview = client.dispatch.preview_operation(input.fetch('operation'), input.fetch('args'), options)
  if preview.is_a?(Tungsten::Runtime::Err)
    puts JSON.generate(preview.error.to_h)
    exit
  end
  options[:confirm] = preview.value.confirmation_token
end
result = client.dispatch.invoke(input.fetch('operation'), input.fetch('args'), options)
puts JSON.generate(result.is_a?(Tungsten::Runtime::Err) ? result.error.to_h : { ok: true })
