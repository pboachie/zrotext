# Ruby webhook companion

Source-only helper for Ruby 3.2+ with its OpenSSL standard library. Add `lib` to
your load path and require `zrotext/webhook`. No third-party gems are required.

```ruby
require 'base64'
require 'zrotext/webhook'
Zrotext::Webhook.verify(
  signing_key: Base64.urlsafe_decode64(signing_secret_base64url),
  timestamp: timestamp_header, signature: signature_header, body: raw_request_body
)
```

Supply exactly 32 decoded secret bytes and the raw request string before JSON
parsing. Its encoding label does not change the bytes authenticated. Canonical
headers, the inclusive symmetric 300-second window and constant-time HMAC-SHA256
comparison are enforced. `VerificationError#reason` identifies refusals without
including secrets or bodies. Synchronize the clock and deduplicate verified
event IDs. No sealed-envelope cryptography, replay database or SMS delivery
guarantee is supplied. This helper is not published to RubyGems.

From the repository root:

```sh
ruby sdk/native/ruby/test_webhook.rb sdk/native/webhook-vectors.tsv
```
