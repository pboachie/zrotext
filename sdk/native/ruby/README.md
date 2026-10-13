# Ruby webhook companion

Experimental helper for Ruby 3.2+ with its OpenSSL standard library. The candidate
gem is `zrotext-webhooks` version `0.1.0.alpha.1`; require `zrotext/webhook` after
installation. No third-party gems are required.

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


Build the licensed archive and run its isolated installed consumer:
`python sdk/native/package-webhooks.py --target ruby --out <external-directory>`.
Use `gem install --local <archive.gem>` to install the resulting candidate. The
acceptance helper removes source staging before installation, checks the loaded
module belongs to the isolated gem directory and runs every shared vector.
Nothing is published to RubyGems by this command.
