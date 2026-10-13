# Experimental Ruby Windows protected recipient

`ProtectedRecipient` uses standard-library Fiddle on a 64-bit Windows Ruby to
operate a Microsoft Platform Crypto Provider P-256 recipient. It resolves NCrypt
through the actual System32 directory and requires the provider hardware bit,
zero export policy, private export denial, exact public blob and curve, and real
ECDH agreement against an independent OpenSSL peer. No software fallback exists.
This is local qualification, not remote attestation or protection against code
that compromises the Ruby process.

The callable recipient interface is a trusted application adapter and makes no
custody assertion by itself. Existing OpenSSL readers retain their public-key
binding. Protected calls use the same HPKE schedule and manifest/election checks.
The private scalar stays in the provider, but shared secrets and plaintext enter
Ruby memory. Clearing strings does not guarantee physical erasure of all copies.

Creation requires a callback that writes and flushes a durable pending-alias
receipt before native creation. `close` releases handles without deleting a
persistent key. Only the creating instance can `delete_created`. Reopening binds
an independently trusted public point and does not permit deletion. Preserve
receipts after failed cleanup and verify application ownership before recovery.

Run with the independently pinned maintained TypeScript producer directory and
a fresh receipt path outside the public checkout:

```text
ruby sdk/native/crypto-envelope/ruby/custody/custody_test.rb PRODUCER_DIRECTORY PENDING_RECEIPT
```

The test probes capability before key creation. Unavailable capability reports
`UNQUALIFIED`; any later failure fails. It creates a synthetic key, asks the
producer to encrypt profile02 inbound/outbound and profile03 to its public point,
requires selected private scalars to be absent, checks authority/public binding
and lifecycle refusals, and deletes only the owned key. Hosted CI without PCP
capability establishes refusal only. Other platforms/providers, 32-bit Ruby,
protected signing/composition and package-consumer acceptance remain separate.
