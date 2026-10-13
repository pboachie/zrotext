# Outbound profile03 time policy

Java, C# and Ruby outbound03 composition and readers require every selected signer and reader key to
cover the entire signed interval `[observed_ms, expires_ms)`. Equality at the key
start or end is permitted; current authorization still requires `now < key_until`
and `observed <= now < expires`. Manifest freshness, accepted election, permission
deadline and durable comparison-clock checks remain required.

Manifest `issued_ms` is not an additional lower bound on observation. A signed
manifest may be issued within the permitted future-skew window while its selected
keys already cover the message lifetime. This aligns outbound03 with the reviewed
clarification and shared cases under [#1226](https://github.com/pboachie/zrotext/issues/1226).
Profile02 and inbound historical authorization are unchanged.

`time-policy-run.py --language java --producer CHECKOUT --producer-pin FULL_SHA`
builds the native composer/reader policy consumer and checks a clean, explicitly pinned maintained
TypeScript producer. Use `csharp` or `ruby` for the other languages. Build the
producer's TypeScript SDK first. Java downloads checksum-pinned JNA unless `--jna`
is provided; Ruby accepts an explicit `--ruby` executable.

Before native creation, a software reader batch checks every shared policy case
using fully signed/encrypted inputs independently opened by the producer. Invalid
lifetime cases therefore cannot pass merely because a mutated AAD breaks AEAD.
Every accepted native composition is also opened by the native outbound reader.

The suite creates one native PCP signer after a read-only capability probe and
passes only its public point to the shared producer. Every case contains genuine
signed manifests and accepted dual-signature election evidence. Each native
consumer verifies this evidence before entering the expected composition-refusal
catch, avoiding false success from malformed fixture provenance. The driver
requires an exact result for every shared case and independently verifies and
decrypts all three recipients of every accepted ciphertext with maintained
TypeScript. It refuses any fixture containing a signer scalar.

`--require-hardware` makes unavailable native signing capability fatal. Without
that option, precreation refusal is explicitly `UNQUALIFIED`, not a completed
policy test. Once creation starts, failures are fatal and owned cleanup receipts
remain until deletion succeeds. No key is exported, no live request is sent, and
this test does not establish remote attestation or production permission.
