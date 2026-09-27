# Dormant Android outbound envelope verification

`Draft02OutboundEnvelope` verifies candidate-02 outbound ciphertext in Android's
main source set. No app, service or message flow calls it. It accepts only profile
02, kind 01, zero flags and the exact bounded binary representation. It neither
negotiates another profile nor retries through the synthetic-alpha path.

The factory requires an already verified `Draft02ManifestAuthority`, a separately
selected immutable route/reader request and a caller-supplied trusted-time function.
It obtains fresh manifest context and checks the exact account, message, device,
line, peer, manifest version/digest, signer and ordered reader set. No received
signer point or relay directory is promoted to trusted authority.

The parser bounds allocation to 34,213 received bytes and checks every length and
EOF, positive identities/version, signed-64 storage limits, outbound intent,
canonical peer encoding, uncompressed on-curve P-256 encapsulations and exact
device/archive/integration cardinality. It requires canonical low-s P-256 ECDSA
over `ZTSE/sign/v2\0 || u32(unsigned_length) || exact_received_unsigned_bytes`.
It does not normalize received signatures or reserialize fields for verification.

Outbound expiry is exclusive; its signed interval is positive and at most fifteen
minutes, and observed time may be at most five minutes ahead of trusted current
time. Subtractions occur only after safe ordering checks. After signature work the
factory rechecks manifest/key context and envelope freshness with a non-regressing
current time. All received bytes are copied before any caller callback runs.

Only the factory constructs the immutable ciphertext result. Its byte-array getters
return copies and its string representation contains no routing or message data.
The replay identity is SHA-256 of the exact unsigned envelope, excluding the
randomized signature. The low-level signature helper produces only a boolean for
the independent signature corpus; it cannot construct the trusted-context result.

## Verification boundaries

The shared JVM and no-radio device corpus verifies a byte-for-byte copy of the
reviewed independent Node WebCrypto fixture from
`protocol/v1/vectors/ztse-draft-02-signatures.json` at commit
`437d5438bc24a102d698e3a7f33a4f845e441c09` (introduced by PR302). The Android resource
`candidate02-outbound-signatures.json` is pinned by SHA-256 and a narrow LF rule;
the unchanged draft-01 unsigned fixture supplies its opaque structural ciphertext.
These are signature vectors, **not decryptable candidate-02 envelopes**.

The corpus also creates signed manifests and freshly signed semantic negatives to
separate authorization rejection from invalid signatures. It covers wrong routes,
manifest identities, signers/readers, revoked or expired keys, final-time expiry,
malformed bounds, wrong domains/profiles, high-s/scalar rejection, maximum body and
reader counts, ciphertext mutations and caller-array aliases. The device runner
requires the ten selected tests to complete with zero failures or skips.

The result records verification at a point in time. It is not a durable grant,
replay reservation, decryption permission or radio capability. A future caller must
reverify current durable trust/freshness and atomically bind current line generation,
session/grant state and journal identity before any effect. A stale retained result
must not bypass those checks. Trusted time is an input, not an implemented provider.
Root comparison UI, owner-key custody/recovery, reboot/restore freshness, durable
replay/effect journals and the live grant bridge remain separate prerequisites.

This module performs no Keystore operation, HPKE unwrap, body decryption or text
decoding, persistence, network operation, permission request or SMS operation. The
general sealed runtime stays disabled. JVM/emulator verification provides no
physical SIM, carrier-delivery or production recovery evidence and completes no
roadmap capability by itself.
