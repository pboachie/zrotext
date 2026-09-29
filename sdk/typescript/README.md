# ZROtext sealed TypeScript SDK

Status is per module, and the boundaries are deliberate:

- **Production-shaped: envelope composition** (`src/sealed-envelope.ts`,
  issue #537 slice A). `composeSealedOutboundEnvelope` composes one complete
  sealed outbound kind-01 profile-02 candidate envelope from explicit caller
  inputs and returns the exact bytes with the SHA-256 digest of the unsigned
  envelope. It is verified byte-for-byte against the cross-client vectors the
  Rust verifier lane consumes (see below).
- **Still test-only:** the draft-01 reader, the profile-02 manifest
  verifier/trust store, the draft-02 envelope preparation helper, and the
  message-plane client described in the sections below.
- **Does not exist yet:** an HTTP client for `/v1/sealed/messages`
  (`SealedMessagePlaneClient` is a test-only contract exercise, not the
  production client), inbound kind-02 composition in the production module,
  and any npm publication. This package is not published anywhere.

The profile-02 byte format itself remains an unaccepted candidate and the
server's sealed route stays disabled by default; nothing in this SDK enables
a server route, and composing an envelope is never carrier submission.

## Production envelope composition (issue #537 slice A)

`composeSealedOutboundEnvelope(input)` performs fail-closed validation with
typed `SealedEnvelopeError` failures (a `code` discriminator plus stable
detail strings mirroring the Rust parser's own refusal reasons), authorizes
the request against the exact manifest object `verifyManifest02` returned,
and only then composes: strict UTF-8 body (1–32,768 bytes, no BOM, no NUL,
no normalization) under AES-256-GCM with the `ZTSE/body/v2` transcript, HPKE
P-256 recipient wraps in strict `(role, key_id)` wire order with the
`ZTSE/wrap/v2` transcript, and a canonical low-`s` ECDSA P-256 signature over
`"ZTSE/sign/v2\0" || u32(len(unsigned)) || unsigned`. The result is bounded
to the server parser's kind-01 window (426..=34,213 bytes inside the
36,864-byte cap) with exactly one device wrap and one archive wrap; anything
that cannot produce an admissible envelope — wrong identity widths, a
non-E.164 peer, out-of-range or misspaced timestamps, an empty or oversized
body, malformed key material, duplicate or misroled recipients, a wrap count
outside 2..=8, or an unauthorized signer or reader set — is refused, never
coerced. The wire layout is produced by delegating to the reviewed
`prepareOutboundEnvelope02` helper, so the bytes are exactly the ones the
cross-client CI lane feeds to the Rust admission parser.

The returned object carries only the `envelope` bytes and the
`unsignedDigest`. That digest is the Q6 idempotency identity: retries must
resend the same exact envelope bytes and reuse this digest, never
`idempotency-key` headers. Two compositions of the same message are two
different identities by design, because the content key, body nonce and every
HPKE ephemeral IKM are drawn fresh from `crypto.getRandomValues`. The
optional `deterministicKeyMaterial` input exists only to reproduce
cross-client vectors; production callers must omit it. Local key-material
copies are zeroed on every exit path, but JavaScript gives no erasure
guarantee — the engine may have copied those buffers, the delegated helper
holds its own snapshot until the promise settles, and the body `content`
string cannot be zeroed at all. No plaintext or key material is retained on
the returned object.

Verification: `test/sealed-envelope.test.mjs` walks every parser rule
byte-by-byte against the dormant Rust reader
(`crates/server/src/sealed_envelope`, `sealed_body`), verifies the signature
over the exact unsigned bytes with the existing draft-02 helpers, reopens
wraps and body as an independent consumer from envelope bytes alone, pins the
deterministic unsigned transcript, and regenerates the cross-client fixture
through `test/support/generate-cross-client.mjs` — the generator the Rust CI
lane drives — proving the production module reproduces the exact unsigned
bytes and digest of envelopes the Rust lane admits, persists and replays.
That Rust lane itself was not executed as part of this slice; the byte
equality and the parser-mirror walk are the local evidence.

`SEALED_CONTENT_TYPE` (`application/vnd.zrotext.sealed.v1`) is exported for
callers that transport the bytes themselves. This module contains no network
client, no send path and no server dependency; slice B is the HTTP client.

## Test-only sealed draft-01 TypeScript reader

This is a **test-only implementation of the unapproved ZT-009 byte candidate**.
It must not be published as a production SDK or connected to a send, inbound,
webhook, or radio path. Draft 01 has no trusted manifest bootstrap, approved
role/scope policy, revocation freshness, replay store, or production Android
Keystore HPKE path. The `manifestDigest` in the shared fixture is synthetic, not a real
owner-signed manifest.

`parseDraftEnvelope` bounds and reads the exact candidate binary layout.
`openDraftEnvelope` requires the caller to supply independently trusted
account/device/line/peer, signer point, manifest digest and recipient key. It
checks the raw origin signature, HPKE P-256 recipient wrap with nonempty `info`
and AAD, and AES-256-GCM body AAD before returning strict UTF-8. It does not
authorize a signer or line, validate manifest history, decide accepted clock
skew, check replay/expiry against wall time, or count SMS segments. A caller
must not treat a successful open as permission to send SMS.
`openDraftEnvelope`, `wrapInfo` and the draft-02 `enrollRootPin02`,
`verifyManifest02` and `verifyRootTransition02` copy their byte and context
inputs when called; changing those buffers while a call is pending does not
affect it.

From this directory run `npm ci --ignore-scripts` then `npm test`. The locked
dependency graph pins `@hpke/core` 1.7.5, above the nonce-reuse advisory's
affected range, and TypeScript 5.9.3. The RFC 9180 Appendix A.3.1 known answer
checks sender `enc`/ciphertext and recipient opening. Candidate outbound and
inbound fixtures exercise the same bytes in TypeScript and Python; the
re-signed mutation tests probe HPKE/body transcript binding after a valid
origin signature. `test/generate-vectors.mjs` uses fixed public test keys,
content keys, nonce and HPKE ephemeral inputs. Web Crypto ECDSA signing may
produce a different valid signature when regenerated; committed signature
bytes are fixed for consumers.

For an optional **emulator-only** browser-to-Keystore outbound envelope check, build
`android/:app:assembleDebug` and `:app:assembleDebugAndroidTest`, install those
two APKs onto an API 31+ AVD at `emulator-5554`, set `ANDROID_HOME`, then run
`npm run test:android-keystore` here. The script checks `ro.kernel.qemu=1` and
refuses a physical serial. It generates a temporary non-exportable P-256
Keystore key, replaces the device wrap in the pinned outbound draft fixture
using independent `@hpke/core` and its nonempty `info` and AAD, then signs the
new envelope with the fixture's public test identity. Android parses bounded
envelope bytes, checks the exact signature transcript against the pinned public
fixture signer, opens the device wrap and body, rejects altered HPKE inputs,
invalid encapsulation, wrong key ID, truncation, trailing bytes and a lost
recipient key, and removes the test alias in a `finally` cleanup. Uninstall
the test APKs when finished. Android does not establish signer authority from
a trusted manifest in this harness. This is test-only custom composition, not a
maintained production provider.

`canonicalP256Signature` demonstrates a proposed low-`s` sender conversion;
it does not alter draft-01 acceptance. The pinned outbound draft-01 signature
is valid high-`s`. Enforcing low-`s` requires a new profile revision and
regenerated vectors.

## Draft-02 trust store clock and recovery semantics

`Draft02TrustStore` (`src/draft02-trust-store.ts`) is a test-only IndexedDB
adapter for the profile-02 candidate. It persists the enrolled owner root, the
manifest version/digest ratchet, and a time high-water `lastTrustedTimeMs`.
Every write is a compare-and-swap against the snapshot the caller started from.

- **Enrollment** carries no owner-signed time, so `enroll` stores a time
  high-water of `0`; `nowMs` is only range-checked.
- **Backward steps** of up to `DRAFT02_CLOCK_SKEW_MS` (five minutes) below the
  high-water are accepted, so NTP slews and small corrections keep working. The
  high-water itself never moves backwards. A larger step fails with
  `clock moved backwards`.
- **Forward jumps** cannot run the ratchet away. A far-future `nowMs` fails the
  manifest or transition validity window and persists nothing. For an accepted
  object the stored time is at most its signed `issuedMs` plus
  `DRAFT02_CLOCK_SKEW_MS`, so a corrected clock is still within tolerance.
- **Recovery is explicit.** Each method below needs caller intent and never runs
  automatically:
  - `resetTrustedTime(current, nowMs)` sets the time high-water to `nowMs`
    (possibly earlier) and keeps the root and version/digest ratchet. Use it
    only when the caller has independent reason to trust `nowMs`.
  - `reenroll(current, rootPin, comparedFingerprint, nowMs)` replaces the
    enrolled root and discards the version and time ratchet. Compare the
    fingerprint through a channel independent of the relay, as for `enroll`.
  - `clearCorruptState()` deletes the stored row only if it fails to decode
    (corrupt, or an unknown schema) and returns whether it deleted one. It
    refuses to remove a valid enrollment; call `enroll` afterwards.

  `current` must equal the snapshot returned by `read()`. A stale or edited
  snapshot fails with `stale or corrupt state`, so a caller cannot discard
  anti-rollback state it has not read. Deleting the IndexedDB database by hand
  also discards that state and is not a supported recovery path.
- **Schema upgrades** from another tab or a newer version close this
  connection (`onversionchange`) instead of blocking the upgrade. Later calls on
  that instance fail; open the store again.

The caller's clock is still not independently trusted, and browser storage
can be deleted, evicted, or restored from an older copy. Production use needs
an authenticated freshness checkpoint; see the
[profile-02 manifest candidate](../../protocol/drafts/zt-sealed-draft-02-manifest-candidate.md).

## Test-only message-plane client (task 21 slice 3)

`src/msgplane-client.ts` binds to the slice-1 sealed message-plane contract
([protocol/v1/sealed-api-v1.md](../../protocol/v1/sealed-api-v1.md) and its
[OpenAPI document](../../protocol/v1/openapi/sealed-v1.json)), which is a
proposal with **no mounted server route**. It is test-only evidence toward
task 21, not a production SDK. `SealedMessagePlaneClient` posts the exact
envelope bytes of one draft-01 envelope with the single allowed content type
`application/vnd.zrotext.sealed.v1` to `/v1/sealed/messages` (kind 01) or
`/v1/sealed/inbound-events` (kind 02), validates bounded syntax and the kind
locally through `parseDraftEnvelope` before any transport call, and never
sends a caller-supplied `idempotency-key` header: the unsigned-envelope digest
is the identity (Q6). Responses map onto the contract's taxonomy as
`SealedApiError` with a `retryable` classification; only `rate_limited`,
`queue_full`, `quota_exceeded`, `billing_pending` and `unavailable` are
retryable, and `withRetry` resends with a pinned digest guard, refusing a
mutated envelope instead of silently sending different bytes. Off-taxonomy
statuses and malformed bodies surface as `unexpected_response`. The client
has no plaintext path and no method for the synthetic-alpha route; origins
carrying a path, query or credentials are refused at construction. Tests use
the pinned draft-01 vectors against a recording transport and no network.


## Test-only profile-02 envelope preparation (task 113)

`src/draft02-envelope-prep.ts` composes complete candidate-02 sealed envelopes
for tests. It is **not a production SDK path** and is connected to no send,
inbound, webhook, or radio route. The production composition API above
delegates to it after its own validation, so its reviewed byte layout and
authorization ordering are the single source of both test and production
bytes. `prepareOutboundEnvelope02` and `prepareInboundEnvelope02` require the
exact `Manifest02` object returned by `verifyManifest02` and call
`authorizeOutbound02` / `authorizeInbound02` with claims derived from that
manifest before any body encryption, HPKE wrap, or signature is produced: a
revoked signer, wrong role/scope, stale manifest, copied manifest object, or
unauthorized reader set refuses fail-closed. Authorization is reused from
`draft02-manifest.ts`, never re-implemented here; key IDs are reused from the
draft-01 `keyId` helper (`ZTSE/key/v1\0`, `0x0010` for KEM recipients,
`0x0101` for signers).

The bytes follow the dormant profile-02 rules exactly: wire `profile:u8 = 02`,
HPKE `info = "ZTSE/wrap/v2\0" || header || protected || role || key_id` with an
**empty** AAD (draft-01's nonempty wrap AAD is intentionally not used),
`body_aad = "ZTSE/body/v2\0" || header || protected`, AES-256-GCM body over
strict UTF-8 (1-32768 bytes, no BOM, no NUL), and a canonical low-`s` ECDSA
P-256 origin signature over `"ZTSE/sign/v2\0" || u32(len(unsigned)) ||
unsigned`. Outbound expiry (`observed < expires <= observed + 900000`) and
inbound event identity (`messageId == eventId`, `localSequence` 1..2^63-1)
mirror the reader. The content key, body nonce, and each wrap's HPKE ephemeral
IKM are caller-supplied deterministic test inputs, so all unsigned bytes are
reproducible; Web Crypto ECDSA signatures vary per run, and the module returns
the unsigned transcript and its SHA-256 alongside the envelope. Recipient wraps
are emitted in strict `(role, key_id)` wire order and each wrap's `key_id` must
match its own point, so the emitted wrap set is exactly the manifest-authorized
set. Every caller-held input (byte arrays, recipient entries, scalars, and the
manifest field values used for composition) is deep-copied into an owned
snapshot synchronously before the first `await`; the order from there is
public identity hashing, then `authorizeOutbound02` / `authorizeInbound02`
against the exact verified manifest object, then encryption, wrapping, and
signing. Mutating
the input objects after the call therefore cannot redirect an envelope that
authorization already approved. Tests pin the full outbound and inbound unsigned
transcripts, reopen a wrap and the body as an independent consumer, verify the
signature and its low-`s` form, and exercise the denial corpus, including
post-call input mutation. No Rust cross-verification or
Android run is part of this slice; those remain separate gates.

`test/support/generate-cross-client.mjs` builds the cross-client fixture the
Rust CI lane consumes: it verifies a fully signed synthetic manifest,
composes the fixture envelopes through `prepareOutboundEnvelope02`, re-signs
adversarial mutations so each one exercises its intended check, and
cross-checks that `composeSealedOutboundEnvelope` fed the same material
reproduces the exact unsigned bytes and digest. Setup JSON arrives on stdin
and the fixture leaves on stdout; optional pinned key-material fields let a
caller reproduce the fixture deterministically, and the Rust lane omits them.

This is one slice of ZT-010 evidence. Independent Rust cross-open, full manifest
chain/rollback vectors, production key lifecycle, and the Q1–Q11 decisions
remain separate gates. The candidate profile says vectors must be regenerated
after those decisions and versioning.
