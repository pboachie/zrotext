# ZROtext sealed TypeScript SDK

Status is per module, and the boundaries are deliberate:

- **Production-shaped: envelope composition** (`src/sealed-envelope.ts`,
  issue #537 slice A). `composeSealedOutboundEnvelope` composes one complete
  sealed outbound kind-01 profile-02 candidate envelope from explicit caller
  inputs and returns the exact bytes with the SHA-256 digest of the unsigned
  envelope, drawing the content key, body nonce and every HPKE ephemeral IKM
  fresh from the Web Crypto CSPRNG. It is verified byte-for-byte against the
  cross-client vectors the Rust verifier lane consumes, and its fresh-material
  output is admitted by the strict server route and verified by the Android
  verifier in the sealed cross-client CI lane (see below).
- **Production-shaped: sealed submission client** (`src/sealed-client.ts`,
  issue #537 slice B). `SealedClient.submitSealedMessage` posts one composed
  envelope to `POST /v1/sealed/messages` as the exact raw request body, with
  contract-pinned retries and a typed error taxonomy, exercised against an
  in-process mock server that asserts the wire format (see below).
- **Still test-only:** the draft-01 reader, the profile-02 manifest
  verifier/trust store, and the message-plane client described in the
  sections below. The draft-02 envelope preparation module is the internal
  wire-layout core the production composer delegates to; only its optional
  pinned-material override is test-only.
- **Does not exist yet:** inbound kind-02 composition in the production
  module, and any npm publication. This package is not published anywhere.

The profile-02 byte format itself remains an unaccepted candidate and the
server's sealed route stays disabled by default; nothing in this SDK enables
a server route, and composing an envelope is never carrier submission. An
operator can mount the admission route with `SEALED_ADMISSION_ENABLED=true`,
so the production client is only usable against such an operator-enabled
deployment; against a default deployment every submission fails, by design.

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
HPKE ephemeral IKM are drawn fresh from `crypto.getRandomValues` on every
call. There is no way to pin that material on the production API: the public
input type has no such field, the production function refuses an input that
still carries a `deterministicKeyMaterial` property at runtime, and
reproducible vector material exists only on the clearly-marked test seam
`src/sealed-envelope-vectors.ts` (backed by the internal core in
`src/sealed-envelope-internal.ts`), which only test files import. Local
key-material copies are zeroed on every exit path, but JavaScript gives no
erasure guarantee — the engine may have copied those buffers, the delegated
helper holds its own snapshot until the promise settles, and the body
`content` string cannot be zeroed at all. No plaintext or key material is
retained on the returned object.

Verification: `test/sealed-envelope.test.mjs` walks every parser rule
byte-by-byte against the dormant Rust reader
(`crates/server/src/sealed_envelope`, `sealed_body`), verifies the signature
over the exact unsigned bytes with the existing draft-02 helpers, reopens
wraps and body as an independent consumer from envelope bytes alone, pins the
deterministic unsigned transcript through the test seam, and regenerates the
cross-client fixture through `test/support/generate-cross-client.mjs` — the
generator the Rust CI lane drives — proving the production module reproduces
the exact unsigned bytes and digest of envelopes the Rust lane admits,
persists and replays. A dedicated test proves the production path draws
fresh CSPRNG bytes on every composition: two compositions of the same message
differ in every key-dependent region (envelope bytes and Q6 digest included,
because the digest covers the full unsigned bytes), the key-independent
header-plus-protected prefix stays identical, and the body nonce, the
recovered content key and every wrap's ephemeral KEM point are never the
all-zero values an all-zero RNG would produce; that mutant is exactly what
the test was checked against. Finally, the sealed cross-client CI lane
(`.github/workflows/sealed-interop.yml`) feeds the generator's
production-path envelope — composed by `composeSealedOutboundEnvelope` with
no pinning — through the strict server admission route
(`crates/server/src/http_sealed` over `sealed_outbound::admit_candidate02`,
`cross_client_interop.rs`) and through the Android verifier
(`SealedSdkPostgresInteropTest`), so SDK-composed bytes are refused by
neither.

`SEALED_CONTENT_TYPE` (`application/vnd.zrotext.sealed.v1`) is exported for
callers that transport the bytes themselves. This module contains no network
client, no send path and no server dependency; the HTTP client is
`src/sealed-client.ts` (slice B).

## Production sealed submission client (issue #537 slice B)

`new SealedClient({ baseUrl, apiToken, timeoutMs?, retry? })` submits one
composed envelope to `POST /v1/sealed/messages`. The constructor refuses
anything but a bare HTTPS origin (no path, query, fragment or embedded
credentials) and a printable nonempty API token. The token is sent only in the
`Authorization: Bearer` header: it never enters a URL, a query string or any
error output.

`submitSealedMessage(envelope, unsignedDigest)` sends the exact bytes from
`composeSealedOutboundEnvelope` as the entire request body — never
JSON-encoded, never base64, never anything alongside — with `Content-Type:
application/vnd.zrotext.sealed.v1` byte-exact and **no `idempotency-key`
header**: the Q6 identity is the unsigned digest carried inside the bytes, and
the server refuses a caller-supplied key. The digest is verified locally
against the unsigned envelope before anything leaves, so a mismatched pair
whose reported identity would lie is refused with no request. A `202` returns
`{ messageId, created }`; `created: false` is the exact-digest replay no-op.

Retry semantics: only network failures that never got a response, `503`
(`unavailable`/`billing_pending`) and `429 rate_limited` are retried, bounded
by `maxAttempts` with the server's `Retry-After` honored up to the
`maxDelayMs` ceiling, and every retry resends the very same `Uint8Array`
object. All 4xx admission failures — including `queue_full` and
`quota_exceeded`, which immediate retries cannot help and only worsen — are
terminal, as is a per-attempt timeout: the outcome is then unknown, so the
client surfaces it instead of auto-retrying and lets the caller decide
whether to replay the same digest identity. Exhausted retries throw the last
typed error. `409 idempotency_conflict` exposes both the sent digest and the
server code, and the client never recomposes or resends after it.

Failures are typed `SealedClientError` values (guarded by
`isSealedClientError`) mirroring the server's codes — `invalid_request`,
`unauthorized`, `forbidden`, `idempotency_conflict`,
`unsupported_media_type`, `rate_limited`, `queue_full`, `quota_exceeded`,
`billing_pending`, `unavailable` — plus `network`, `timeout` and the
fail-closed `unexpected_response` for off-taxonomy statuses, unknown codes
and malformed bodies: never a crash, never a silent success.

Verification: `test/sealed-client.test.mjs` runs the client against an
in-process `node:http` server that asserts the exact wire format (byte-exact
content type with no parameters, exactly one such header, no idempotency
header in any casing, raw body byte identity, Bearer-only authentication, no
token in URLs or error output) and scripts every response — replays, each
terminal code, Retry-After handling and bounding, retry exhaustion, socket
destruction, timeouts and malformed bodies. No live server is involved, and
none can be by default: the real route is mounted only behind the operator
flag, acceptance remains durable storage and queueing, and it is never
carrier evidence.

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

`src/sealed-lifecycle-client.ts` provides metadata-only list/status and empty-body
pre-grant cancellation for the default-off sealed queue. `SealedLifecycleClient`
requires an HTTPS origin and scoped bearer, bounds response bytes/pages, rejects
extra content fields, and never retries an uncertain cancellation automatically.
It provides no ciphertext fetch or execution grant. See the current
[lifecycle contract](../../protocol/v1/sealed-api-v1.md).

`src/msgplane-client.ts` binds to the slice-1 sealed message-plane contract
([protocol/v1/sealed-api-v1.md](../../protocol/v1/sealed-api-v1.md) and its
[OpenAPI document](../../protocol/v1/openapi/sealed-v1.json)). It is
**test-only evidence toward task 21, not a production SDK**: the production
submission client is `src/sealed-client.ts` above. The server route it
mirrors is mounted only when an operator sets `SEALED_ADMISSION_ENABLED=true`
and stays absent from default deployments. `SealedMessagePlaneClient` posts
the exact
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


## Profile-02 envelope preparation (wire-layout core)

`src/draft02-envelope-prep.ts` composes complete candidate-02 sealed envelopes
and is the internal wire-layout core the production composition API above
delegates to. Its production bytes are admitted by the server's sealed
admission route (`POST /v1/sealed/messages`, behind the default-off
`SEALED_ADMISSION_ENABLED` flag, PR #545) and by no synthetic-alpha, plaintext,
or radio route. The reviewed byte layout and
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
cross-checks that the test seam fed the same pinned material reproduces the
exact unsigned bytes and digest. It also composes one envelope through the
production entry point with fresh CSPRNG material and no pinning; those are
the bytes the Rust lane posts through the strict server admission route and
the Android verifier verifies downstream. Setup JSON arrives on stdin and the
fixture leaves on stdout; optional pinned key-material fields let a caller
reproduce the fixture deterministically, and the Rust lane omits them.

This is one slice of ZT-010 evidence. Independent Rust cross-open, full manifest
chain/rollback vectors, production key lifecycle, and the Q1–Q11 decisions
remain separate gates. The candidate profile says vectors must be regenerated
after those decisions and versioning.

The [local stdio MCP server](../../docs/mcp-local-tools.md) exposes SDK syntax previews and gated tool discovery; live scoped messaging remains unavailable.

The [synthetic agent adapter foundation](../../docs/agent-adapter-simulator.md) adds callable fixture handling and a Python wrapper over this SDK. It cannot activate live messaging or grant agent authority.

## Workflow context candidate

`workflow-context.ts` seals and opens proposed ZTWC01 contexts using the existing
HPKE implementation and a just-verified role-2 archive reader. It performs no
networking, persistence, private-key generation or dispatch activation. The
server's owner router remains unmounted. See
[`workflow-context.md`](../../protocol/v1/workflow-context.md) for exact authenticated
identity, version, ciphertext, exception and retention boundaries.

`workflow-decisions.ts` supplies the complete `workflow-action-01` canonical
descriptor and SHA-256 binding for customer proposals. It rejects missing or
unknown fields and snapshots inputs before hashing. TypeScript integers must be
safe integers. Computing a binding or reading historical action state grants no
approval, content-reader or dispatch authority. The durable decision service
remains a separate candidate implementation; this codec performs no networking.
The [customer assistant routine candidate](../../docs/customer-assistant-routines.md)
adds a default-off customer-side proposal runner with durable provider budgets,
selected-reader adapters and crash-safe uncertain outcomes. Live workflow and
provider integration remains unavailable; generated actions always require
separate exact owner confirmation.
