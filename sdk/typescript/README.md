# Experimental sealed draft-01 TypeScript reader

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


This is one slice of ZT-010 evidence. Independent Rust cross-open, full manifest
chain/rollback vectors, production key lifecycle, and the Q1–Q11 decisions
remain separate gates. The candidate profile says vectors must be regenerated
after those decisions and versioning.
