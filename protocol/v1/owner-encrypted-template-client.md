# Dormant owner encrypted-template client

`OwnerEncryptedTemplateClient` is a customer-browser transport for the existing
[encrypted-template persistence candidate](encrypted-template.md). The server
router remains unmounted in main. This module does not make templates available
in an application, authenticate an owner, issue keys, decrypt content, approve,
schedule or send. Its receipt acknowledges an encrypted stored revision only.

The caller keeps its existing owner authentication, reader/key ceremony and
plaintext review. It uses `sealEncryptedTemplate` before supplying ciphertext.
This client reuses `encryptedTemplateAad`, `encryptedTemplateDigest`,
`templateSaveRequest`, `templateSaveReceipt` and the existing branded manifest
verification/authorization helpers. ZTWT is never relabelled as workflow-context
ciphertext. No generic context client, alternate identity registry or new wire
contract is introduced.

## Host and lifecycle

Construction is dormant unless `enabled: true` is explicitly selected. The host
supplies an exact HTTPS same-origin origin, a copied
`ConversationSignerBinding02`, one template ID, and these callbacks:

- `readCurrent`: authenticated current owner/session, consent, active interval
  phase, the selected binding, a branded SDK-verified manifest, authoritative
  monotonically advanced UTC `nowMs`, and a finite `validForMs` of at most one
  minute. These are an independently implemented host contract; assertions from
  model output, an HTTP body or an arbitrary JavaScript object are insufficient.
- `currentCsrf`: the current session's bounded nonempty CSRF value, synchronously
  or asynchronously. It is compared through the lifecycle, never returned in a
  receipt or given to an agent.
- `consumeCiphertextReview`: consume a decision tied to an exact copied request
  ID, expected revision, template scope and encrypted envelope digest. This is
  metadata/ciphertext review, **not plaintext content review or approval**.
- A mandatory `AbortSignal`, and optional smaller `timeoutMs` and test transport.

The client obtains identity and trust from `verifiedManifestIdentity02` and
`verifiedManifestTrust02`, re-verifies copied manifest bytes and authorizes the
selected role-2 reader through that same verified object. Mutable public manifest
fields cannot establish trust. Root/generation substitution, version rollback,
changed digest at the same manifest version, owner/session/selection or CSRF
change, revoked reader, inactive interval and expired authority refuse.

The initial operation deadline uses a monotonic clock, is at most ten seconds,
and can only shorten with current authority, reader, manifest or template expiry.
It includes asynchronous current-host, CSRF, review, cryptographic, network and
streamed-body waits. Preparing a ticket, retrying or verifying never renews its
deadline. Synchronous host callbacks must return promptly; JavaScript cannot
preempt a synchronously blocked host. One ticket is outstanding at a time.
`close`, caller abort and expiry abort transport, clear owned encrypted buffers
and reject late results. Unknown request metadata survives closure for diagnosis.
These fences do not forcibly cancel arbitrary host callback work; the trusted
host remains responsible for its own cancellation and resource cleanup.

Only an active selection is accepted, even though the existing server can read
currently authorized history. This conservative client does not implement history
browsing, interval discovery or transfer to another reader/recipient.

## Save and unknown submission

`prepareSave({requestId, expectedRevision, scope, envelope})` snapshots caller
data before awaits, validates exact ZTWT scope/header and CAS, checks current
authority, consumes cloned ciphertext review, rechecks authority and returns an
opaque process-local ticket. Modifying review or original buffers cannot alter
the prepared request. The wire retains the existing UUID idempotency key, exact
binary content type and previous-revision header.

`commit(ticket)` performs the first POST. Only an exact bounded canonical
`{"revision": N}` receipt, followed by a fresh current authority/CSRF check, returns
`state: "acknowledged_saved_revision"`. It is neither a latest-head assertion nor
a dispatch approval. An exact retained historical revision acknowledgement
remains meaningful when another owner saves a newer version.

An attempted mutation with a lost, unusable, malformed or late response remains
unknown. `pending()` returns its copied request/template/revision/encrypted-digest
metadata, without payload or authority. While unresolved, another prepare or a
fresh encryption/request identity is refused. `retryUnknown(ticket)` is explicit
and sends the exact stored bytes, idempotency identity and previous revision;
there are at most three POST attempts in total. A later refusal cannot erase an
earlier ambiguous effect. No automatic retry is requested by the client. Browser
or network infrastructure may itself retry a request, so backend exact-request
idempotency remains essential.

Tickets and buffers are process-local and expire. They establish no crash or
restart recovery; after closure the unresolved metadata does not recreate the
ticket. Do not respond to uncertainty by minting another request or ciphertext.
Application recovery needs a separately reviewed durable identity contract.

## Latest read

`readLatest()` reads only the fixed template's latest opaque envelope. It validates
bounded body/header and P-256 encapsulation shape, independent selected identity,
binding/peer/reader/current manifest scope and expiry before and after awaited
integrity checks. It returns cloned scope, ciphertext and encrypted digest with
`state: "verified_current_snapshot"` and `requestAcknowledged: false`.
This is an independently checked response observation, not GCM authentication or
decryption capability. Use the existing `openEncryptedTemplate` with separately
authorized customer custody to authenticate/decrypt; this transport accepts no
private key and returns no plaintext.
The caller must check current owner/reader/custody and expiry again around its
separate decryption operation before publishing any content.

Known acknowledgement/read revision floors reject delayed older heads; a changed
encrypted digest at the same observed revision also refuses. A concurrent later
save can change the head immediately after observation, so callers must still
use CAS for edits. A CAS refusal does not reset an observed head floor.

`verifyUnknown(ticket)` uses the same latest-read path and may report
`matchesPending: true`, but a matching GET never acknowledges that POST and never
discards its unknown ticket. A newer head, unreadable/purged content or reader
revocation also cannot establish its request acknowledgement. There are at most
three unknown verification reads, including `readLatest()` calls while unknown;
all share the original ticket deadline.

Transport uses credentialed same-origin fetch, current CSRF, `cache: "no-store"`,
an abort signal and redirect refusal. No bearer token, broad owner credential,
raw exceptions, server error bodies or plaintext enters reports. The existing
server independently checks real owner authentication and CSRF, current reader
scope, immutable request replay, CAS, retention and budget under database locks.

## Executed fixture scope

The SDK's discovered `owner-encrypted-template-client.test.mjs` exercises actual
SDK encryption and manifest verification with synthetic fetch boundaries. It
covers mutable caller/review data, provenance, unknown identity and exact retry,
revocation/CSRF changes, delayed acknowledgements, deadline/abort, stalled and
oversized bodies, redirect refusal, read floors and attempt bounds.

The existing rendered-owner CI job discovers
`web/owner/browser/encrypted-template-client.test.js` after installing pinned
Playwright and Chromium. It runs the compiled module in actual Chromium against
an owned local HTTPS fixture with synthetic Secure/HttpOnly owner cookies and
CSRF, real opaque request bytes and current-host exchanges. It checks save/read,
ambiguous persisted response plus exact retry, post-response owner revocation and
a stalled body that actually reaches the deadline. Its unique self-signed
certificate is accepted only by its isolated browser test context; production
TLS is unchanged. All temporary server connections, context and certificate
files are owned and cleaned up. Missing browser/runtime/dependencies fail; no
optional test or runtime proof is skipped.
OpenSSL must be available on the test process PATH to generate that certificate.

The fixture supplies synthetic host/session authority and persistence responses;
it does **not** exercise the unmounted Rust router or PostgreSQL storage. Existing
server/PostgreSQL tests prove their existing backend separately. This slice makes
no composed application, real content-reader, supported customer application,
new-user journey, physical-device, carrier or production acceptance claim.
