# Security and sealed-content design brief

This document describes a proposed sealed-content protocol. It is not an implemented or audited cryptosystem. The design separates intended protections from choices still under discussion.

The [ZT-009 review package](../protocol/drafts/zt-009-review.md) includes a [versioned byte profile draft](../protocol/drafts/zt-sealed-draft-01.md), threat diagram, candidate libraries and unresolved review questions. Neither document approves production crypto or closes ZT-009.

## Claims and trust boundaries

| Statement | Technical qualification |
|---|---|
| Open-source Android SMS gateway | Product category; implemented behavior must match public source |
| Encrypted connection / encryption at rest | Does not imply the service cannot read messages |
| Bodies encrypted on client before cloud upload | Proposed sealed-content path; not a current service feature |
| Cloud routes sealed content and visible metadata | Proposed routing model |
| End-to-end encrypted SMS | The SMS radio/carrier/recipient path remains conventional plaintext |
| We can never read your messages / zero knowledge | Endpoints, served browser code, metadata and key-directory trust limit such a claim |
| No Google message-content transit | Do not generalize into no third-party transit; the edge provider is also a processor |

Protected against in sealed mode: passive database/backup theft of bodies, accidental relay plaintext logging, a relay operator reading stored bodies without client keys, replayed device commands/events, and cross-account access. Not guaranteed: endpoint compromise, malicious updates/browser JavaScript, carrier interception, recipient access, availability, metadata secrecy, or retrospective revocation of already decrypted content. Server compromise can deny/reorder messages; preventing forged sends requires client signatures and authenticated enrollment, not HPKE alone.

Visible metadata includes account/device IDs, recipient and sender numbers, direction, time, size, segment information, network connection metadata, status, usage and billing. Minimize retention and log exposure. Plaintext phone numbers are a **chosen v1 routing/abuse design**, not an inherent requirement of end-to-end payload encryption or billing.

Enrollment maintenance runs every 60 seconds and deletes up to 500 rows per table per batch, repeating while a batch comes back full, for at most 10 batches per pass. Device authentication challenges are removed one hour after expiry, including used challenges. Pairing requests, including approved requests, are removed 24 hours after expiry, or 24 hours after cancellation if later. Active device identity and signing keys live in the separate `devices` and `device_keys` tables. Larger backlogs take multiple passes. A failed prune logs `maintenance prune unavailable (task=...)` once per failure streak, without SQL error text or row data; database backups follow their own retention policy.

## Key separation

| Key | Created/held by | Purpose |
|---|---|---|
| Login password verifier | Server stores Argon2id verifier | Authentication only; never derives content keys |
| Random 256-bit unlock/recovery secret | Owner client; recovery kit kept by owner | Wraps the vault using a domain-separated KDF |
| Random vault wrapping key | Owner client; only wrapped copy on server | Encrypts account private keys and settings |
| Account archive encryption pair | Owner client; private key in locked vault | Owner history decryption |
| Account authorization signing pair | Owner client; private key in locked vault | Signs approved device/integration key manifests |
| Device authentication signing pair | Android Keystore, proposed P-256 | Binds device identity to challenges/events |
| Device payload encryption pair | Device-local, protected by Keystore-backed wrapping if needed | Decrypts only payloads addressed to that device |
| Integration signing pair | Customer's local runtime | Authorizes send envelopes; scoped in owner-signed manifest |
| Optional integration decryption pair | Customer's local runtime | Decrypts authorized inbound/webhook/history content |
| API bearer token | Customer runtime; server verifier | Transport authorization, scopes, quotas; not decryption |
| Webhook signing secret | Server and customer receiver | Authenticates ciphertext events; encrypted at rest on server |

Use maintained crypto libraries, not home-written primitives. Candidate portable envelope suite: HPKE DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM for wrapping a random 256-bit content-encryption key; AES-256-GCM for one message body. This remains a **candidate until library/API interoperability tests pass**, not an instruction to compose an ad hoc ECDH scheme. Record exact standardized suite IDs, encoding, nonce generation, test vectors, and library versions in a versioned protocol revision. [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)

Browser support for a primitive is not support for HPKE/OPAQUE as a complete protocol. A small maintained JS/WASM crypto module with pinned dependencies and cross-client tests is expected. Do not advertise “zero JS supply chain” while using HTMX and cryptography. Vendored assets, CSP, no third-party dashboard scripts, a reproducible bundle and pinned native/SDK clients reduce exposure but do not eliminate the active served-code attack.

## Proposed outbound flow

1. Pairing registers a device-auth key and separate encryption key through a short-lived one-use session. Owner compares a code/fingerprint on phone and browser; unlocked owner client approves a versioned signed key manifest. QR carries no account-wide API token.
2. SDK pins the account authorization fingerprint on first setup; it rejects a replaced root, rollback of manifest version, unknown keys, wrong scopes, or expired approval. Subsequent rotation needs an owner-approved signed chain; server directory lookup alone is insufficient.
3. Client creates stable message ID, random content key and nonce; encrypts body once; HPKE-wraps the content key to **the selected device and account archive key**, plus only explicitly approved readers. Do not wrap every message to every fleet device. No server-side rerouting to an unwrapped device.
4. Bind version, account, message ID, recipient, selected device, expiry, keyset version and intent into canonical authenticated data. Sign the complete canonical envelope and routing fields with an approved sender signing key. Exact canonicalization must be in shared byte fixtures. Transport idempotency digest includes this envelope.
5. Relay checks tenant scope/limits and routes ciphertext. Device validates origin signature, manifest freshness, routing/AAD, expiry, bounds and attempt identity before decryption and radio submission. Server-generated execution grants control queue ownership; client signature controls original message authorization.
6. Phone reports authenticated status. Account dashboard decrypts bodies locally, renders them as text, and searches only locally decrypted pages. Metadata search stays on the server.

Sealed bodies still appear in memory at endpoints. Avoid persistent browser plaintext caches and disable message-body error breadcrumbs. Browser session lock clears live key references as far as the platform permits; do not promise perfect memory zeroization in JavaScript.

## Inbound, integrations and opt-out

Phone receives plaintext SMS, normalizes multipart events, and encrypts once to the account archive key and approved inbound integration recipients before upload. Device signs the event; event ID/sequence prevent duplicate ingestion. Webhooks carry that ciphertext. Send-only API keys need no decryption private key; never issue decryption scope by default.

Customer automation must decrypt in the customer's runtime using the SDK. Provide a local connector recipe; a plain Zapier webhook does not magically decrypt HPKE. Webhook HMAC proves relay authenticity, while the device event signature preserves source authentication for reviewers able to verify it.

The restricted M1 pilot classifies STOP-family keywords and likely free-text withdrawal requests on the phone. It stores a local recipient block immediately, even if an upload window is unavailable, and uploads only a signed metadata action when the reply matches a positively sent attempt and the selected SIM. The writer persists an account-scoped E.164 suppression and rejects both new acceptance and exact acceptance retries under the same account lock. An exact START or UNSTOP clears an existing server suppression only after authenticated, deduplicated inbound processing in the same outbound-attempt reply window. The phone retains its local STOP block after an affirmative writer acknowledgement because the current local record has no verified line and enrollment generation to compare with START. Neither action uploads SMS plaintext or sends an automatic confirmation. Authenticated owners can view active ambiguous SMS holds in a no-store review queue showing recipient metadata and event times. They can record an off-channel withdrawal as a separate account-scoped hold and one immutable decision per review item. Both writes need the owner session, exact Origin and CSRF, take the admission account lock, and add an append-only audit row. Acceptance rejects a held recipient, including an exact retry. Only a signed START from that recipient observed more than five minutes (the accepted clock skew) after the hold releases it, and no decision lifts a signed suppression; see [SMS compliance and current limits](SMS-COMPLIANCE.md).

## Recovery, rotation and revocation

- Email verification proves control of the address to the registrant who chose the password, not to whoever reads the mailbox. `POST /v1/auth/verify-email` takes the emailed code and the password of the pending owner, verifies the password against that owner's Argon2 hash under the shared password-work gate, and only then consumes the code; a wrong password, an unknown code and a consumed code share one response. A registration that collides with a pending, unverified owner for the same address returns the usual generic acceptance but cancels that owner's outstanding code and queued mail, so a code issued for someone else's password can never verify the address for the recipient, and the verification mail tells recipients who did not sign up to ignore it. An address held by a pending owner is still unavailable to others until the 24-hour pending window elapses.
- Owners can change their password from an authenticated session by supplying the current password and, when enabled, a fresh MFA or recovery code. The change revokes all sessions, clears the current browser cookies, and revokes API keys issued by that owner. Owners can review up to 50 active sessions and revoke every other session by confirming their current password and, when enabled, a fresh MFA or recovery code. A forgotten password can be reset with a one-hour, one-use code sent to the verified account email through the configured SMTP outbox; the code is pasted into a POST form and never placed in a URL. A reset revokes all sessions, owner API keys and pending MFA login challenges, preserves MFA enrollment, and queues a notification email. Integrations using revoked keys must be reissued after sign-in. The request endpoint returns the same response for known and unknown addresses. Instances without configured SMTP do not offer email reset; an operator with private database access can instead run `zrotext-admin reset-password`, which reads the new password on stdin and applies the same revocations, preserves MFA enrollment, and queues the same notification for delivery once mail is configured. Password recovery restores authentication only. Unlocking history still requires the recovery secret or a previously trusted unlocked client.
- New phone gets future messages only by default. History sharing is an explicit client-side rewrap operation; the server cannot rewrap ciphertext without keys.
- Revocation closes device sessions, blocks new leases, removes the key from future manifests, and advances keyset version. Stale clients fail closed and refresh; freshness policy and offline behavior must be tested. A revoked phone may retain messages/keys it already received, and may finish an already authorized radio operation.
- Rotate account/integration/device keys by signed chain with old/new overlap rules; preserve archive keys required for retention unless the owner chooses crypto-erasure. Revocation is not retroactive deletion from recipients or backups.
- Lost all trusted clients/recovery material means old content is unrecoverable. Allow a visibly new vault generation with a new trust root after account recovery; do not silently replace keys and pretend continuity.
- Auth MFA recovery, content recovery, operational backup recovery, and signing-key recovery are separate procedures with separate custodians where possible.

OPAQUE is defined in **RFC 9807**, not RFC 9380 (hash-to-curve). It may improve later password-based vault UX, but switching authentication protocols requires explicit migration and security review. Ordinary server-side Argon2 authentication cannot preserve an OPAQUE-derived zero-knowledge-password claim. [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807.html)

## Baseline controls

Use 256-bit random API tokens, prefix lookup, constant-time verification, revocation and scopes. HMAC-SHA256 with a separately stored server pepper is suitable for high-entropy token verification; the old allegation that all fast hashes need password-style salts is too broad. Passwords use a password KDF. Password hashing and verification run on blocking workers behind one process-wide two-worker semaphore, including registration, login, verification resend, MFA password proofs, and initialization of the unknown-account verifier. Admission occurs before submitting blocking work; cancellation retains the permit until that work finishes. HTTP admission and abuse limits still bound pending requests, while the worker gate keeps expensive password work off the async runtime. API keys never enter query strings, analytics, QR device enrollment, or logs.

TLS 1.3 preferred; minimum TLS policy follows the tested Android support matrix. Strict origin checks and CSRF protection for cookie-based requests; non-browser APIs use explicit bearer authentication. Cookie-authenticated mutations require the exact configured HTTPS `Origin` and the `x-zrotext-csrf` header matching the session-bound `__Host-zrotext_csrf` cookie. Owner GETs that return account content (`/v1/owner/export`, `/v1/owner/messages`, `/v1/owner/opt-out-review`, `/v1/owner/opt-out-holds`, `/v1/webhooks` and its delivery history, `/v1/inbound/messages/{id}/events`, `/v1/auth/api-keys`, the SMS line reads, `/v1/enrollment/devices` and `/v1/enrollment/pairings/{id}`) also require that header, without `Origin`, which browsers omit on same-origin GETs. A request with only the session cookie is refused with 403 (the export, message, review, webhook and enrollment reads refuse it before any database work), so these reads do not rest on same-origin response isolation alone. `/v1/auth/session`, `/v1/auth/sessions`, `/v1/auth/mfa` and `/v1/billing/status` stay cookie-only: the owner page calls them to learn whether it is signed in, and they return session and account-state metadata rather than messages, recipients or callback URLs. The `/owner/events` live-update stream also stays cookie-only, because a browser `EventSource` cannot send custom headers; it carries only which dashboard sections changed, and the dashboard then re-fetches them through the header-checked snapshot endpoints. Rate-limit registration, login, pairing, exports, bulk metadata reads, recipient velocity and device claims. Default-deny operator message access; sealed content cannot be inspected by support.

Encrypt webhook secrets under a separate operational KEK, rotate with overlap, validate timestamp and event dedupe. These server-readable webhook secrets are not content keys. Block SSRF at resolver, connection and network layers. Retain minimal content-free operational logs; avoid phone numbers in log labels and metric dimensions. Protect against high-cardinality telemetry abuse.

Use tenant-isolation tests, untrusted-input size limits, structured phone parsing plus country validation, explicit per-segment constraints, no message content in HTML without escaping, dependency review, Cargo advisory/license checks, SBOM, secret scanning, and artifact signatures/attestations. Public PR CI has no production secrets, no `pull_request_target` execution of fork code with privileged credentials, and no privileged home-network runner access.

Ephemeral/RAM-only mode is deferred. A later mode must specify process restart loss, swap/core-dump behavior, retries, device retention, logging, and TTL deletion; disabling Redis persistence alone does not prove RAM-only operation. Default short retention is deliverable without making a stronger promise.

## Protocol questions and test cases

Open protocol questions include concrete suite/library support, canonical encoding, sender signature roles, trust-root bootstrap, key-directory substitution, manifest rollback/freshness, key rotation, recovery, nonce reuse, chosen-ciphertext handling, multipart semantics and device time skew.

Test altered AAD, wrong recipient/account/device, old manifests, revoked keys, duplicated command/event, nonce misuse vectors, truncated/oversized envelopes, invalid points, malformed HPKE inputs, signature forgery, cross-tenant object IDs, CSRF, redirect/DNS-rebinding SSRF, and billing event replay/out-of-order delivery. Use published known-answer vectors and differential interoperability among browser, TypeScript SDK and Android.

Seed synthetic canary message bodies, run a full send/reply/backup/error cycle, and scan relay database, logs, traces, analytics, dumps and webhook envelopes for those plaintext canaries. This verifies a useful property; it is not proof against every malicious operator or client compromise.

### HTTP resource admission and API key issuance

The API admits HTTP handlers per process through four separate permit pools,
chosen from the request path before authentication, body extraction, or database
connection setup: 16 for provider callbacks (`/v1/billing/stripe-events`), 16
for device WebSocket upgrades (`/v1/device-stream`), 32 for anonymous routes
(login, MFA login, registration, verification, password reset, enrollment
claim/prove, and device challenge/authenticate), and 64 for everything else,
including owner and API-key routes. A full pool rejects further requests of that
class with 503 and Retry-After while the other classes keep admitting, so a
slow-request flood on the anonymous routes cannot starve Stripe deliveries or
device reconnects. The request body must be fully received within 10 seconds of
admission, however steadily it trickles; a late body fails with 408 and releases
its permit. A 30-second handler deadline bounds the rest of the request and also
returns 408. This is per-process admission, not a fleet-wide database connection
pool. A canceled handler can leave a PostgreSQL query running until its
connection driver receives the result, so this is not a hard bound on
outstanding database queries or connections. Each process reuses PostgreSQL
sockets within fixed per-class budgets (16 request, 16 device, 4 worker); idle
database sockets count against those budgets. Device clients are checked out per
operation and released before peer reads/writes, including the
pre-authentication proof wait. Up to 32 established device streams share the
16-client device reserve; request and device checkouts wait at most two seconds
for pool admission, while workers fail fast. A released socket is reset with
`DISCARD ALL` before reuse and is closed instead when the reset does not finish
within two seconds (for example a canceled query still running or an open
transaction), after 60 idle seconds, or at 30 minutes old. A five-second timer
closes expired idle sockets on quiet hubs and returns their connection permits
after the PostgreSQL driver exits. Deployments must still bound incoming
sockets, headers, and per-address connections at the edge, because the admission
pools are not keyed by client address, and size PostgreSQL for HTTP, upgraded
WebSockets, and background workers across all API instances. A timed-out
mutation may have committed; callers must reconcile state before retrying
non-idempotent actions.

API key creation consumes an atomic PostgreSQL budget of 20 attempts per account
per 24-hour window and 600 globally per minute. Sessions and API instances share
the budget; key revocation does not refund it. Exhaustion returns 429, and budget
storage failure returns 503 without creating a key. This bounds issuance rate,
not the lifetime retention of audit metadata for previously created keys.

Pairing creation (`POST /v1/enrollment/pairings`) consumes an atomic PostgreSQL
budget of 10 attempts per account per 15-minute window and 120 globally per
minute, charged after the owner session and CSRF checks and before the pairing
row is written. Cancelling or finishing a pairing does not refund it. Exhaustion
returns 429 and budget storage failure returns 503, both without creating a
pairing. This keeps one owner from inserting pairing requests faster than
enrollment maintenance removes them. Open pairings are not capped: an owner can
still hold several unclaimed pairings at once until they expire.

### Owner session and API key lifetime

An owner session expires 14 days after sign-in, and earlier if it goes unused
for 72 hours. A session never used after sign-in is measured from its creation.
Both limits are fixed in the server (`SESSION_DAYS`, `SESSION_IDLE_HOURS`); the
idle limit bounds how long a cookie left on an unattended or shared machine
stays useful. Rejected idle sessions return 401 and are not revived, and the
session inventory omits them and reports the earlier of the two deadlines.

Sessions and API keys record `last_used_at` after the credential verifies, at
most once per 15 minutes per credential. A wrong secret behind a known public
key prefix never moves it. Because of that write window, the recorded time can
trail the true last use by up to 15 minutes, and a session can lapse up to 15
minutes before 72 hours after its true last request. The owner key list
(`GET /v1/auth/api-keys`) returns `last_used_at_ms` (`null` if never used) so
owners can find and revoke keys no integration uses. API keys keep their
optional lifetime (1 to 365 days); omitting `lifetime_days` still creates a key
without an expiry, which the owner dashboard shows as "expires Never".

### Public sign-in and enrollment budgets

Password sign-in, second-factor completion, pairing claim and proof, and device
challenge and proof (HTTP and the device WebSocket) spend atomic PostgreSQL
budgets before password, factor or signature work. Each has a per-subject
budget (address, challenge token, pairing or device) and a route-wide budget
shared by all API instances. Budgets are not keyed by client IP address: behind
the TLS edge the server has no trustworthy client address.

Anyone can spend a route-wide budget with made-up subjects, so it only decides
admission for anonymous requests. When it refuses a request, the request is
still admitted if the caller shows it is not anonymous: an enrolled, unrevoked
device ID for a device challenge; the unused challenge ID and nonce for a device
proof; the one-use QR token for a pairing claim and the claim nonce for its
proof; a live second-factor challenge token; or, for password sign-in, a
login-client cookie issued for that address. Each check is a single indexed read
with no password or signature work. Admitted requests spend the same per-subject
budget plus a separate verified-route ceiling ten times the anonymous one, which
made-up subjects cannot reach. Refused requests leave no counter rows.
A background worker deletes idle counter rows only after the longest window of
their budget, plus one minute, has passed, so pruning never resets a budget
that is still in force. Retention is derived from the same policy table the
budgets use; scopes it does not know are kept for two minutes.

Owner second factors have two separate failure budgets of five rejected codes
per 15 minutes. Sign-in completion spends one, stored on the owner's MFA row
and cleared by a successful sign-in factor. Factors presented from a live owner
session (password change, revoking other sessions, MFA confirmation and
removal, and owner step-ups) spend the other, kept in the abuse counters and
keyed by the owner. Someone who knows only the password can delay sign-in but
cannot lock a signed-in owner out of those recovery actions.

The login-client cookie (`__Host-zrotext_login_client`; HttpOnly,
SameSite=Strict, 180 days) is set after a full sign-in from a browser that lacks
one for that address, and is kept across logout. Its value is a random ID and an
HMAC, under the auth pepper, binding that ID to the normalized address. It
grants no session and does not reveal the address. When the address or route
budget refuses that browser, it falls back to its own budget of 12 attempts per
15 minutes.
Browsers without the cookie receive the same 429 whether or not the address
exists. While the route-wide budgets are exhausted, sign-in from a new browser,
registration and verification resend still wait for the window to reset, and
the process-wide password worker gate still applies.

Password reset requests spend an anonymous per-address budget of 3 per day,
which anyone can spend by naming the address. When it refuses, a verified owner
address is admitted through a verified lane that charges its own per-address
subject, distinct from the anonymous counter, and rolls over with the
one-code-per-15-minutes throttle that sets the real cadence for known
addresses. Anonymous requests naming a real address can therefore delay the
owner's next code by at most one throttle window, not a day, and cannot cause
more mail than the throttle allows. Unknown addresses charge their exhausted
anonymous counter once more instead, so a refused request runs the same probe
and counter statements whether or not the address exists, and the response is
202 either way. The verified-route ceiling still bounds the lane as a whole.

Argon2id uses 64 MiB per operation, so each process runs at most two password
operations at once (sign-in, registration, verification resend, password change
and reset, revoking other sessions, and authenticator enrollment or removal).
A request reaches this gate only after spending its abuse budget. It then waits
up to two seconds for a free slot; if none frees, it gets 503 `unavailable`
with `Retry-After: 1` rather than 429, so a busy server is not mistaken for a
throttle. The 64-handler admission cap and 30-second deadline above bound how
many requests can wait and for how long.
