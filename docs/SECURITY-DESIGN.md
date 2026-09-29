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

Enrollment maintenance runs every 60 seconds and deletes up to 500 rows per table per batch, repeating while a batch comes back full, for at most 10 batches per pass. Pairing requests, including approved requests, are removed 24 hours after expiry, or 24 hours after cancellation if later. Active device identity and signing keys live in the separate `devices` and `device_keys` tables. Socket handshake challenges are stateless HMAC values under the enrollment pepper and leave no rows to prune. Larger backlogs take multiple passes. A failed prune logs `maintenance prune unavailable (task=...)` once per failure streak, without SQL error text or row data; database backups follow their own retention policy.

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

## Team seats (device-status observers)

An account has exactly one immutable owner. The first collaboration phase adds
owner-managed observer seats: the owner invites an address from `/owner/seats`,
and the server stores only the HMAC of the single-use invitation token under
the auth pepper. Creating an invitation grants a persistent read seat, so it
needs the same step-up as minting an API key: the owner's current password and,
once MFA is on, a fresh authenticator or recovery code, so a stolen session
cookie alone cannot create one. The route's `SeatInvite` budget is spent
before the password is hashed, on every attempt including a wrong password, so
it also bounds password guesses; a wrong code spends the MFA step-up failure
budget and an exhausted budget answers 429. Cancel and remove only narrow
access, so a session and CSRF are enough for them. Invitations expire after
seven days, are bound to one address, are unique per account and address (a
repeat invitation from the same account replaces the earlier one, and an
expired one never blocks the address), and are bounded to ten open invitations
and ten live observer seats per account. Acceptance claims the invitation row
under a lock (single-use, replay-safe, exactly one winner under concurrency),
refuses any address that already belongs to a user without touching that
user's password or membership and without consuming the invitation, and
creates an unverified observer that must verify its email with its own
password before signing in - the same password-bound code model as owner
registration. An accepted-but-unverified observer is pruned after the 24-hour
pending window, like an unverified owner.

Inviting never acts as an address oracle. For the inviting owner, a registered
address, an unknown address, an address invited by another account, and an
address that used to be another account's observer are indistinguishable in
status (201), body shape and fields (a real single-use token every time), list
entry, open-invitation slot use, `SeatInvite` budget charge, and database
work: creation never reads the user table or other accounts' invitations. One
account's open invitation never blocks another account from inviting the same
address. A conflict is discovered only by the token holder at acceptance,
where a taken address answers 409 and, when two accounts' tokens race for one
address, the loser gets the same 409 instead of a server error.

Observers authenticate with sessions in their own name and can manage only
their own authentication: change password (which revokes their sessions and
their API keys, which they cannot create), review and revoke their own
sessions, and sign out. Every owner-authority route rechecks the owner role in
the database and answers an observer session with the same 401 as no session,
so role is not a side channel. Their single read surface,
`/v1/observer/devices`, returns the account's device status (socket lease,
queue counts, reported preconditions) with the CSRF header proof, and never
message content, recipients, credentials, or tokens. Removing a seat is
irreversible and never blockable: the membership is revoked (a database
trigger keeps revocation immutable) and the same transaction revokes its
sessions, API keys, MFA challenges, reset codes, queued verification mail, and
any still-open invitation for that address, records a tombstone on the
accepted invitation (email, accepted and removed times) for the owner's list,
and then deletes the observer's user row, guarded so only a user whose single
membership is this account's observer seat can be deleted and never an owner,
so the address is free again and a later invitation or registration creates a
brand-new identity with nothing carried over. The delete runs in a savepoint:
if the database refuses it with an integrity error (a restricting reference,
unreachable for observers today), the revocations still commit, the address
stays occupied, and both the removal response and the owner's seat list carry
`address_free: false`.
Account erasure covers seats: `POST /v1/owner/erasure` deletes the account's
observer users, invitations and removal records in its one transaction with the
same single-membership guard (never an owner or another account's user), locks
the account's observer memberships and then its invitation rows before the
auth fence in the order removal and acceptance use, and fails closed with
`erasure_blocked` if a foreign key refuses an observer delete.
Threats considered: a stolen owner cookie minting a persistent seat (step-up
proof, password and MFA failure budgets); a leaked invitation token (bounded
lifetime, single use, owner cancel); cross-tenant address enumeration and
squatting (uniform owner responses, per-account uniqueness); racing accepts,
accept-versus-cancel and cross-account accepts of one address (invitation row
lock, unique-violation mapped to a conflict, exactly one winner); a removed
seat attempting reuse (every credential dead, identity deleted or, in the
fallback, revocation immutable); an observer probing owner routes (database
role recheck, uniform 401); and enumeration or timing probes of the accept
route (uniform failure with the same password work as a live acceptance).

Not in this phase: observer MFA, emailed password reset for observers,
bounded pruning and retention of expired or closed invitation rows,
additional collaboration roles (administrators, billing viewers), and
owner-registration invitations.

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

The API admits HTTP handlers per process through five separate permit pools,
chosen from the request path before authentication, body extraction, or database
connection setup: 16 for provider callbacks (`/v1/billing/stripe-events`), 16
for device WebSocket upgrades (`/v1/device-stream`), 32 for anonymous routes
(login, MFA login, registration, verification, password reset, and enrollment
claim/prove), 8 for the bodiless probes
(`/healthz`, `/readyz`, `/about/version`), and 64 for everything else,
including owner and API-key routes. A full pool rejects further requests of that
class with 503 and Retry-After while the other classes keep admitting, so a
slow-request flood on the anonymous routes cannot starve Stripe deliveries,
device reconnects, or health checks. The request body must be fully received
within 10 seconds of admission, however steadily it trickles; a late body fails
with 408 and releases its permit. A 30-second handler deadline bounds the rest
of the request and also returns 408.

Owner and API-key routes that take a request body authenticate from headers
before the body is read. Owner routes check the session cookie, then borrow a
pooled connection only to look up the session and verify the exact Origin and
the CSRF cookie and header, and return that connection before reading the body;
the alpha message route does the same with its bearer API key. A request without
valid credentials therefore gets its 401 or 403 as soon as its headers are
checked and releases its permit, however slowly it sends its body, so a
credential-less or forged-session trickle cannot hold owner/API permits. A
request that authenticates also takes one of its account's 4 in-flight slots per
process for the rest of the request; a fifth concurrent body-carrying request
from the same account gets 429 `rate_limited` before its body is read. An
account with valid credentials can therefore hold at most 4 of the 64
owner/API permits, and only until the 10-second body deadline. Several
compromised or colluding accounts can still together fill the pool, and the
anonymous pool is by design reachable without credentials. This is per-process admission, not a fleet-wide database connection
pool. A canceled handler can leave a PostgreSQL query running until its
connection driver receives the result, so this is not a hard bound on
outstanding database queries or connections. Each process reuses PostgreSQL
sockets within fixed per-class budgets (16 request, 16 device, 4 worker); idle
database sockets count against those budgets. Device clients are checked out per
operation and released before peer reads/writes, including the
pre-authentication proof wait. Up to 32 established device streams share the
16-client device reserve. After its proof verifies, a stream takes its device's single session slot; one account holds at most `DEVICE_SOCKETS_PER_ACCOUNT` (default 8) of the 32, independent of billing device caps, so one tenant with many enrolled keys cannot refuse every other tenant's phones. A reconnect of the same device takes over the older stream's slot and signals that stream to close at once; the storage epoch fence still rejects any work the older stream attempts before it exits. Request and device checkouts wait at most two seconds
for pool admission, while workers fail fast. A released socket is reset with
`DISCARD ALL` before reuse and is closed instead when the reset does not finish
within two seconds (for example a canceled query still running or an open
transaction), after 60 idle seconds, or at 30 minutes old. A five-second timer
closes expired idle sockets on quiet hubs and returns their connection permits
after the PostgreSQL driver exits. Deployments must still bound incoming
sockets, headers, and per-address connections at the edge; this is a hard
deployment requirement, because the admission pools are not keyed by client
address and the anonymous pool accepts requests without credentials, and size PostgreSQL for HTTP, upgraded
WebSockets, and background workers across all API instances. A timed-out
mutation may have committed; callers must reconcile state before retrying
non-idempotent actions.

API key creation consumes an atomic PostgreSQL budget of 20 attempts per account
per 24-hour window and 600 globally per minute. Sessions and API instances share
the budget; key revocation does not refund it. Exhaustion returns 429, and budget
storage failure returns 503 without creating a key. This bounds issuance rate,
not the lifetime retention of audit metadata for previously created keys.

Issuing a key (`POST /v1/auth/api-keys`) takes the same step-up as changing the
password or revoking other sessions: the body must carry `current_password`
and, once MFA is enabled, a fresh authenticator or recovery `code`. A session
cookie plus CSRF token alone, the position of an attacker who copied the cookie
from a compromised browser or proxy, cannot mint a key that would keep sending
through the owner's phone after the session is revoked. A missing, wrong or
stale proof returns 400 without creating a key, the code is verified and
consumed inside the same transaction as the insert under the owner's user-row
lock, and factor failures spend the separate step-up failure budget (see
"Owner second factors" below), so repeated failures here do not lock the
owner out of signing in. The issuance
budget above is charged before the password is hashed, so it also bounds
password guesses made through this route to 20 per account per day.

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
owners can find and revoke keys no integration uses. An API key lives for its
requested `lifetime_days` (1 to 365); omitting it applies the 365-day default.
`"lifetime_days": null` is the explicit never-expire opt-in: it leaves
`expires_at` NULL, exactly as keys created before the default existed carry,
and is discouraged — a stolen never-expiring key stays valid until an owner
notices and revokes it. Existing non-expiring keys keep authenticating
unchanged. The dashboard shows "expires never" for both legacy keys and
explicit never-expiring keys (the metadata cannot distinguish them); the
Never option in the creation form states that it is discouraged.

Keys record the user that issued them, not the session, so a key minted from
a stolen session cannot be told apart from the owner's own. "Sign out other
sessions" (`POST /v1/auth/sessions/revoke-others`) therefore revokes only the
other sessions by default, because integrations use API keys independently of
any session. A caller that suspects a stolen session can pass
`"revoke_api_keys": true` to revoke every unrevoked key of that owner in the
same transaction, matching password change and reset; the owner dashboard
offers this as a separate, clearly labelled checkbox next to the password
confirmation.

### Public sign-in and enrollment budgets

Password sign-in, second-factor completion, and pairing claim and proof spend
atomic PostgreSQL budgets before password, factor or signature work. Each has a
per-subject budget (address, challenge token, or pairing) and a route-wide
budget shared by all API instances. Budgets are not keyed by client IP address:
behind the TLS edge the server has no trustworthy client address.

Anyone can spend a route-wide budget with made-up subjects, and anyone who
knows a public identifier such as a pairing ID can spend that subject's
anonymous budget, so the anonymous lane only decides admission for
anonymous requests. When it refuses a request, the request is still admitted if
the caller shows it is not anonymous: the one-use QR token for a pairing claim
and the claim nonce for its proof; a live second-factor challenge token; or,
for password sign-in, a login-client cookie issued for that address. Each
check is a single indexed read with no password or signature work. Admitted
requests spend a second, verified per-subject counter with the same size as
the anonymous one, keyed separately, plus a verified-route ceiling ten times
the anonymous one. Neither is reachable without a live subject, so
unauthenticated requests that name a real pairing ID cannot use up the budget
the pairing's holder needs. Refused requests leave no counter rows. The
exception is a subject that is itself a secret, such as a sign-in
second-factor challenge or a password reset link. Only its holder can spend
its anonymous counter, so it keeps one per-subject counter across both
lanes, and a challenge still allows five code attempts per five minutes in
total rather than five per lane.

The device WebSocket handshake is deliberately exempt from per-subject
budgets. Its challenge is a stateless HMAC under the enrollment pepper over
the account, device, and a timestamped challenge UUID, verifiable for 60
seconds, so issuance costs one indexed liveness read and no write. The device
ID is public information, so any counter keyed to it could be spent by an
unauthenticated caller who knows it, which used to let such a caller refuse
the enrolled phone's handshake with 1013. Issuance and proof each spend an
anonymous route-wide ceiling (300 per 60 seconds, across all instances), with
handshake slots bounding concurrency. When the anonymous ceiling refuses a
hello, the hub still issues a challenge if the named device is enrolled and
live, charging a subjectless verified-route ceiling ten times the anonymous
one; when it refuses a proof, the proof is still admitted if it verifies,
charging the matching verified-route ceiling. Made-up device IDs and proofs
that fail verification never reach a verified ceiling, so junk traffic that
fills the anonymous ceilings, from however many sources, cannot refuse an
enrolled phone. The residual is traffic naming a real, live device ID: at a
sustained rate above roughly 3,300 hellos per minute (about 55 per second)
it can fill the verified issuance ceiling too, and every phone then receives
a retryable 1013 until the window rolls over, for as long as that rate is
sustained. No per-device counter exists for such a caller to single out one
phone. Operators should therefore rate-limit WebSocket upgrades per source
address at the edge, in addition to the per-source connection limit, because
a connection limit alone does not bound sequential hello/close cycles.

A proof is accepted only when its challenge ID, account, device and nonce
equal the challenge issued on the same connection. Challenges are stateless
and not marked used, so this binding is what stops a proof captured from one
connection, or replayed after a reconnect, from opening a session on another.
Within one connection's 60-second window a captured proof could be replayed
only against that same challenge; sessions are still fenced by the
writer-owned connection epoch, and observing a proof requires breaking TLS.
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
more mail than the throttle allows. The verified lane also has a daily cap of
12 admitted requests per address, charged before the reset transaction and only
after the throttle-window subject admits. With the 3 anonymous requests, an
address therefore gets at most 15 reset mails a day, however many requests
name it. A capped request gets the same 202 as every other throttled or
unknown-address request. The cap is a trade-off: a stranger who keeps
requesting codes for a real address can use up that day's verified lane (at
least 4 throttle windows, about an hour, of repeated requests), and the owner
then waits for the next day's budget. Unknown addresses charge their exhausted
anonymous counter once more and read the daily budget instead, so a refused
request runs the same probe and number of counter statements whether or not
the address exists, and the response is 202 either way. The verified-route
ceiling still bounds the lane as a whole. Each newly issued reset code marks
the previous unused code for that owner as used and cancels its queued mail,
so only the newest mailed code works; a stranger's request can therefore
replace a code the owner has not used yet, but never within 15 minutes of the
previous one.

Argon2id uses 64 MiB per operation, so each process runs at most two password
operations at once (sign-in, registration, verification resend, password change
and reset, revoking other sessions, and authenticator enrollment or removal).
A request reaches this gate only after spending its abuse budget. It may then
queue for up to two seconds for a free slot, but at most four requests may
queue at once: a queued request still holds one of the request pool's 16
database connections, so an uncapped queue could idle most of that pool during
a burst of budget-admitted password attempts. With two hashing and four queued
requests, the password lane holds at most six request connections; the rest
stay available to every other owner route. A request that finds no queue slot,
or whose two-second wait expires, gets 503 `unavailable` with
`Retry-After: 1` rather than 429, so a busy server is not mistaken for a
throttle.
