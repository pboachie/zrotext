# Security and sealed-content design brief

This document describes a proposed sealed-content protocol. It is not an implemented or audited cryptosystem. The design separates intended protections from choices still under discussion.

The [ZT-009 review package](protocol/zt-009-review.md) includes a [versioned byte profile draft](protocol/zt-sealed-draft-01.md), threat diagram, candidate libraries and unresolved review questions. Neither document approves production crypto or closes ZT-009.

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

Enrollment maintenance runs every 60 seconds and deletes at most 500 rows per table per pass. Device authentication challenges are removed one hour after expiry, including used challenges. Pairing requests, including approved requests, are removed 24 hours after expiry, or 24 hours after cancellation if later. Active device identity and signing keys live in the separate `devices` and `device_keys` tables. Backlogs may require multiple passes; database backups follow their own retention policy.

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

Use maintained crypto libraries, not home-written primitives. Candidate portable envelope suite: HPKE DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM for wrapping a random 256-bit content-encryption key; AES-256-GCM for one message body. This is a **candidate pending library/API interoperability review**, not an instruction to compose an ad hoc ECDH scheme. Record exact standardized suite IDs, encoding, nonce generation, test vectors, and library versions in a reviewed protocol revision. [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)

Browser support for a primitive is not support for HPKE/OPAQUE as a complete protocol. A small reviewed JS/WASM crypto module and its dependencies are expected. Do not advertise “zero JS supply chain” while using HTMX and cryptography. Vendored assets, CSP, no third-party dashboard scripts, a reproducible bundle and pinned native/SDK clients reduce exposure but do not eliminate the active served-code attack.

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

The restricted M1 pilot classifies STOP-family keywords and likely free-text withdrawal requests on the phone. It stores a local recipient block immediately, even if an upload window is unavailable, and uploads only a signed metadata action when the reply matches a positively sent attempt and the selected SIM. The writer persists an account-scoped E.164 suppression and rejects both new acceptance and exact acceptance retries under the same account lock. An exact START or UNSTOP clears an existing suppression only after authenticated, deduplicated inbound processing in the same outbound-attempt reply window; the phone clears its local block only after an affirmative writer acknowledgement. Neither action uploads SMS plaintext or sends an automatic confirmation. General unsolicited-reply capture, durable line identity in the signed event, and an owner review path for off-channel and ambiguous requests remain open before a general send route; see [SMS compliance and current limits](SMS-COMPLIANCE.md).

## Recovery, rotation and revocation

- Account login reset restores authentication only. Unlocking history requires the recovery secret or a previously trusted unlocked client. Generate the recovery kit, verify a sample entry, and offer encrypted export during onboarding.
- New phone gets future messages only by default. History sharing is an explicit client-side rewrap operation; the server cannot rewrap ciphertext without keys.
- Revocation closes device sessions, blocks new leases, removes the key from future manifests, and advances keyset version. Stale clients fail closed and refresh; freshness policy and offline behavior must be tested. A revoked phone may retain messages/keys it already received, and may finish an already authorized radio operation.
- Rotate account/integration/device keys by signed chain with old/new overlap rules; preserve archive keys required for retention unless the owner chooses crypto-erasure. Revocation is not retroactive deletion from recipients or backups.
- Lost all trusted clients/recovery material means old content is unrecoverable. Allow a visibly new vault generation with a new trust root after account recovery; do not silently replace keys and pretend continuity.
- Auth MFA recovery, content recovery, operational backup recovery, and signing-key recovery are separate procedures with separate custodians where possible.

OPAQUE is defined in **RFC 9807**, not RFC 9380 (hash-to-curve). It may improve later password-based vault UX, but switching authentication protocols requires explicit migration and security review. Ordinary server-side Argon2 authentication cannot preserve an OPAQUE-derived zero-knowledge-password claim. [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807.html)

## Baseline controls

Use 256-bit random API tokens, prefix lookup, constant-time verification, revocation and scopes. HMAC-SHA256 with a separately stored server pepper is suitable for high-entropy token verification; the old allegation that all fast hashes need password-style salts is too broad. Passwords use a password KDF. Password hashing and verification run on blocking workers behind one process-wide two-worker semaphore, including registration, login, verification resend, MFA password proofs, and initialization of the unknown-account verifier. Admission occurs before submitting blocking work; cancellation retains the permit until that work finishes. HTTP admission and abuse limits still bound pending requests, while the worker gate keeps expensive password work off the async runtime. API keys never enter query strings, analytics, QR device enrollment, or logs.

TLS 1.3 preferred; minimum TLS policy follows the tested Android support matrix. Strict origin checks and CSRF protection for cookie-based requests; non-browser APIs use explicit bearer authentication. Rate-limit registration, login, pairing, exports, bulk metadata reads, recipient velocity and device claims. Default-deny operator message access; sealed content cannot be inspected by support.

Encrypt webhook secrets under a separate operational KEK, rotate with overlap, validate timestamp and event dedupe. These server-readable webhook secrets are not content keys. Block SSRF at resolver, connection and network layers. Retain minimal content-free operational logs; avoid phone numbers in log labels and metric dimensions. Protect against high-cardinality telemetry abuse.

Use tenant-isolation tests, untrusted-input size limits, structured phone parsing plus country validation, explicit per-segment constraints, no message content in HTML without escaping, dependency review, Cargo advisory/license checks, SBOM, secret scanning, and artifact signatures/attestations. Public PR CI has no production secrets, no `pull_request_target` execution of fork code with privileged credentials, and no privileged home-network runner access.

Ephemeral/RAM-only mode is deferred. A later mode must specify process restart loss, swap/core-dump behavior, retries, device retention, logging, and TTL deletion; disabling Redis persistence alone does not prove RAM-only operation. Default short retention is deliverable without making a stronger promise.

## Protocol questions and test cases

Open protocol questions include concrete suite/library support, canonical encoding, sender signature roles, trust-root bootstrap, key-directory substitution, manifest rollback/freshness, key rotation, recovery, nonce reuse, chosen-ciphertext handling, multipart semantics and device time skew.

Test altered AAD, wrong recipient/account/device, old manifests, revoked keys, duplicated command/event, nonce misuse vectors, truncated/oversized envelopes, invalid points, malformed HPKE inputs, signature forgery, cross-tenant object IDs, CSRF, redirect/DNS-rebinding SSRF, and billing event replay/out-of-order delivery. Use published known-answer vectors and differential interoperability among browser, TypeScript SDK and Android.

Seed synthetic canary message bodies, run a full send/reply/backup/error cycle, and scan relay database, logs, traces, analytics, dumps and webhook envelopes for those plaintext canaries. This verifies a useful property; it is not proof against every malicious operator or client compromise.

### HTTP resource admission and API key issuance

The API admits at most 64 concurrent HTTP handlers per process and rejects
excess requests with 503 and Retry-After before authentication, body extraction,
or database connection setup. A 30-second handler deadline bounds slow request
bodies; timed-out requests return 408. This is per-process admission, not a
fleet-wide database connection pool. A canceled handler can leave a PostgreSQL
query running until its connection driver receives the result, so this is not a
hard bound on outstanding database queries or connections. Deployments must still bound incoming
sockets/headers at the edge and size PostgreSQL for HTTP, upgraded WebSockets,
and background workers across all API instances. A timed-out mutation may have
committed; callers must reconcile state before retrying non-idempotent actions.

API key creation consumes an atomic PostgreSQL budget of 20 attempts per account
per 24-hour window and 600 globally per minute. Sessions and API instances share
the budget; key revocation does not refund it. Exhaustion returns 429, and budget
storage failure returns 503 without creating a key. This bounds issuance rate,
not the lifetime retention of audit metadata for previously created keys.

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
