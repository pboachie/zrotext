# Typed Android proposal onboarding

The server library exposes two authenticated endpoints for inspecting and retaining
public typed conversation proposals. These endpoints are mounted only by
`Startup::router_with_sealed_line_setup`; ordinary `Startup::router` leaves them
absent. Startup requires the complete sealed-line setup schema and the exact
`owner_android_proposals` storage contract. It installs no schema, spawns no
worker and enables no dispatch or root-signing feature.

This is a Draft02 onboarding prerequisite. The accepted proposal kinds are
3 (genesis, `ZTCG` version1), 4 (activation, `ZTCA` version1) and 5 (refresh,
`ZTCF` version1). It does not accept profile03 manifests/elections, implement a
profile03 sender or grant receiver, or establish browser-to-phone SMS delivery.
The root-material decoder and inspection APIs are public; secret signing remains
behind the separate `unlock` feature, which the server does not enable.

## Authentication and requests

Both endpoints use the existing owner mutation authentication: verified owner
session cookies, the configured canonical Origin, matching CSRF cookie/header,
ordinary account request budgets and a closed JSON object. API bearer credentials
are not a substitute. Unknown, duplicate (including escaped duplicate), null or
array fields are rejected. Requests have a 32 KiB body limit. Responses use
`Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

`POST /v1/owner/conversation/android-proposal` accepts exactly:

| Field | Type | Meaning |
|---|---|---|
| `kind` | integer | 3, 4 or 5 |
| `proposal_b64` | string | Canonical padded standard base64, nonempty, decoded maximum20480 bytes |
| `expected_session_id` | UUID string | Must equal the authenticated session |
| `phone_export_b64` | string, kind 3 only | Required public phone export; decoded maximum223 bytes |
| `encrypted_archive_b64` | string, kind 3 only | Required encrypted archive framing; decoded maximum845 bytes |

The two kind 3 input fields must be absent for kinds 4 and 5. Present null is never
an absent field. Inspecting encrypted archive framing binds its exact ciphertext
digest; it does not authenticate/decrypt the archive or prove recoverability.
Phone export key/identity fields must match the current selected paired phone.

Success returns exactly `v` (1), `kind`, lowercase 64-character
`proposal_sha256_hex`, UUID `owner_session_id`, and decimal-string `expires_ms`.

`POST /v1/owner/conversation/android-proposal/context` accepts exactly `kind`,
`proposal_sha256_hex` (lowercase 64-character hex) and `expected_session_id`.
Success returns exactly `v`, `kind`, `account_id`, `user_id`, `session_id`,
`origin`, `root_fingerprint_hex`, `proposal_sha256_hex`, `proposal_b64`,
`expected_context`, `server_now_ms` and `expires_ms`. The two time fields are
decimal strings. UUIDs use the normal UUID JSON representation; binary fields
inside `expected_context` use lowercase hex. `expected_context.scope` contains
the independently derived account, original session, device, line, binding
generation, peer, origin and root fingerprint. Genesis additionally binds the
public root pin, phone reader/signer, archive reader and exact archive digest;
activation/refresh bind the exact accepted predecessor and current required roles.

## Authority and immutable retries

Each operation retains its schema fence and root-before-owner/line locks in one
transaction. It requires a live generation-one authority with zero anchor,
matching current root fingerprint/checkpoint, an approved sealed line binding,
the current paired signing point, live device connection and deployment epochs,
and enabled/non-draining site. Owner session revocation, expiry, role loss,
account disablement and the 72-hour idle deadline are checked again after waits.
The returned server comparison time is sampled from PostgreSQL. Stored context
is not an offline authority token and cannot replace these current checks.

Genesis requires the uninitialized manifest position and rejects known signing
point aliases. Activation requires exact current consent and no pending or active
conversation interval anywhere in the account. Refresh requires the exact active
interval, its still-live originating owner session and a new unreserved signer.
All three inspect the typed packet against server-derived expectations before
storage and again before returning context.

There is at most one immutable pending record per account/kind. An identical
retry preserves exact packet bytes, expectations and the original deadline.
Changed identity, context, checkpoint or payload cannot replace a live record.
Deadlines are bounded by five minutes and the relevant packet/manifest lifetime;
refresh also retains the originating session's deadline. Expired records can be
removed and replaced; no UPDATE may rewrite an existing pending record.

## Inventory, retention and erasure

The authenticated conversation inventory includes `android_proposals` with
`installed` and at most three account-scoped `proposals`. Entries contain public
packet/context bytes and identities, not private keys or message content.
An absent optional schema yields `installed: false` and an empty list. A partial
or drifted installation fails closed rather than being treated as absent.

The explicitly returned sealed-setup retention worker prunes at most 100 expired
proposal records per sweep in the same transaction as its existing challenge and
nonce cleanup. It skips row locks held by other operations. Starting the worker
and reserving its database slot remain the embedding runtime's responsibility.

Owner erasure validates and fences installed proposal storage before its final
password/MFA/session fence and includes pending-record deletion in the same
transaction. Ordinary absent storage is compatible with erasure; partial or
malformed storage refuses without partial deletion. Existing immutable root,
line-binding and approval records can block account erasure with 409 before any
delete. A pending proposal does not override those blockers or make its required
immutable binding erasable. Session/account foreign-key deletion also removes
pending records when the corresponding authoritative deletion is permitted.

The numbered proposal migration must be part of a complete, consecutive,
reviewed migration train before deployment or full migration/PG acceptance.
Applying its SQL alone is not a production schema or readiness guarantee.
Neither successful proposal issuance nor a context response supplies root
custody, phone consent, profile03 binding election, content admission, a one-use
execution grant or permission to invoke the SMS radio.
