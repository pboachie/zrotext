<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Pending line proposal inspection

The explicitly mounted sealed-line setup adapter extends its existing
`POST /v1/owner/conversation/sealed-line/owner-key/{challenge_id}/status`
response with `pending`. Ordinary startup still does not mount this adapter.
Owner cookie authentication, canonical Origin, CSRF, body limits and the
`expected_session_id` check apply before inspection.

A completed registration returns its immutable `receipt` and `pending: null`.
An outstanding registration returns `receipt: null` and the original persisted
proposal bytes, their SHA-256, original owner identity, expected typed scope,
root pin and database time sample. The status object always contains exactly
`receipt` and `pending`. An absent or consumed challenge has both set to null.
The lookup does not generate another approval key or renew a challenge.

The pending object has exactly twelve keys: `v`, `kind`, `account_id`, `user_id`,
`session_id`, `origin`, `root_fingerprint_hex`, `proposal_sha256_hex`,
`proposal_b64`, `expected_context`, `server_now_ms` and `expires_ms`. Version and
kind are integer 1; `expected_context` is an object containing `root_pin` and
`scope`; the remaining values are strings. UUIDs use canonical hyphenated form,
bytes use lowercase hex or canonical padded base64, and times use positive
decimal milliseconds. Scope identities, challenge, nonce, fingerprints, epochs,
generation and original issuance/expiry are bound to the persisted transcript.

Inspection locks root authority before the account and binds the original
session, phone signing fingerprint, connection and deployment epochs, line
generation, root identity, canonical origin, nonce and exact row/transcript
metadata. Revocation, changed authority, expired proposal or expired live
session/device lease refuse inspection. A final live check follows database
waits before the response is published. A fresh session cannot inherit an
earlier session's pending proposal.

The database time sample is not a renewed lease or independently authenticated
owner time. If completion races the lookup between its receipt and pending
transactions, an explicit retry can reconcile the immutable receipt; the
lookup never synthesizes a replacement proposal.

Clients must compare the authoritative context with their independent selection
and exact proposal bytes both before signing and after signing. A successful
lookup is neither phone consent nor completed activation, and it does not
replace the completion endpoint's one-use factor, signature and live authority
checks. This endpoint handles only line registration; it does not establish
provenance for other typed owner ceremonies.
