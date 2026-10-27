# Saved owner-review consumption and status

This experimental Rust/Go slice supports **descriptor-null owner review only**.
It does not propose an action, accept a workflow descriptor, obtain an output
credential, approve an action or send SMS. Typed proposals and their independent
output grant are available through the separate [proposal API](ORIGINAL-PROPOSAL.md).

Prepare an immutable intent using the current client's `PrepareOwnerReview` /
`prepare_owner_review`, supplying the event, caller-chosen consumption request ID
and optional active request ID. The library does not generate replacement IDs.
Persist and synchronize `Bytes()` / `bytes()` in trusted application storage
before calling `ConsumeOwnerReview` / `consume_owner_review`. This persistence is
an application obligation, not an automatically enforced SDK durable journal.
Retain the exact bytes across uncertain outcomes. Reconstruct the client from its
existing accepted-history checkpoint and call `RestoreOwnerReviewIntent` /
`restore_owner_review_intent` to recover the same intent.

The closed 151-byte record contains `ZTOR` plus version byte one, the enrolled
65-byte root point, the existing 32-byte original-scope hash, sixteen-byte event
and consumption IDs, a one-byte active-ID presence flag, and sixteen active-ID
bytes (zero when absent). Scope includes account, device, line, interval,
connector, grant, reader and peer. IDs are nonzero when present. Restoration
rejects another enrollment/scope, unknown format, wrong length or inconsistent
presence. Returned bytes are copies. This is a canonical trusted-storage record,
not a signature or protection against malicious rewriting of application state.
Do not reinterpret it as a proposal descriptor or migrate it implicitly.

Consume obtains and durably verifies fresh current authority, attempts exactly
one nested `params` request with `descriptor: null`, checks the closed result's
event/consumption/active IDs, `owner_review` disposition and null action, then
obtains fresh current authority again before returning the result. It never
retries, follows redirects, substitutes another identity or submits another
action. `StatusOwnerReview` / `status_owner_review` accepts the same saved intent
and correlates all three identities through the same fresh-proof boundaries.
Status never sends consume, including after a not-found response.

Error meaning is deliberately bounded:

- `Unavailable` before consume dispatch means this call made no consume attempt.
  It does **not** establish that the saved identity has never been consumed.
- Any dispatched consume failure is `Unknown`, including a lost response,
  non-success HTTP status, redirect, malformed/mismatched result or failed final
  proof. A prior attempt may already have committed; do not replace the identity.
- A failed status is `Unavailable` and does not prove absence or permit automatic
  resubmission. Retain the saved intent for explicit reconciliation.

The server returns no embedded consumption proof; this integration uses separate
authenticated current checks around the operation. Those checks are snapshots,
not perpetual authority or a substitute for the server's transactional fences.
Transport deadlines and credential confinement, monotonic checkpoint CAS and its
trusted-storage/whole-database rollback limitation remain unchanged.

`test-original-consumption.py` uses synthetic local TLS, genuine pinned signed
manifests and fresh subprocesses. It checks identical canonical records in both
languages, synced intent restoration, exact nested requests, null/selected
active IDs, malformed/mismatched responses, no redirects/retries, uncertainty and
lost-response recovery using status without a second consume. Linux/Windows CI
runs both native probes. These are source/runtime tests, not live-service or
installed-package qualification. Go 1.26.10 and Rust 1.99.1 remain required.

Contacts/templates and installed qualification of these new APIs remain
incomplete. No package is published by
these checks.
