# Authenticated original page discovery

Go `OriginalCurrentClient.Page` and Rust `OriginalCurrentClient::page` perform one
explicit original-grant HTTPS request and return bounded event metadata after
verifying and durably accepting the current service proof. They use the existing
independently enrolled root, grant scope, accepted-history checkpoint and trusted
clock. Credentials remain caller supplied. There is no automatic retry or
automatic request for the next page.

Limits are 1–32 events and at most eight unique active request IDs per event.
Every event, request and cursor UUID must be nonzero and canonical; wire objects
are closed, duplicate fields refuse, and numeric fields must be positive safe
integers. An absent input cursor starts discovery; a supplied cursor contains the
exact accepted time and event ID from a previous page. Invalid input refuses
before networking.

Following the server's `original_reply/page.rs` contract, returned rows must be
strictly ordered by `(accepted_at_ms, event_id)` and strictly after the supplied
cursor. UUID ordering compares its sixteen bytes. Event IDs cannot repeat even
with a different timestamp. A full page must return a cursor exactly matching
its last row; a short or empty page must return null. This checks continuation
correlation in addition to the maintained TypeScript client's closed cursor
shape. It does not assume observed time equals server acceptance time.

The three dispositions are `unassociated`, `owner_review`, and
`request_available`. They describe discovery only. They do not qualify a reply,
classify STOP, authorize consumption or establish proposal authority. Reading
plaintext still requires the separate verified read API. A final authority
snapshot accompanies the page; it cannot replace a fresh check for later effects.

The client serializes checkpoint operations and applies the current-proof
monotonic comparison/CAS rules. Invalid current signatures, scope, freshness or
persistence suppress the entire page. As elsewhere, trusted private checkpoint
storage does not detect hostile whole-database rollback.

`test-original-page.py` uses exact pinned maintained-client signed manifests
over local synthetic TLS. It covers empty/short/full pages, equal-time ordering,
exclusive cursors, exact next correlation, closed metadata, event/request
uniqueness, limits, invalid proof and rollback, and checks one or zero requests.
Linux and Windows CI run both native probes. These are source/runtime tests,
not installed-package or live-service qualification. Runtime requirements remain
Go 1.26.9 and Rust 1.97.1. [Descriptor-null consume/status](ORIGINAL-CONSUMPTION.md) is available separately.
Typed workflow proposals,
contact/template parity and installed qualification remain separate work.
