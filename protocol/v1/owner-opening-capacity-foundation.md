# Owner-confirmed single-opening capacity foundation

This dormant library foundation defines one bounded opening with declared
capacity from one through 100 units. Its SQL is an unnumbered candidate under
`deploy/compose/migration-candidates/`, excluded from the production migrator.
Tests install the candidate explicitly into disposable schemas. Owner create
and status routes are composed only behind the existing disabled-by-default
customer-routines gate and require an explicitly installed valid candidate.
This foundation does not enable an SDK/application journey, interval-overlap
booking, external calendar, provider call or SMS dispatch.

The optional schema gate checks the actual resolved relations in the current
schema, their complete columns and defaults, validated checks, primary and
unique keys, foreign-key targets and actions, and required usable indexes.
Internal foreign-key triggers must belong to the exact candidate relations;
external incoming foreign-key dependencies are refused.
An absent candidate remains optional for lifecycle/export callers and unavailable
for opening commands. Partial or inconsistent installed objects abort the caller
transaction before opening effects; status also passes this gate because it can
expire pending holds. This validation neither installs the candidate nor enables
an HTTP route, client journey or production migration. The inspection is
read-only and retains existing transaction lock order and time bounds. Privileged
candidate installation and schema DDL require controlled coordination; this
guard does not prove resistance to arbitrary concurrent operator DDL after its
inspection and grants no application or owner DDL authority.

## Owner create and status HTTP wire

The gated router exposes `POST /v1/owner/workflow/openings` and
`POST /v1/owner/workflow/openings/{id}/status`. Status expires pending holds;
it therefore requires mutation authentication and is never an inert GET.
Both routes require the actual owner session cookie, canonical Origin and
CSRF cookie/header proof. The genuine account ingress slot remains held through
the handler. The required `x-zrotext-opening-account` header asserts the
independently intended account against that authenticated principal before
body parsing or effects. It never supplies a principal or database selector.
Missing, duplicate, malformed or mismatching assertions are refused. Bearer
authorization is refused; routed responses include `no-store` and `nosniff`.

Bodies are JSON objects bounded to 8192 bytes; arrays, duplicate fields,
unknown fields and query arguments are refused. Create accepts exactly
`request_id`, `opening_id`, integer `capacity` from 1 through 100,
`description` containing `context_id`, integer `revision` from 1 through 128
and nonzero lowercase 64-character hexadecimal `digest`, and `decision_deadline_ms`.
UUIDs are canonical lowercase, hyphenated and nonnil. The deadline is a
canonical positive decimal string through the signed 64-bit maximum, never a
JSON number. The status path uses the same UUID form and its body is exactly
the empty object. Existing library validation and authority checks still apply.

A create 200 has exactly `account_id`, `request_id` and `outcome`; the latter
contains `receipt`, boolean `applied` and `recorded: true`. These identities
come from actual authentication and the dispatched original typed request.
An exact retained committed replay reports `applied: false`; changed typed
capacity, source or deadline conflicts. Root authority is locked before ledger
replay: root loss cannot be bypassed by a retained request ID, and erased receipt
payloads cannot acknowledge. Status 200 has only `account_id` and `receipt`;
metadata never acknowledges an uncertain create.

Both receipts contain `opening` with `opening_id`, `definition_version` and
`state_version`, `offer`, `allocation_id`, `allocation_version`, `phase`,
`pending` and `confirmed`. In this create/status slice the three nullable
offer/allocation fields remain null. Phase is `open`, `closed` or `cancelled`.
Positive versions and nonnegative counts use canonical decimal strings; combined
pending and confirmed count is at most 100. Invalid internal projection returns
unavailable rather than a misleading acknowledgment. Existing empty library
error bodies and authentication/body errors retain their status meanings.

The route slice alone does not complete a caller integration. Readiness requires
genuine acknowledged context authoring over authenticated POST/GET, actual HPKE
decryption of the returned ciphertext, and the maintained opening SDK consuming
unchanged mounted response bytes. Structural ciphertext fixtures and mocked
positive authority cannot substitute for this pairing. Local key unavailability
with a still-live owner scope differs from scope closure, server authority loss
and erased ledger retention; uncertain attempts keep their original identity.
The optional SQL remains outside production migrations and the gate default
remains disabled. No sending or application availability follows from this wire.

The [wire schema](owner-opening-capacity.schema.json) and
[synthetic vectors](vectors/owner-opening-capacity.json) describe these closed
shapes. Schema validation of an already parsed value cannot detect duplicate
JSON members, preserve integer-token spelling, bind an independently selected
account or acknowledge a dispatched request. Combined-count bounds require a
separate semantic check. Streamed parsing, actual owner/source/current-root
authority and retained typed ledger identity remain server/client requirements;
passing a shape vector does not prove admission, installation or availability.

Current conversation storage admits at most one pending, install-pending or
active interval per account. The maintained activation authorizer retains that
account-wide boundary. Capacity race tests use genuine signed replies in one
eligible interval; they prove atomic unit ownership within that scope.
Multi-peer intake and complete application journeys under #759 remain unaccepted.

## Offer and allocation mutation wire (proposal)

The [allocation schema](owner-opening-allocation.schema.json) and
[synthetic vectors](vectors/owner-opening-allocation.json) propose closed JSON
shapes for the library's offer, reserve, confirm, release, cancel and close
requests and their shared response. **No such route is mounted and no handler
exists**; this is a reviewable contract only, so a later route and SDK slice
cannot drift from the typed library requests. Request fields mirror
`contracts.rs` exactly (a unit test compares them to the Rust structs), use the
create/status primitives unchanged (canonical UUIDs, decimal-string versions
and deadlines, lowercase nonzero digests) and carry no account, owner,
SEND `ActionKey`, delivery, acceptance or model field: authority comes only from
the authenticated owner and current server state. The response repeats the
create envelope (`account_id`, `request_id`, `outcome`) with a receipt that may
now carry `offer` and `allocation_id`/`allocation_version`. `recorded` may be
false for an already-terminal no-op. A schema pass does not prove duplicate
member refusal, the combined 100-unit bound, that allocation identity and version
are both null or both present, replay, authentication or availability; those are
semantic and server controls, listed in the vectors as `schema_valid: true,
valid: false`.

The current authenticated account owner selects exact current encrypted
workflow context IDs, revisions and digests. The maintained selected-reader
authorizer requires writing authority; a permanent context stop fence also
prevents admission after takeover. Each offer separately binds its real peer
contact and current purpose consent episode. Integration SEND permission,
routine authority, model output and message delivery cannot create capacity.

An actual retained signed capture from the selected context's interval and
expected peer may support a pending reservation. Both signed observed time
and server accepted time must be at or after offer issuance, before its bound
deadline, and no later than the final database clock; observed time must not
exceed accepted time. Unsupported clock skew is unavailable. These checks
establish provenance and timing only: they do not establish affirmative
plaintext meaning or cryptographic offer-ID binding. The owner declares the
business meaning after client-local decryption through a separate confirmation.

Pending and confirmed allocations both consume one unit. Confirmation does
not increase their combined count. Increasing operations lock current root
authority first, then current owner/account, actual context/interval, real contact,
opening, offer, allocation and retained response checks; final source, purpose,
clock and owner fences run after all mutations. Exact request identities replay
only previously committed metadata results. Changed request bytes conflict.

Owner close stops admission and cancels pending holds while preserving confirmed
occupancy. A later explicit owner cancel releases confirmed units. Owner release
uses opening/allocation IDs and versions plus current account ownership, even
after contact or source erasure; historical routing and decryption authority are
unnecessary for reduction. Closed and cancelled identities never reopen.
Reductions lock owner/account before opening/allocation; borrowed lifecycle
hooks retain their caller's account-leading lock without reacquiring the root.

Consent withdrawal and takeover stop exact affected offers and pending holds in
the same transaction. Source-description loss also cancels dependent pending
holds. Confirmed occupancy survives these events until explicit owner reduction.
Contact/source erasure nulls affected contact, consent, context, response and
actor/time bindings and redacts affected receipt payloads and digests. Confirmed
allocations retain only account/opening/allocation IDs, phase/version and an
opaque response-use fence. Exact description erasure also clears its original
issuer and deadline. Unrelated offers preserve their independent bindings.
Bounded owner takeout reflects the scrubbed rows; account erasure removes all
four tables child-first and reports their actual counts.

The database deduplication domains are exact ASCII `ZT/opening-request/v1`
and `ZT/opening-response-use/v1`, each followed by one NUL. Request hashing
adds the canonical 16-byte account UUID, big-endian two-byte operation and
closed typed JSON. Response-use hashing adds canonical 16-byte account and
verified event UUIDs. The response-use digest remains unique across openings
after source erasure. These hashes convey no authority or decryption capability.

Ordinary increasing mutations have a lifetime 8192 charged-receipt bound.
Redaction preserves the admission charge. Every created object consumes one
charged receipt; each opening/offer has at most two owner reducing transitions
and each allocation at most one. Internal lifecycle/expiry/erasure hooks add
no receipts. Thus owner reductions add at most 16384 rows and total journal
rows remain at most 24576. An already-terminal request with a fresh UUID returns
current metadata with `applied=false, recorded=false`, reserves no nonce and
promises no historical result replay. Release/cancel/privacy erase never check
ordinary quota. Only irreversible reductions may retain saturated MAX state
versions; all increasing mutations refuse overflow.

Full application acceptance remains open: production migration promotion,
reviewed callers and journeys, multi-opening/interval overlap, encrypted contact
custody, device/carrier/provider proof and end-to-end routine integration require
their separately tracked work. A library or disposable fixture pass proves none
of those boundaries.
