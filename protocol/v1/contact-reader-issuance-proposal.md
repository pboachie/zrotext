# Owner contact reader issuance proposal

This is an **unmounted library proposal**. The ordinary server does not install
the companion SQL or mount the issuer. It has no aggregate genesis, independent
restore frontier, private root custody, contact ciphertext store, provider effect
or SEND authority. An extant database row alone cannot establish independently
accepted issuance history. Missing or corrupt state never initializes itself.

The library composes the existing generation-one account archive reader (role 2,
scope 12) and owner root writer (role 6, scope 0). It does not create phone,
conversation, device, purpose, reader-directory or provider identities. Public
statements and returned metadata do not grant current access or a future lease.

## Caller and wire grammar

The isolated router prefix is `/v1/owner/contact-reader-issuance`:

| Operation | Exact request |
| --- | --- |
| `POST /intents` | `create_request`, `expected_revision`, `prior`, `selected_reader_id`, `compared_root_fingerprint`, `requested_until_ms` |
| `POST /intents/lookup` | `create` (the complete original request), `expected_input_digest` |
| `POST /{authorization}/complete` | `generation`, `create_request`, `creation_expected_revision`, `unsigned_digest`, `signed_statement`, `code` |
| `GET /{authorization}?generation=G` | One positive canonical generation, no body |
| `POST /{authorization}/cancel` | `generation`, `create_request`, `unsigned_digest` |
| `POST /withdraw` | `expected_revision`, `expected_authorization`, `expected_generation`, `expected_digest` |

`prior` is exactly `{phase:"empty"}` or
`{phase:"active"|"withdrawn",authorization,generation,digest}`. Empty omits all
tuple keys; explicit null placeholders refuse. Every object is directly typed
from the retained raw JSON with unknown and duplicate fields refused, including
escaped duplicate names. Whitespace and property order are accepted. No generic
JSON object is reconstructed to claim original duplicate rejection.

Integers are quoted canonical decimals, at most signed 63 bits. Revisions may be
zero; generations and live times are positive. UUIDs are exactly 36 lowercase
characters and nonnil. Binary fields use canonical padded base64 with exact
roundtrip: IDs/digests 32 bytes, pin 94, points 65, manifest 364–9751, unsigned
250–753, whole signed statement 314–817. Role start times may be zero. Code uses
the maintained factor grammar, is held in zeroizing memory and never enters
rows, projections, logs or Debug output.

Every request requires the real owner session Cookie and the session-bound
`x-zrotext-csrf` value. POST additionally requires exact configured Origin and
`application/json`. Bearer Authorization, repeated framing/auth headers,
duplicate relevant cookie names, unsupported methods, extra queries and GET
bodies refuse. Session metadata GET elsewhere is Cookie-only; these content
GETs are not. All outcomes are no-store. Success is bounded JSON; errors carry
static codes (400/401/403/404/409/429/503), without factors, SQL or protected IDs.

Raw UTF8 request size is at most 8192 bytes. Body completion has a one-second
limit inside a ten-second outward deadline; local lock timeout is three seconds
and statement timeout five. Four AccountSlots bound outward requests per
account, not backend cleanup. The maintained global 16 socket permits remain
driver-held during asynchronous pool reset/closure. Request timeout or Drop
does not prove database settlement. Explicit commit/rollback ACK proves only
that successful path; late success is suppressed and ambiguous transport stays
UNKNOWN. There is no automatic positive replay, new identity or refund.

## Commitments, copies and lifecycle

The internal CREATE equality encoding is the existing reviewed 172+origin-length
layout: version byte, derived account, length-prefixed configured origin, original
request UUID, expected revision, prior phase and sentinel tuple, selected reader,
independently compared root fingerprint and original requested until. SHA-256
binds every value. Current reconciling user/session is excluded; original actor
and session are frozen separately for first completion. Impossible requested
expiry refuses rather than silently rewriting the committed request.

One extant state row holds immutable account/pin/fingerprint/generation one,
allocator, mutation revision, clock, ring position and EMPTY/ACTIVE/WITHDRAWN
tuple. At most four pending rows and 32 fixed receipt slots exist per account.
CREATE increments allocator and revision once, requires revision <= MAX-2 and
allocator < MAX. COMPLETE increments revision and installs the next eligible
tuple. Cancellation and withdrawal still work at revision MAX, without root or
MFA; they never allocate, reset, reopen, refund or revive an old identity.

Retained CREATE equality is compared before any duplicate result, including
terminal receipts. Historical completed replay requires the exact whole signed
bytes and never consumes another factor. Different whole bytes conflict.
Receipt visibility is seven days at actual database time; fixed-slot rotation
may retire an older receipt. This is bounded retained evidence, not lifetime
UUID uniqueness or a guarantee of wall-clock physical deletion. An unavailable
or retired identity is not proof of no prior effect and cannot reinstall.

Historical lookup/status read state SHARE NOWAIT, copy and validate explicit
bounded rows, perform the real final ordinary owner query, and await commit.
They do not need live root, MFA or original actor and do not write highwater.
Pending `creation_source` is explicitly `historical_creation_source`: original
pin/manifest/roles and actual successful creation observation clock, not a fresh
818 observation or current brand. Current aggregate metadata has a separate
point-in-time clock. Final ordinary owner reads are unheld point-in-time checks.

New positive work first settles the historical probe, then acquires actual
ceremony transaction -> current root -> maintained owner/MFA rows -> state ->
ascending pending/receipt slots. There is no reverse lock upgrade. CREATE spends
the maintained owner-management budget. First COMPLETE checks the frozen
actor/session, prior, complete unsigned bytes, source and actual time; the one
outbound composition invokes unchanged historical statement verification on its
genuine private current manifest, then separately inspects current roles.
Bad admission/factor commits only existing budget writes; issuer staging has
not occurred. Other failures roll back.

After the last positive write, staged facts and pending/receipt postimages are
checked, followed by genuine owner/MFA, current source, nonregressed clock,
deadline and factor freshness, before commit. Reduction instead uses separate
actual account/user/member/session SHARE NOWAIT locks and a private borrowed
auth-local fence; it has no root/password/factor dependency. Its final check
repeats owner, active/verified membership, revocation, expiry and actual 72-hour
idle predicates. NOWAIT is bounded row refusal, not a global lock-order proof.

## Closed projections and export

`Current` has `phase`, `mutation_revision`, `allocation_generation`, `observed_ms`;
nonempty phases additionally have `authorization`, `generation`,
`statement_digest`. It contains no whole statement or permission.

`Pending` has `kind:"pending"`, original CREATE commitment/request, authorization,
generation, original expected/allocated revisions, unsigned digest/bytes,
issued/expires/until, original user/session, frozen creation source and Current.
Creation source has kind plus account, pin/fingerprint, trust generation,
manifest version/digest/bytes, original observed time, manifest times, signed
upper bound and two closed four-field roles (ID, point, from, until).

Completed/cancelled/expired receipts have kind, CREATE commitment/request,
authorization/generation, original expected revision, unsigned digest, terminal
time and Current. Only `historical_completed` includes whole signed statement
and digest. Withdrawal returns kind `withdrawn` or `already_withdrawn`, tuple,
revision and observed time. Unavailable is exactly `{kind:"unavailable"}`.
Individual issuer responses and each pending export copy are <=20 KiB UTF8.

The existing takeout gets a separate explicit issuer family and two account-
scoped `generation:authorization` cursors, at most four pending and 20 visible
receipts per page. This is not an atomic snapshot of every export family.
An unknown, foreign, retired or no-longer-visible cursor returns 404.
Full takeout retains its existing private fields and bounds.

The paired public consumer uses the SAME existing route, exactly
`GET /v1/owner/export?contact_reader_only=state`, with genuine Cookie plus CSRF.
Any cursor, extra key, duplicate or differently spelled selector refuses before
private-family work. Its <=4096-byte response is exactly
`{kind:"contact_reader_state",state:null|State}`. State contains
`root_pin_b64`, `root_fingerprint_b64`, `trust_generation`, `last_mutation_ms`,
`current`, and `signed_statement` (whole public bytes only ACTIVE, otherwise
null). Null is unavailable; it is never inferred revision zero or admission.
The early branch opens no private contact vault and performs current-owner
checks, state SHARE, actual clock, final point-in-time owner and commit ACK.

## Storage, erasure and unavailable prerequisites

The companion SQL remains unnumbered/uninstalled. Exact columns, nullability,
keys, validated CHECKs, typed predicate bodies/signatures/search path and
transition/immutable/deferred closure triggers are required. Absent returns
unavailable or an owner-checked empty export; partial/mismatched schema refuses.
Rows are independently revalidated for copied framing, points, digests,
signature mathematics and semantic/source consistency before serialization.
No copied blob is deserialized into accepted authority. Database constraints
and privilege assumptions do not establish independent restore admission.

The real account-erasure transaction calls pending -> receipts -> state deletion
with three counts, before parent deletion. Later failure rolls everything back.
Existing immutable enrolled-root history blockers still return 409 earlier.
This hook does not make enrolled-account erasure reachable or solve backup,
replica, WAL or independently anchored no-reuse continuity.

Tests use genuine registration, password verification, login and public MFA.
Their already-enrolled root/manifest and aggregate rows are explicitly synthetic
extant fixture assumptions. Exhausted counters and full retained rings likewise
model preexisting fixture state; they do not certify production seed or restore.
The complete product still needs admitted genesis/restore, installed schema,
matched CLI/page consumers, private custody and actual mounted contact CAS/read.
