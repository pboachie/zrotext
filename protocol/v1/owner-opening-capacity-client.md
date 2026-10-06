# Owner opening-capacity client foundation

`createOwnerOpeningCapacityClient` is an SDK foundation for a future authenticated
opening bridge. It has no ordinary page caller or browser graph entry and does not
mount HTTP routes, install schema, initialize capacity, approve messages or send
anything. The optional opening schema, actual owner HTTP adapter, packaged page
composition and genuine server/SDK pairing remain required before availability.

## Selection and preparation

The closed options require an explicitly enabled HTTPS origin, independently
copied conversation binding, initial context ID and source end, the real author's
`savedSource` getter, the existing setup's `readCurrent`, current CSRF callback,
explicit review callback, parent signal and setup/custody close subscriptions.
Subscriptions may return either a cleanup function or nothing. Immediate close,
reentrant close and removal failure leave the client unusable. The client never
reads an archive key. These structural callbacks are trusted application
dependencies; their shape does not establish independent authority.

The actual setup observation has exactly binding, manifest, nowMs,
ownerSessionLive and consentLive. It has no `validForMs`, phase or interval end.
Preparation copies the binding, checks genuine manifest identity/trust, copies
the signed bytes and re-verifies them. All reader/signer records and lifetime
ceilings come from that new privately held verified manifest, never mutable
public fields on the supplied object. It checks exact account/device/line,
session, interval, generation, peer and selected phone/archive readers, active
role-4 device/line signer, nonregressing observed clock and root/manifest history.
It does not use a generation-one account archive statement helper or enroll a
role-5 key. The actual binding has no selected phone signer ID; the role-4 check
is a local bound, while the server must enforce its stored interval selection.

Only a new preparation calls the acknowledged-source getter. Its closed snapshot
is accountId plus the exact six receipt primitives: requestId, contextId, revision,
envelopeDigest, state and requestAcknowledged. Require the independently intended
account/context, revision 1, nonzero lowercase SHA-256, `verified_current_snapshot`
and true acknowledgment. Copy and compare that whole tuple again after review.
Matching ciphertext without an original acknowledged write, UNKNOWN, closed or
expired author state cannot supply this input. It is historical metadata, not a
current-head capability. The source write request ID is retained provenance, not
a replacement opening identity.

`prepareCreate({requestId,openingId,capacity,decisionDeadlineMs})` requires explicit
nonnil canonical UUIDs, capacity 1..100 and positive signed-range BigInt time. The
review is content-free and binds all these values and the exact source tuple.
A legitimate decision end shorter than the source ceiling is allowed. The known
ceiling is the minimum of newly verified manifest/key ends and the independently
retained source end. It is not an invented interval deadline. The server's actual
source check/recheck must enforce that additional interval limit, current
revision/envelope digest and final fences. Local preparation can still be refused
by that server. The final getter, actual observation, CSRF and lifetime checks
must finish before an opaque private ticket is returned.

## Original clocks and unsettled work

Explicit totalTimeoutMs is 1..60000, attemptTimeoutMs and observationTimeoutMs
1..10000, and maxAttempts 1..3. The absolute monotonic total starts at construction,
before any preparation/review work. Authenticated observed time, elapsed bootstrap
and crypto, known signed/source ceilings and the requested decision end may only
shorten it. Observation freshness can shorten a nominal 60-second total to ten
seconds or less; it is not a promised 60-second usable review. No clock renews on
retry, status or a second observation.

One unsettled operation is allowed. The maximum explicit dispatch budget is
shared by create, retry and status. No request is automatic. Outward timeout or
abort does not prove fetch, stream, callback or crypto settlement. Their slot
remains charged until the actual promise settles. Stream cancellation is observed
as cleanup work where needed; it does not establish backend transaction or kernel
settlement. Closed clients cannot launch replacement work.

## Wire and exact uncertainty

Create is literal POST `/v1/owner/workflow/openings` with closed body:

```
{request_id,opening_id,capacity,
 description:{context_id,revision,digest},decision_deadline_ms}
```

The i64 time is a canonical decimal string. Every request sends the independently
copied account in `x-zrotext-opening-account` and actual selected CSRF in
`x-zrotext-csrf`, uses application/json, same-origin credentials/mode, no-store
and redirect error. No bearer, Cookie override, arbitrary endpoint or query is
accepted. The future bridge must compare the account assertion to the genuine
authenticated owner before reading a body or applying an effect. This SDK does
not implement that missing server check.

Successful create is exactly `{account_id,request_id,outcome}`, where outcome is
`{receipt,applied,recorded}`. Require original account/request/opening IDs,
recorded true and applied boolean. Receipt is exactly opening, offer,
allocation_id, allocation_version, phase, pending and confirmed. Opening has
opening_id, definition_version and state_version; versions are positive canonical
i64 strings. Counts are nonnegative canonical i64 strings, decoded losslessly as
BigInt, with pending plus confirmed at most 100. Offer/allocation fields must be
null; phase is open, closed or cancelled. Applied false is an acknowledged
historical replay, not new permission. No inferred source echo is introduced.

Responses use an 8192-byte streamed cap, fatal UTF-8 and duplicate-aware closed
JSON validation. Numeric aliases, extra fields, bad identity, zero digest,
redirect, malformed success or ambiguous transport cannot acknowledge. A first
definitive 400/401/403/404/409/413/429 before any UNKNOWN is refused. After possible
dispatch, timeout/abort/408/5xx/stream or decoding failure is UNKNOWN; every later
refusal stays UNKNOWN. No request, opening ID, original body or deadline is
regenerated.

`retry(ticket)` explicitly sends the original exact bytes/account/IDs/CSRF under
the original deadline. It invokes no getter, readCurrent, key or source lookup.
Loss of the local source adapter while the actual parent owner scope remains live
does not block retained replay. Actual setup/custody/page/user close is different:
it closes this client and cannot be ignored or revived. The server still locks
current root authority before retained replay and can refuse on root loss or
redacted ledger; the client preserves uncertainty.

`status(openingId)` is a separate explicit POST to
`/v1/owner/workflow/openings/{id}/status` with exact `{}` and newly selected current
same-account CSRF. It returns only `{state:'metadata_snapshot',accountId,openingId,
receipt}` from closed `{account_id,receipt}`. It never acknowledges creation,
clears UNKNOWN or renews the positive ticket. Status errors throw an availability
error while preserving creation uncertainty. When UNKNOWN exists, a different
opening cannot be selected. A fresh separately selected owner metadata flow
after closure would require a real caller; this client cannot remount itself.

Close clears replay body/token and dependency references before abort/removal,
suppresses late success, and retains only content-free account/request/opening
UNKNOWN identity. Already returned copies remain historical metadata, not
revocable authority. JavaScript reference clearing is not a RAM-zeroization or
backend-settlement promise.

## Test and integration boundary

Ordinary controls obtain saved metadata from the actual authoring factory,
maintained HPKE/context client and genuine verified manifest primitives. Controlled
HTTP responses prove SDK choreography only; they are not genuine Cookie/MFA or
PostgreSQL authentication. Mutated public receipt copies are negative inputs,
never forged positive factories. Actual callback/stream/timer/close/refusal,
duplicate/numeric bounds, shorter decision end and keyless replay controls remain
separate from real HTTP/schema acceptance.

The future browser graph must add the new root to browser_assets.rs and its
positive/removal fixtures, plus the existing Startup fixture in composition.rs.
The generic packager, current page/setup/helpers and graph are unchanged here.
Future authenticated server/SDK pairing needs separately reviewed bounded opened
I/O, stdin/stream/process identity and cleanup with an original deadline captured
before producer launch. An existing driver timer starting after stdin write or
checking output size only after wait is not that proof. No runner, schema install,
route exposure, physical device, provider or complete application acceptance is
part of this foundation.
