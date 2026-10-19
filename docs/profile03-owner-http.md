# Owner profile election transport

`sdk/typescript/src/owner-profile-election-client.ts` supplies the owner-session
transport for the coordinated additive profile03 election API. This library
does not mount a dashboard or server route. The database transition, original
line proof capture, device setup and maintained receiver remain separate work.
Existing profile02 clients and protocol bytes are unchanged.

The client uses the configured canonical HTTPS origin, same-origin browser
credentials, the existing `x-zrotext-csrf` header, closed JSON, explicit deadlines,
bounded streams and redirect refusal. A caller-supplied transport and durable
storage callback are trusted application dependencies; this library cannot
prove that an arbitrary callback persisted data or authenticated a server.

Create one opening with the exact already root-signed successor03 manifest.
Before `reserve` reaches the network, `saveRecovery` must persist its public
record with the opening UUID, exact manifest bytes, selected line, owner session,
device, origin and independently compared root fingerprint. It never receives
the current password or factor. Those are transient per-request input and are
not cached, logged, persisted or retried by this client. JavaScript strings are
not claimed to be securely erased from memory.

Use the same public record for observation or an explicit authorized retry.
Changed opening content refuses locally. A reservation result preserves its
original issue and expiry times, including when it has expired. A successful
historical response does not renew permission. The instance retains one opening;
it does not silently allocate another after failure.

After a fresh sign-in by the same original user, use `observeOpening` with the
unchanged saved record and explicitly read `status` or `deviceProof`. The
response remains bound to its original owner-session digest. `reserve` and
`commit` refuse that older session's record before storage or HTTP; observation
never upgrades old signed bytes to the new session. `restoreOpening` retains
its strict same-session mutation contract.

Reservation/status responses require `closed_unaccepted`, empty when there are
no closed predecessors and otherwise at most16 exact linked records. Each
contains `opening_id`, `challenge_id`, `new_binding_id`, original E500 `core`,
`closed_unaccepted_ms` and `superseded_by_challenge_id`. The transport checks the
same original02 scope, increasing burned generations, original expiry, closure
time equal to its successor's original issue time, distinct IDs and a complete
ascending link to the returned challenge.
Historical session/nonce bytes stay unchanged. These are candidates: the server
must permanently fence actual closed rows, and the phone must compare the chain
with its own retained signed journal. Elapsed time or an absent response alone
cannot prove nonacceptance or allow a new signature. Starting a new opening
remains a distinct explicit user action with fresh authorization.

An interrupted mutation has an **unknown** outcome unless a valid closed4xx refusal
arrives. A503 remains unknown even with its valid static error body, since a
database commit may already have succeeded. The client aborts and retires after
an uncertain response. Restore the
saved public record in a fresh client and observe its status before deciding
on an exact retry. Failure to observe a reservation is not proof that a previous
in-flight mutation cannot commit. The server must independently enforce durable
idempotency, outstanding-reservation exclusion and original expiry. The library
does not implement that server authority.

`deviceProof` reads a candidate device signature without creating a reservation
or approving anything. The caller must independently verify it against the
actual paired signing key and exact reviewed core before owner signing. Commit
uses the exact original628-byte bundle and successor. Its returned receipt is
historical acceptance metadata, not a grant or proof of present permission.

`current` returns a structurally bound candidate projection and original signed
evidence. Root-pin fingerprints, exact bundle/manifest commitments and obvious
scope/counter mismatches are checked, but the transport performs no original
signature, registration or activation verification. A caller must use the
existing independent root/manifest/election verifiers and actual current device
authority before installation or effect. A JSON field or local type cannot
replace those checks. Original acceptance-session digests stay historical;
a later authorized owner session must not rewrite them to read the evidence.

All methods refuse late results after session/CSRF change or closure. Recovery
from a new owner session requires a fresh explicitly authorized ceremony where
the old challenge's session binding no longer applies. Preserve completed root,
phone and key setup rather than manufacturing renewed challenge authority.

`bootstrap` returns the separate original02 candidate before an election. It
does not allocate a ceremony or renew permission. Its original signed evidence
must be verified against the independently compared root and phone keys, actual
retained02 history and current session before owner signing. Only its initial
selection epoch may be zero; the other counters remain strictly positive.

The transport uses six explicit POST operations under
`/v1/account/sealed/payload-profile`: `bootstrap`, `challenges`, `challenges/status`,
`challenges/proof`, `elections` and `current`. POST reads allow the browser to
send its ordinary Origin header; script must not fabricate that forbidden
header. Requests are bounded to96KiB and responses to192KiB. UUIDs are canonical
lowercase strings, binary fields are unpadded canonical base64url, and storage
counters/timestamps are positive decimal strings within the signed64-bit bound.
The existing grant03 integer fields and exact362-byte fetch transcript are
separate unchanged contracts.
