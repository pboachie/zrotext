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

An interrupted mutation has an **unknown** outcome unless a valid closed refusal
arrives. The client aborts and retires after an uncertain response. Restore the
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

The transport uses five explicit POST operations under
`/v1/account/sealed/payload-profile`: `challenges`, `challenges/status`,
`challenges/proof`, `elections` and `current`. POST reads allow the browser to
send its ordinary Origin header; script must not fabricate that forbidden
header. Requests are bounded to96KiB and responses to192KiB. UUIDs are canonical
lowercase strings, binary fields are unpadded canonical base64url, and storage
counters/timestamps are positive decimal strings within the signed64-bit bound.
The existing grant03 integer fields and exact362-byte fetch transcript are
separate unchanged contracts.
