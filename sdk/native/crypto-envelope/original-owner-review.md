# Candidate saved owner-review consumption

Java, C# and Ruby original clients expose explicit descriptor-null owner-review
consumption and status reconciliation. These experimental source APIs do not
create proposal descriptors, request output credentials, grant workflow authority
or automatically retry an effect. Installed-package qualification and publication
remain separate work.

Prepare an intent with the exact event UUID, caller-selected consumption/request
UUID and optional active-request UUID. Preparation generates no IDs and performs
no network or persistence. **The application must durably save and flush the
returned bytes before invoking consumption.** Restore those same bytes after
an unknown outcome or process restart, and call status for that identity. A new
request ID could create a different effect and is not a recovery mechanism.

The owned 151-byte `ZTOR` version-one format captures the independently enrolled
root point, full scoped checkpoint-binding hash, event, request and optional
active-request ID. Restoration checks exact format, enrollment, scope, nonzero
IDs and the canonical optional-ID representation. Returned bytes are copies.
This is a captured request, not a signed authorization, tamper-proof record or
library-managed durable journal. The application owns trusted storage, atomic
replacement policy and protection against rollback or modification of saved IDs.

Consumption first obtains and durably verifies a fresh current proof, dispatches
one descriptor-null request, validates every response field against the saved
intent, and obtains a second fresh current proof before returning the correlated
result. A failure before consume dispatch is unavailable for this invocation;
it does not prove the same identity was never consumed earlier. Once dispatch
may have occurred, transport failure is unknown. After a successful transport
return, malformed or mismatched data and final-proof/persistence failure are also
unknown. The error exposes neither credentials nor server payload.

Status uses the same saved identity and before/after current-proof checks. It
never sends consume, including after unavailable, forbidden or not-found status.
A failed status does not establish absence of an earlier effect. Successful
results bind event, consumption, optional active request and final authority;
they require `owner_review` disposition and null action. Proposal/output scope
is deliberately unsupported. Client exclusivity and callback reentry refusal
cover the full operation; persistence failure retains existing client poisoning.

Run `original-owner-review-run.py --language java|csharp|ruby --fixture
<fixture-checkout> --producer <producer-checkout>` after building the maintained
TypeScript producer. The exact clean shared TLS fixture is
`a0cd1763406b6c0a05f7ea57a897664f39667b75`; its producer is pinned to
`72124e1a3ff28e782f870eeddbdc33cacf8ca3b4`. The shared 57 signed TLS controls check
golden intent bytes, invalid frame and identity refusal before network, one
consume attempt, response/proof failures, and committed-response loss followed
by status recovery in a fresh process using the previously flushed bytes.

The dedicated workflow performs software acceptance on Windows/Linux. No
protected-key creation, live gateway, external workflow proposal or existing
credential is involved. Current proof verification is an additional local guard;
the service still independently authorizes each effect. Local private checkpoint
and intent storage do not establish hostile whole-file rollback resistance.
