# Verified original-grant current proof

Rust `OriginalCurrentClient` and Go `OriginalCurrentClient` connect the dedicated
HTTPS transport to an existing scope-bound accepted-history checkpoint. The
constructor requires independently enrolled root bytes/fingerprint, the selected
grant scope, an existing checkpoint, and a trusted local comparison time. HTTP
responses cannot bootstrap enrollment or replace a missing/corrupt checkpoint.

`current`/`Current` accepts a fresh original credential and a trusted clock
callback, performs one HTTPS current request, and verifies the closed response
schema. It checks every scope identifier, reader, authority revision, root
generation, exact contiguous signed manifest chain, retained baseline digest,
current version/digest, freshness and expiry. JSON integer fields must be positive
integers within the exact JavaScript integer range; canonical UUID/base64/hex
representations are required.

Before returning a `VerifiedOriginalCurrent`, it atomically preserves the signed
history and advances the local clock/revision under checkpoint CAS. A clock
callback runs under the write lock to recheck freshness; a postcommit check
withholds authority if the deadline passed. A newer postcommit comparison is
persisted by a second fenced transaction before return. There is no final sampled
clock left only in memory. Persistence failure, revision conflict, or failed
postcommit freshness makes the client stale: reconstruct it from the existing
checkpoint, never reset trust or silently retry. Concurrent calls on one instance
refuse. Go instances must not be copied after first use.

Server `accepted_at_ms` timestamps and the local durable comparison are distinct.
The maintained TypeScript original-reply client permits a signed chain timestamp
up to 30000 ms ahead of the trusted local clock, then independently checks the
current manifest at the fresh local time. The native checkpoint now retains the
same bounded acceptance skew. Its private profile02/generation-one history
adapter verifies every signature, enrolled root and unsigned predecessor while
treating each server acceptance timestamp independently. It does not import the
previous server timestamp as a local clock floor. The generic manifest API and
its monotonic comparison rule are unchanged. Local checkpoint comparison remains
strictly monotonic, including on reopen. This does not add profile03 or root
transition support to original-grant history.

The returned authority is a verified snapshot. It does not authorize omitting
fresh checks before/after plaintext release or effects. [Verified read integration](ORIGINAL-READ.md) adds both checks. [Page discovery](ORIGINAL-PAGE.md) also fences metadata. [Descriptor-null consume/status](ORIGINAL-CONSUMPTION.md) adds saved-intent
reconciliation. Typed descriptor/output authorization and installed package
qualification of this surface remain follow-on work. No live grant or service
deployment is qualified by these tests.

`test-original-current.py --binary <probe> --producer <exact-clean-checkout>`
uses the pinned maintained selected-reply producer and real local TLS. It checks
genuine signed history advancement, bounded future server acceptance, a separate
monotonic local floor, wrong scope/identity/signatures, chain/schema failures,
locked/postcommit deadlines, competing-writer CAS, stale-instance refusal, and
reopen/rollback behavior. The existing checkpoint crash/CAS/restored-reader suite
continues to cover storage recovery independently.
Other native runtime probes can use `--command-file <trusted-local-json-argv>`
instead of `--binary`; the helper executes that argument array without a shell.
