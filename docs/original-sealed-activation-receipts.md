# Original sealed activation evidence

Migration109 retains exact original SEALED v2 activation evidence for future
independent verification. It adds no Profile03 election, current permission or
sending path. The production application must verify both original activation
signatures and the original root-authorized approval-key registration before
calling the narrow capture function. A database digest is not that verification.

The capture takes the account and challenge selectors, exact device/owner
statements, original DER signatures and original signing points. It independently
locks the existing authority, account fence and actual anchor, then matches the
actual fresh registration, pending challenge, observation and device lease.
The database mints the binding identity and acceptance time. A caller cannot
provide those values, a permission boolean or a replacement proof lease.

The original 255-byte device statement and 314-byte owner statement preserve
their existing domains, version, SEALED purpose and signatures. The owner
statement contains the exact device statement and the hash of its original DER
signature. Existing v2 DER acceptance remains unchanged; no new low-S rule or
signature normalization is imposed on old proofs. The original registration
transcript and its two original signatures remain in the existing registration
receipt, referenced by the new immutable record.

Capture occurs while the original pending nonce still exists and before the
first activation mutation. An INSERT-only deferred constraint requires the same
transaction to consume that challenge, approve its pending record, activate the
exact binding and original registration, and retain the actual owner session.
An interrupted or rejected transaction leaves no receipt or minted mapping.
The later Android installation acknowledgement may clear its pending nonce;
it is deliberately a separate transaction. Current readers must independently
require that acknowledgement and current local continuity.

An already-approved activation without the new receipt cannot be backfilled
from digests or later resubmitted bytes. An exact historical retry returns the
original binding identity and acceptance time without renewal. Different bytes
conflict. Historical user/session UUIDs are metadata, with no new live user or
session foreign key to block their existing revocation or erasure. Account and
registration foreign keys preserve account-erasure cascades; ordinary direct
receipt deletion or any update is refused.

Unlike migration096's nonce-free observation record, the new receipt explicitly
retains the consumed nonce inside the exact accepted signed statements. It
contains public signing points, original signatures, pseudonymous identities
and historical lease metadata. This is additional retained evidence, not
anonymous data. No pending statement is exposed by this change. Account erasure
removes these additional records under the existing account lifecycle.

Runtime has SELECT and the narrow capture function only. Provisioning resets
both relation and column grants after broad defaults and on every rerun. The
closed schema validator checks exact helper bodies/metadata and the complete
reviewed graph before consulting runtime readiness. Optional legacy v2 fixtures
without this installation retain their old behavior and cannot claim original
receipt or Profile03 support. Required consumers refuse missing, partial,
changed, disabled or polluted installations.

Function declarations are part of this graph: input/output names, modes and
types, defaults, variadic identity and routine kind are pinned with body/config
metadata. Migration checks the complete predecessor declaration snapshot before
installing the new receipt. The stock runtime verifier independently checks
the capture function's complete input/output type list before calling readiness;
a compatible-looking `record` result cannot substitute a different OUT type.
