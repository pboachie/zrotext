# Original profile03 reviewed-message admission storage

Migration114 adds `conversation_reviewed_sends03` and a distinct
`sealed_profile03` queue mode. The narrow admission method retains the exact
reviewed intent, original browser signature, authenticated segment ceiling and
original installed interval, owner, manifest, binding and full device connection.
It checks the public envelope framing and exact hashes against that intent.
These structural checks do not authenticate a person, verify P-256 signatures,
decrypt ciphertext or reconstruct a phone's private preparation.

The production adapter must first verify the genuine current owner permission,
original role5 signature, exact envelope and independently verified current
manifest, physical selection, installed interval and reader mappings. It then
captures the sidecar and uses the actual queue and existing billing reservation
in the same transaction. A deferred check requires the matching queued message,
initial dispatch job and one actual outbound usage reservation before commit.
A returned sidecar alone is not a committed admission. Missing or changed
queue, quota, current scope or post-wait deadline rolls back the entire operation.

The sole ciphertext remains `messages.transport_payload`. The queue's segment
ceiling must be present and equal the signed reviewed intent; NULL and a
different valid ceiling both refuse. Experimental03 requires a configured finite
outbound quota. Configured self-hosted manual quotas do not require a hosted
paid subscription. The adapter must preserve the existing account admission,
risk, reconciliation and hosted billing guards, rather than substitute a caller
flag or charge again through a second quota mechanism.

Exact historical retries compare the original intent, signature and envelope
hashes and return the first admission receipt. They do not requeue, reserve
quota again, refresh permission, translate a connection or change the stable
anchor tuple. A new admission versions that actual tuple at unchanged selection
epoch1; retention also participates so old repeatable-read and serializable
snapshots cannot revive erased originals. Conflicting tuple/account lock orders
fail promptly rather than waiting through a lock inversion.

The original intent contains the recipient. When actual terminal-message content
is erased under the existing retention and outstanding-effect rules, the intent,
signature and peer become NULL together. Ciphertext is not duplicated in the
sidecar. Original hashes, accepted context and replay identity remain with a
one-way redaction time. Restoring originals, requeueing or charging again is
refused. Actual account/message erasure keeps its parent cascade behavior.

The ordinary non-owning runtime receives SELECT and the narrow admit/readiness
methods. It cannot edit the sidecar, call internal predicates or change epochs.
Closed body, declaration, graph, trigger, ownership and ACL validation rejects
partial or substituted installations. `conversation_reviewed_send03_storage`
checks this storage capability; it is not an authentication or consent witness.

This migration permits only the exact initial queue/job writes and retained-data
erasure. Claim, attempt, grant, fetch and effect mutations require subsequent
separately typed03 provenance. Existing02 authorization records and callers with
no authenticated segment ceiling do not become03 authority. Real adapter,
billing, maintained receiver and integrated no-radio qualification remain
separate from SQL structural qualification.
