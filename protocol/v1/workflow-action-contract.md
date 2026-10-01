# Exact workflow action and approval contract

**Normative prerequisite contract; no workflow runtime or route is shipped by
this document.** Scheduling, persisted owner decisions and customer-agent
policies must reuse this contract rather than defining independent approvals.
The executable reference in `tests/workflow_contract_model.py` is a synthetic
conformance oracle, not an authorization service. Related work: #635, #634,
#638, #639 and #615.

## Bound action

An action is identified by `(account_id, action_id, revision, binding_digest)`.
IDs are opaque stable identities, never a phone number or plaintext recipient.
Every revision binds all of these fields, with no defaults:

| Field | Meaning |
| --- | --- |
| `account_id`, `action_id`, `revision` | Tenant, stable logical action, monotonically increasing positive integer |
| `line_id`, `recipient_id`, `purpose_id` | Account-owned line, encrypted contact reference, exact consent purpose |
| `content_ref`, `content_digest`, `content_version` | Immutable encrypted object reference, SHA-256 of exact ciphertext bytes, positive object version |
| `not_before`, `expires_at` | UTC epoch seconds; inclusive earliest dispatch, exclusive expiry |
| `timezone`, `window_id` | Explicit recipient-selected timezone and immutable sending-window policy identity |
| `routine_id`, `authority_generation` | Routine authority identity and positive revocation generation |
| `commitment` | `informational` or `sensitive`; includes downstream tool effect severity |

The exact action contains no body, phone, substitution map or decryption key.
Content references must resolve only in the same account and line. The content
reader validates its ciphertext digest and version; the relay cannot verify
plaintext equivalence. Approval UI must display the exact decrypted action and
its timing, purpose and effects before confirmation. Unknown recipient timing
holds work for owner review; silence does not select a timezone.

For the synthetic conformance format, identifiers and timezone are nonempty
ASCII strings of at most 128 characters, timestamps are nonnegative integers,
and revisions/generations/versions are positive integers (booleans forbidden).
Content digest is 64 lowercase hex characters. Reject extra or missing fields;
require `not_before < expires_at`. Canonical bytes are UTF-8 JSON of precisely
these fields, lexicographically sorted keys, no whitespace, with integers in
ordinary decimal form. `binding_digest` is lowercase SHA-256 of those bytes.
Do not hash a caller-selected subset. Production implementations must match
these canonical bytes and enforce a bounded request before parsing.

## Authority and decisions

Approval is an explicit authenticated owner confirmation, independently of SMS
sender identity, delivery receipts, silence, routine output or content-read
permission. A future delegation must name the exact approve capability and
commitment ceiling; until selected, only owner confirmation is accepted.
Login identity alone does not imply decrypt, root-key custody or permission to
send. A decision binds account, action, revision and binding digest, and carries
an opaque `decision_id`, `approve` or `cancel`, and expected record version.

After account isolation and live owner/session validation, verify current
membership, line ownership, purpose consent and routine generation in the same
transaction as compare-and-swap. The conformance oracle models that fresh
verification as an explicit `authorized` input; never trust this input from an
HTTP request. It additionally compares the owner's account and confirmation.
Foreign, stale, disabled or revoked authority cannot write a decision, even a
replay. Sending remains a separate check at dispatch against fresh consent,
line/device eligibility, routine budget, current grants and generation.

Store a decision's complete semantic request under `(account_id, decision_id)`
for the retention window. An exact duplicate returns its original result and
has no effect; a changed request under the same identity is a conflict. Check
this replay fence after fresh authorization and before version comparison.
Concurrent decisions serialize: one matching expected record version wins;
the loser gets a conflict and must re-read. A duplicate must never reapply an
old approval to an edited action. Every accepted mutation increments record
version. Client retry identity is separate from downstream dispatch identity.

## State transitions

| Current state | Operation | Next state / condition |
| --- | --- | --- |
| proposed, invalidated | approve | approved; exact current binding, explicit owner confirmation, before expiry |
| proposed, approved, invalidated | cancel | cancelled; exact binding and confirmed owner decision |
| proposed, approved, invalidated | edit | invalidated; next revision, any bound-field change, prior approval removed |
| proposed, approved, invalidated | expiry | expired at `now >= expires_at` |
| approved | dispatch | dispatching only at `not_before <= now < expires_at`, fresh send authority, exact approved digest |
| dispatching | authoritative outcome | succeeded or failed; terminal persisted execution evidence |
| dispatching | uncertain outcome | unknown; timeout or uncertain external effect |
| unknown | authoritative reconciliation | succeeded or failed for the same dispatch identity |

Cancelled, expired, succeeded and failed are terminal. Unknown is a hold state,
not permission to retry the effect. Dispatching cannot be edited or cancelled
as if the effect were prevented. Owner takeover blocks subsequent work but
cannot roll back a possibly executed effect. Unsupported transitions conflict.
Edits use compare-and-swap, preserve account/action identity, increment revision
exactly once and are idempotent under a separate update identity using the same
semantic replay rule. Changing timing, content, recipient, purpose, line,
authority, timezone, window or commitment requires a new confirmation. Even
informational-to-sensitive escalation cannot inherit approval. Identical edit
replay returns the stored result; an unchanged new edit is rejected.

A scheduler reserves one stable dispatch identity atomically with transition
to dispatching and a durable outbox record. Retrying transport uses that same
identity and exact bytes. Never turn an unknown outcome into a new effect.
Cancellation and dispatch race on the same record version: whichever commits
first defines whether dispatch can start. Approval/cancel races obey the same
rule; receipts can report outcomes but never approve new work.

## Storage, audit and dependent services

Only encrypted content and minimal routing, digest, timing, state and authority
metadata persist. Audit records contain account/action/revision, decision or
update identity, actor identity, verified authority generation, result/version
and transition reason. No decrypted content, raw recipient, session token or
key enters audit, errors or logs. Rejected foreign IDs use the same not-found
response as unknown IDs; authentication failures do not reveal resource state.

Dependent stores must export encrypted objects, all revisions, decisions,
replay fences, audit records and dispatch/outcome links through authorized
account export. Account erasure removes these records and encrypted objects,
including revoked routine grants and outstanding work; retention policies must
bound ciphertext and audit lifetime. Keep minimal replay tombstones only for
the documented maximum accepted retry lifetime, then reject retries outside
that lifetime rather than accepting them as new. No indefinite plaintext or
hidden reader is introduced. Retention, export and erasure transaction tests
are required when these stores ship; this contract introduces none.

The synthetic vector suite covers foreign/stale decisions, duplicate identity
conflicts, edit invalidation, commitment escalation, concurrent approval/cancel,
expiry boundaries and dispatch uncertainty. It grants no external calendar,
CRM, payment, AI, SMS or other tool effect and enables no production gate.
