# Exact workflow decisions

The workflow decision service is a dormant candidate library and unmounted owner
HTTP router. Scheduling, integration credentials, and production activation are
separate work. No model output, receipt, silence, or caller-supplied authority
flag approves an action.

An action binds the complete descriptor defined by the workflow action contract.
Edits retain the action's context and routine identity; changing either requires
a new action. This preserves bounded takeover and context retention ownership.
The service stores immutable revisions and their canonical SHA-256 digest. An
owner decision requires a current authenticated owner session, exact revision
and digest, expected record version, and a replay-safe request identifier. An
edit invalidates approval; irreversible actions cannot be edited into another
effect. A replay returns the recorded result without applying it again.

Production purpose identifiers are closed: UUIDs ending in `000001`, `000002`,
and `000003`, with all preceding digits zero, mean `transactional`,
`operational`, and `marketing` respectively. Other identifiers are refused.
The current contact consent record for that purpose, recipient suppression,
owner hold, context reader authority, manifest generation, interval, routine,
and expiry are independently checked. The normative canonicalization fixture
uses abstract identifiers and does not confer production authority.

`LockedAction` is created only by the live owner authorization path and borrows
its transaction. Scheduling consumers must write in that same transaction.
It exposes immutable action metadata and the actual initiating owner identity;
stored actor identifiers cannot recreate a session or decision authority.

Before dispatch, the owner separately confirms an exact signed encrypted
message and its digest. The server verifies its recipient, line, manifest,
signature, expiry, and exact action link. It cannot compare encrypted plaintext
with a content commitment. Customer software must render and verify that
equivalence before confirmation. The message link and dispatch identity are
immutable and permit one effect for one approved action.

Human takeover fences the context and its routines before cancelling unissued
messages through the shared delivery transaction. An already-issued grant is
reported as irreversible and remains unknown; takeover never claims to recall
it. Grant issuance, encrypted retrieval, and first durable radio intent each
check the current workflow fence independently.
These checks also require an active conversation interval and its current,
verified originating owner session. Pause, withdrawal, and origin revocation
fence new effects immediately without waiting for retention.

Safety records do not consume the discretionary mutation journal. The bounded
context fence stores one exact takeover request, digest, and result; repeating
that request returns its original result, while a different request for the
stopped context conflicts. A qualifying signed response stores one exact STOP
result per immutable routine. Later events cannot allocate another routine STOP
and are classified as ambiguous. All operations share the same account-scoped
request identity checks, so a safety request cannot be reused for another action.

A response correlation requires an original signed inbound event in the exact
context interval and an explicit owner-selected request. The service verifies
the captured envelope and provenance. Only an issued request in its exact
timing window can qualify; the resulting fence stops that routine and unsent
followups without marking the request completed. Ambiguous or late responses
enter the bounded exception queue. A peer match alone is insufficient. Reusing
an event with a different selected request conflicts.

The router accepts JSON POST requests under `/v1/owner/workflow/`: `actions`
proposes a descriptor; `actions/status` reads a key; `actions/decide` records an
explicit `approve` or `cancel`; `actions/edit` replaces the revision;
`actions/bind` confirms rendered ciphertext; `responses/correlate` selects a
signed response; and `takeover` stops a context. Every endpoint requires the
existing live owner session and CSRF mutation proof, including the read-only
status POST. Responses are no-store and nosniff. The request schema is
[`workflow-decisions.schema.json`](../protocol/v1/vectors/workflow-decisions.schema.json).
Database authority checks also enforce relationships and current time; schema
validation alone grants nothing.

Metadata and replay storage are bounded. Owner export includes independent
20-row pages for actions, versions, mutations, correlations, message links,
routines, and context fences. The query cursors are `workflow_actions_before`,
`workflow_action_versions_before`, `workflow_action_mutations_before`,
`workflow_correlations_before`, `workflow_message_links_before`,
`workflow_routines_before`, and `workflow_context_fences_before`. Each opaque
cursor belongs to its account and ledger. Export of historical metadata does
not restore a revoked reader or permission.

Account erasure deletes these records before context and message parents in the
same transaction, preserving existing erasure blockers. Context retention
purges encrypted bytes at the existing deadline. Later metadata pruning waits
for linked messages to disappear before deleting action authority, so a
surviving message cannot lose its workflow fence. A stopped routine or context
cannot be reopened by clearing its stop timestamp.
Reply correlations retain immutable event identity and replay metadata while a
nullable live-provenance reference clears during source retention. This permits
provenance and event erasure without restoring source or execution authority.

Message retention clears only the live message reference through its foreign
key. The original message identifier, dispatch identifier, ciphertext digest,
and exact action binding remain immutable tombstones. Recreating a message with
the same identifier cannot restore a live workflow effect. Signed inbound
provenance remains while a reply-correlation ledger references it; cleanup
removes those references with their expired context metadata.
