# Exact workflow decisions

The workflow decision service is a dormant candidate library. Its owner HTTP
service, scheduling, integration credentials, and production activation are
separate work. No model output, receipt, silence, or caller-supplied authority
flag approves an action.

An action binds the complete descriptor defined by the workflow action contract.
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

A response correlation requires an original signed inbound event in the exact
context interval and an explicit owner-selected request. The service verifies
the captured envelope and provenance. Only an issued request in its exact
timing window can qualify; the resulting fence stops that routine and unsent
followups without marking the request completed. Ambiguous or late responses
enter the bounded exception queue. A peer match alone is insufficient. Reusing
an event with a different selected request conflicts.

Metadata and replay storage are bounded. Full lifecycle export, erasure, and
retention integration must be completed before this candidate is activated.
