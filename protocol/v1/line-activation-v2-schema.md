# Versioned line activation schema prerequisites

Migrations 095 and 096 prepare storage for a future authenticated version 2 line
activation runtime. They do not enable that runtime. Current challenge issuers,
socket session claims and activation consumers remain version 1; the existing
[v1 line contract](line-activation-contract.md) and its single-subscription
constraint remain in force. The schema does not select the sealed envelope
profile or implement a profile03 producer, election, grant or receiver.

## Session admission metadata

`device_sessions.line_activation_version` is a non-null smallint with default 1
and allowed values 1 and 2. Existing session rows are initialized to 1; new inserts omitting the field
default to 1. Existing claim updates do not assign this field, so they preserve
its stored value, including 2 if an external writer previously selected it.
No production claim writer in this change selects 2 or derives protocol admission
from omission. A change of the value requires a strictly increasing connection epoch;
an ordinary lease refresh may keep the same value. The database rule alone does
not authenticate the connection, prove an installed line or authorize a SIM
observation. A future socket writer must perform that authenticated admission.

## Separate exchange storage

`line_activation_v2_pending` keeps one immutable identity per challenge and one
opening per account and purpose. Its identity includes the original owner
session, account/line/device/generation, purpose, optional sealed registration,
recorded transport tuple and fingerprints, and exact challenge expiry. Insertion
requires a matching unconsumed version 2 challenge and binding purpose. Sealed
purpose requires a registration; SMS purpose forbids one. A pending record can
exist for an expired challenge, but observation admission requires a live one.

The live nonce is separate from durable terminal evidence. Approval hash/time,
installation time and retirement time become write-once when set. Nonces cannot
be replaced or resurrected. Clearing a nonce requires installation or retirement;
installation additionally requires sealed purpose and approval. Pending identities
cannot be deleted. These are storage transitions, not signature verification.

`line_activation_v2_observations` stores one immutable record per pending challenge.
It references the exact pending scope, bounds observation/signature/digest lengths,
and requires a live unconsumed challenge, an unapproved/unretired pending nonce,
and the recorded device fingerprint and site/instance/connection/deployment tuple.
Updates and deletes are refused. Retiring a pending exchange keeps observation
history unchanged. Length-valid bytes are not necessarily valid signatures,
canonical transcripts or genuine Android subscription observations.

The existing v1 exchange tables and their count-one constraints are unchanged.
There is no new runtime route, schema installer, socket negotiation, worker,
cleanup policy, feature-gate change or radio operation in these prerequisites.
Future consumers must still authenticate current owner/device authority, verify
actual cryptographic proofs, exclude conflicting writers, recheck clocks after
waits and implement a separately reviewed lifecycle. The SQL guard does not
substitute for those requirements or establish production v2 readiness.

## Migration and test contract

The consecutive migration inventory is 001 through 096. All complete test fixtures
embed these actual migrations in order. PostgreSQL controls use isolated schemas
and synthetic data to exercise an upgrade from 094 with legacy rows, full replay,
version/epoch changes, pending scope and terminal constraints, observation admission
and immutable history. Their signature-shaped storage bytes deliberately do not
claim cryptographic or hardware acceptance. Migration-runner discovery/replay and
PostgreSQL execution must be qualified separately from source review or compilation.

The first isolated PostgreSQL execution compiled and discovered all six new groups:
five passed and the session-version group failed because its unchanged-epoch NULL
update expected the NOT NULL error before the existing BEFORE UPDATE guard. The
corrected control expects the guard's check violation for that update and tests
the NOT NULL violation separately with an advancing epoch. Neither migration was
changed. The original failure and its logs remain preserved.

The corrected candidate subsequently compiled and passed all six PostgreSQL
groups and all nine exact fixture inventory controls. A real migration-runner
build applied 001 through 096 to a fresh isolated database, with every ledger
filename and checksum matching the source. A second invocation reported the
schema current and left all 96 ledger entries, including timestamps, unchanged.
The actual catalog contained the new session column, both exchange tables and
their guards. This qualifies the bounded schema/migrator prerequisite only;
authenticated v2 runtime, profile03 integration, device/carrier behavior and
Play readiness remain unverified.
