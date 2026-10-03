# Managed reader grant foundation (issue #761)

This is dormant grant metadata, not runtime acceptance. The default
`ManagedGrants` constructor refuses issuance. Only test builds have the
synthetic candidate constructor. No production service-reader or policy issuer,
HTTP grant mutation route, plaintext reader, credentials, model transport,
task seed, key wrap, SEND permission, effect permit or worker is included.

`deploy/compose/migration-candidates/managed_reader_grants.sql` is a proposal.
The migrator does not discover or install it. Future promotion requires a fresh
main and active-owner migration inventory; no promotion number is reserved.
Fixtures explicitly apply the proposal. Installing it does not enable issuance.

The first supported source is `workflow_context_v1`, current head only.
Create/replace loads the actual stored head and immutable ciphertext version in
the grant transaction, verifies its exact revision and SHA-256 digest, and calls
the existing archive-reader validator with `writing=true`. Its manifest, active
interval, creator-session, line/device and selected-reader fences remain intact.
The real contact-purpose consent, expiry, suppression and recipient-hold checks
also run in that transaction. No connector or action principal is fabricated.
An exact owner password and fresh MFA ceremony are required for create/replace;
all authority and clocks are checked again before commit. A bad MFA factor
commits only the existing ceremony failure accounting, without grant changes.

Versions pin an immutable service policy identity and reader generation. The
policy pins provider and budget IDs, versions, digests and finite caps. This
proposal holds public identities/points and commitments only, with no secret
key, credential, instruction text or source plaintext. The existing HPKE key-ID
helper supplies the exact P-256 KEM suite domain (`0x0010`). None of these
synthetic fixture records proves an approved service identity or provider.

Narrowing requires a current owner and an exact expected version. Its selections
must be a subset of the old exact kind/ID/revision/digest tuples; policy, reader,
contact, purpose and instruction commitment must match. Expiry and each limit
can only decrease. This path intentionally does not require fresh source, root,
key or policy authority, so owners can reduce grants after expiry, key loss or
source purge. Empty selections and zero limits are valid reductions. Revoke is
permanent, idempotent and remains available at the 128-version cap.

Consent withdrawal uses the existing issue #634 / PR #767 transaction hook and
permanently revokes all old grants for that account/contact/purpose, including
expired grants. A new consent event cannot reactivate an old ID; a new grant
requires a new ceremony. This implementation is deliberately stacked on that
functional dependency, without changing its owner branch.

Events are append-only through the API and database UPDATE is rejected for
policies, grant versions, selections and events. The privileged database role
can DELETE; no stronger database deletion-immutability claim is made. The owner
erasure handler explicitly deletes these six tables in child-first order within
its existing owner-fenced transaction and reports their counts. Partial proposal
installation fails closed; complete absence preserves ordinary export/erasure.
Export includes expired/revoked history and all public policy/key identities in
bounded pages. Reader generations and policy versions use composite cursors.

Selections retain metadata references without foreign keys to archive rows so
retention can remove source bytes/history independently. Composite account,
grant/version, policy and reader foreign keys constrain grant metadata. Removing
source bytes does not mint replacement authority. Future consumption must repeat
its own current authority checks and cannot treat stored metadata as an effect
permit. Task-bound wraps and atomic exposure admission require separate designs.

Verification: the real PostgreSQL fixtures cover owner/archive/MFA admission,
exact digest/head rejection, immutable rows, cross-account foreign keys, export,
child-first erase counts/rollback, expired/purged reductions, the version cap,
fresh MFA for replacement, creator-session loss, the mounted consent route,
observed account-lock waits, and mounted erasure commit/counts/later-failure rollback.
Run `cargo test --locked -p zrotext-server managed_grants -- --ignored` with a
disposable `ZT_INBOUND_TEST_DATABASE_URL`. Hosted PostgreSQL results and an
independent exact-head review are required before this draft is ready.
