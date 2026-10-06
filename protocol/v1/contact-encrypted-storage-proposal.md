<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Proposal: opaque encrypted contact storage, deletion, takeout and legacy conversion

Status: proposal only, for #634. Nothing here is implemented, mounted, migrated or
enabled. Contact names and notes still use the server-held vault key
(`http_owner_contacts/vault.rs`), which does not meet the client-sealing target.
This document settles the storage, deletion, takeout and legacy-conversion
contract that the merged pure formats ZTCO01/ZTCM01
([contact-content-contract.md](contact-content-contract.md)) leave open, so a
later runtime slice has a reviewed target. It adds no route, SQL migration,
verifier change or grant. The companion schema and vector are synthetic and
check only the proposed takeout record shape against the merged vectors.

## Principles

1. The server stores and returns opaque bytes. It never holds a reader key and
   never opens a field, so it cannot convert, search or display a client-sealed
   name or note.
2. Routing identity and purpose-specific consent stay in their existing planes.
   A content write, conversion or deletion never creates consent, clears
   suppression, edits a withdrawal, revives cancelled work or sends anything.
3. A historical signature proves integrity, not currency. The server's stored
   head is a claim; only a client-side high-water that the account owner trusts
   can detect rollback. The server must not present its head as proof.

## Current record (proposed)

Per `(account, contact)` the server keeps at most one current record:

| Part | Meaning |
| --- | --- |
| client revision | u64 from the latest accepted signed mutation, starting at 1 |
| mutation | the exact 368-byte signed ZTCM01 mutation (hex in takeout) |
| name field | exact signed ZTCO01 envelope or absent |
| notes field | exact signed ZTCO01 envelope or absent |
| legacy generation | server counter for the legacy plaintext-era columns, see below |

Only the current record is stored. Superseded fields and mutations are deleted
in the same transaction as the successor is installed; history is not retained
server-side, so earlier ciphertext cannot be recovered from the server.

### Write rule

A write is one compare-and-swap in a single transaction on the contact row:

- create requires no current record, expected revision 0, successor 1;
- update requires stored revision equal to the mutation's expected revision and
  the mutation's previous digest equal to SHA-256 of the stored mutation;
- the supplied fields must match the mutation slots exactly (a present slot
  sealed at the successor revision needs the matching new field; a retained slot
  keeps the stored field byte-for-byte; a clear slot stores nothing);
- account and contact in every header and mutation must equal the authenticated
  account and the path contact; routing digest must equal the digest of the
  stored routing identity;
- a stale or concurrent writer receives a conflict and no partial write. An
  identical replay of the already-accepted mutation returns the same success.

Whether the server also verifies the root signature and accepted-manifest
binding with the merged Rust verifier is an open choice. Either way it is
defence in depth: clients must verify independently and must not trust a server
that merely accepted a write.

## Deletion tombstone

Deleting a contact replaces its current record with a tombstone that keeps only
the contact id, the final client revision and the digest of the last signed
mutation. Fields, the mutation bytes and the legacy columns are removed. The
tombstone lets a client that held revision N detect that the contact was erased
rather than rolled back, and prevents a later create at revision 1 from being
mistaken for a continuation. Owner erasure does not require a signed successor
(the grammar deliberately has none for a saturated revision). Deletion must not
remove consent, withdrawal, suppression, hold or unknown-submission liability
records that existing guards need; which routing identity material those records
may keep after a contact is deleted is an open question for the runtime slice
and must be settled with the existing erasure transaction owners.

## Legacy conversion (local, explicit)

Existing rows keep server-vault ciphertext in `display_name_ciphertext` and
`notes_ciphertext`. Conversion is performed by the owner's client, never by the
server:

1. The client reads the row through the existing authenticated takeout, which
   still opens the legacy fields, together with its legacy generation.
2. The client seals the plaintext to the selected reader, signs an operation-3
   mutation whose expected legacy generation equals the one it read, and submits
   the mutation and fields.
3. In one transaction the server verifies the legacy generation is unchanged and
   no ordinary current record exists, installs the record at revision 1, nulls
   both legacy columns, and increments the generation. Any concurrent legacy edit
   or conversion changes the generation and the conversion is refused.
4. A refused or abandoned conversion leaves the legacy row untouched and still
   readable by the owner. There is no automatic or bulk server-side conversion and
   no downgrade from a current record back to the server vault.

The expected legacy generation in the signed mutation is a historical
consistency check only; the locked server comparison in step 3 is the real fence.

## Opaque takeout

Takeout returns, for each contact, either a `present` record (revision, exact
mutation, each field or null) or a `deleted` tombstone, as in the vector. The
server does not open present records, so takeout of converted contacts
contains no plaintext and the server cannot satisfy a request to display them.
The owner can decrypt only with the account-held reader key; custody of that
key, reader rotation and retained old-reader custody are separate prerequisites
(#821, #823). Takeout of unconverted rows keeps the existing behaviour until
conversion. Pagination and size bounds follow the existing takeout limits; a
record never exceeds 368 + 2443 + 651 bytes plus encoding.

## Erasure

Account erasure deletes current records and tombstones with the contact rows in
the existing transaction, subject to the existing append-only consent and
liability blockers. Backups, replicas and write-ahead logs are outside this
contract; ciphertext is only as private as the reader key's custody.

## Threat and failure cases considered

- Server compromise or operator read: sees ciphertext and routing/consent
  metadata, not names or notes. A malicious server can still withhold, roll back
  or replay a stale record; only a trusted client high-water detects rollback.
- Cross-account or cross-contact substitution: refused by account/contact/routing
  binding in headers, mutation and the AEAD associated data of the merged formats.
- Rollback to an older field after a clear or replace: slots cannot restore an
  old digest; a restored value needs a new signed field at a new revision.
- Concurrent writers and replay: single-row CAS with previous-digest binding;
  identical replay is idempotent, a different request at the same revision conflicts.
- Conversion races with legacy edit or duplicate conversion: locked generation fence.
- Deletion then recreation: tombstone retains the last revision and digest.
- Consent bypass: no content operation touches consent, suppression, holds,
  cancelled work or sending; import and conversion never grant consent.
- Unknown financial submissions and usage debits are unaffected by deletion.

## Not provided by this proposal or its vector

No route, schema, migration, server code, SDK or Android change; no key custody,
reader installation, reader rotation or accepted-manifest admission; no CSV or
manual intake of encrypted fields; no mounted owner editor; no backup or restore
semantics; no production availability. Tests check the proposed record shape and
its consistency with the merged cryptographic vectors; they do not exercise a
server or demonstrate cross-client decryption.
