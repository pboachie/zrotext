<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Same-root profile03 manifest successors

Migration112 adds immutable storage for explicit browser signer enrollment,
same-key validity renewal and browser signer replacement after an accepted
profile03 election. It does not mount an endpoint, authenticate an owner,
verify a signature, authorize a content interval or enable messaging.

The narrow install call retains the exact513-byte possession statement, original
signature, signed predecessor and successor, actual acceptance checkpoint and
original owner/session identifiers. The application must independently verify
the existing root signature, browser-key possession and genuine fresh owner
authentication in the same held transaction. Database hashes describe retained
bytes and cache provenance; they establish none of those proofs.

An accepted successor preserves the elected root, binding, generation and
selection epoch. It retains every existing key record. Active keys may extend
their validity with the same point, identity, subject, scope and start time.
Explicit replacement may revoke only the current line's active browser signer
and add one distinct browser signer with new possession. The revoked record and
its original window remain intact. Revoked keys never reactivate. Replacement
can exhaust the canonical64-record format; the database never discards history
to make space. Same-key renewals have no lifetime counter.

The receipt, monotone authority update, accepted manifest history and shared
purpose-separated signing-point reservation commit together. Every new receipt
versions the actual account anchor at unchanged epoch1, so old repeatable-read
and serializable snapshots cannot silently retain the previous selection.
Exact historical retries return the original receipt without renewing its time
or touching that tuple. The ordinary runtime can read receipts and call the
narrow install and read-only retention operations; it cannot mutate rows,
epochs or internal scope helpers.

All accepted ancestry remains available. The exact prefix commitment includes
original signed manifest bytes, possession signatures and acceptance times,
rather than unsigned semantic digests alone. An application must verify the
complete original chain before caching it and bind reuse to that exact prefix
and tip. Transport paging and independently verified client highwater remain
separate integration obligations; storage imposes no lifetime chain limit.

Original activation, election and physical refresh statements are never
rewritten. A later physical selection can retain its original proof only
through actual accepted same-root ancestry preserving its selected reader and
enrolled signing identities. Closing an expired unapproved refresh across a
renewal requires that ancestry and a new explicit ceremony. The application and
phone must independently verify it; SQL cannot recreate a local physical handle.

Every existing message, attempt and content interval stays pinned to its
original context. A new signer or renewal does not translate, retry, cancel or
delete that work. Legacy02 writers remain fenced after election, and current
phone, content consent, quota, grant, fetch and one-use effect checks remain
independent requirements.

# Read-only cache retention

`payload_profile_manifest_retention` matches an exact retained checkpoint and
prefix commitment, then recomputes the entire original retained ancestry on
every call. A warm signature cache must use this capability before reuse;
rereading only the tip's stored prefix cannot detect changed intermediate
received bytes. The capability exposes no mutation and proves no current owner,
device, physical or content permission. Independent original signature checks
and all actual current selection records remain mandatory.
