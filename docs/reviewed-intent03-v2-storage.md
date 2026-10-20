<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Reviewed-intent V2 storage

The experimental profile03 reviewed-send ledger distinguishes each original
intent by an immutable `intent_version`. V2 uses the exact `ZTRI02030300`
header and the V2 signature domain. Its existing envelope and unsigned-envelope
digests bind the reviewed ciphertext; it has no plaintext-body digest. The
canonical intent is 592–803 bytes. V1 retains its original 624–835-byte format
for historical decoding.

Migration117 appends the explicit version without rewriting existing V1
records. New admission derives the version from the received bytes. A caller
cannot select a format through a Boolean, default or separate format argument.
V2 always stores SQL NULL in `body_digest`. Its row, exact intent/signature,
accepted time, authenticated segment ceiling and sole message ciphertext remain
coupled to the same transaction's real quota reservation and initial dispatch
job. Deferred checks refuse an incomplete admission.

New admissions, dispatch grants and current fetch permission require V2.
Retained V1 identities remain available to the separately authenticated history
reader, with their original timestamps and hashes. Reposting an old original
does not re-admit, renew, reserve quota or return fresh dispatch permission.
The account-lifetime one-attempt tombstone remains unchanged.

The next genuine content-redaction transition removes a live V1 body digest
alongside its original intent, signature, peer and message ciphertext. It must
meet the existing terminal-state and unresolved-liability conditions. Already
redacted V1 records may retain their historical 32-byte body field; this migration
preserves those records and the reader discards that field. Redacted originals
cannot be restored, rewritten or requeued. Retained V1 intent/signature hashes
can still support candidate reconstruction; no retroactive confidentiality
guarantee is made for V1.

`conversation_reviewed_send03_storage::require_v2` validates the complete current
writer/schema graph and the explicit V2 capability. Previous admission readiness
does not imply V2 support. The closed declaration, column, ACL and native-hosted
identity validators participate in this version transition. A fast constant
version default is accepted only as original V1 metadata; a logical restore may
materialize it without that catalog marker.

The storage capability does not authenticate an owner, verify a signature or
establish current message permission. Actual adapters must independently verify
the V2 role5 proof, original registered evidence, current manifest ancestry,
installed interval, physical selection, device lease and billing policy. Legacy
profile02 and synthetic transport keep their existing admission rules.
