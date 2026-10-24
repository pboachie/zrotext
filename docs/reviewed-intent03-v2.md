# Explicit reviewed-intent V2 verification

`reviewed_intent03::v2` decodes the exact `ZTRI02` format and verifies its
distinct `zrotext/conversation/reviewed-send03/v2` signature transcript. It
retains ten ciphertext and context digests, with the peer and recipient tail
starting at byte520. No plaintext body hash or substitute field is present.
The exact lengths are592 through803 bytes. The original `ZTRI01` decoder,
signature domain and public vectors remain separate.

A decoded intent selects records to authenticate. A `SignatureCheckedIntent03V2`
only establishes a signature over those exact bytes under the supplied public
point. It does not establish that this point is the current root-selected role5
key, that a browser reviewed the plaintext, that an interval is installed, or
that the database accepted the message. Actual effects also require the held
original owner/session, all original consent proofs, accepted election and
current manifest ancestry, physical device lease, exact recipients and live
mapping authority, billing and the authenticated segment ceiling.

The shared synthetic component vector and structural schema have one producer
and are consumed byte-for-byte by the SDK and server. Their real signatures
cover canonical component bytes; the fixture explicitly contains no accepted
database, encrypted message, hardware custody or current authority proof.

The optional server admission and grant/fetch composition selects the immutable
stored intent version and requires V2 for every new effect. It requires the
separate `conversation_reviewed_send03_storage::require_v2` installation
capability; an older admission, grant or native identity schema is insufficient.
The current readers still independently verify actual original owner/session,
installed interval, physical lease, root and manifest ancestry, exact ciphertext,
recipient mappings, current billing and the original signed segment ceiling.

Historical V1 status does not requeue, renew, translate or resign old work. Live
V1 originals and their body digest remain historical; permitted content erasure
requires the storage layer's genuine coupled one-way redaction. V2 stores no body
digest. Already-redacted114 V1 tombstones may retain their original32-byte body
digest as passive metadata; the reader discards it and never reconstructs
originals or permission. A future genuine V1 redaction clears that field in the
same coupled transition. Removing a legacy stored body hash does not promise retroactive
confidentiality for V1 records whose immutable review hashes remain.

`profile03-fetch-permission-v2.schema.json` keeps the ten outer and forty current
fields and the `message_manifest_permission03` discriminator. It requires an
explicit V2 reviewed intent and refers to the unchanged current/interval shapes;
the old V1 packet schema remains separate. Structural validation proves no
signature, database acceptance, freshness or custody.

This optional source is not mounted by the default application. A corrected
storage installation and genuine integrated qualification are required before
enabling it; these APIs do not enable sending or change existing message rows.
