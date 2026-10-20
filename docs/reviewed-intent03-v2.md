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

The separately reviewed storage and effect composition must require V2 for new
admission, grants and execution. Historical V1 status does not requeue, renew,
translate or resign old work. Removing a legacy stored body hash does not
promise retroactive confidentiality for V1 records whose immutable review
hashes remain. These component APIs do not mount an HTTP route, enable sending
or alter any existing message or database row.
