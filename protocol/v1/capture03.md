# Profile03 incoming-content capture

This additive contract preserves the existing profile02 paths and profile03
type2 envelope. The current Android source provides clock/commitment primitives
and component tests. The incoming receiver, protected one-use journal, actual
current-record producer and commit-acknowledgement integration are still separate
work. A schema-valid frame, public signature or downloaded phase grants no
capture permission.

At actual receipt entry, only an already-live RAM interval/physical/session source
may issue a ticket, before decoding, storage or key waits. The ticket retains one
monotonic-instant interval from the authenticated nonce/time anchors. Its lower
bound carries the strongest previous lower plus elapsed time; the existing
conservative upper is unchanged. Width is at most 2000 ms. The envelope observation
is the original lower, not a later comparison or PDU timestamp. Every permission
and deadline check still uses conservative upper time. A missing ticket, lower
before original interval installation or withdrawn source refuses permanently
for that receipt; later setup cannot upgrade it.

The distinct capture permission read and original interval proof projection use
the same primary comparison and bounded end. The end is at most 30 seconds after
comparison and 60 seconds after the first lower, further bounded by the original
owner, interval, device lease, physical source and selected keys/mappings. Current
reads allocate no sequence or capture. Their actual request UUID, capture UUID,
full context and original first observation must match the same pending ticket.

## Canonical commitment

Header8 is `ZTCI` followed by `01 03 03 02`: intent1, envelope3, manifest3,
inbound2. Thirteen UUID16 values end at 216: account, capture, request, interval,
interval receipt, device, line, owner user, original owner session, current
binding, election challenge, original binding and physical refresh. Only the
refresh UUID can be zero, exactly for the independently verified original-v2
physical source. Capture and request UUIDs are distinct; capture is the exact
unchanged envelope's message and event UUID.

Fourteen big-endian u64 values end at 328: binding generation, vault generation,
manifest version, selection epoch, connection epoch, deployment epoch, positive
device sequence, first observed lower, first observed upper, permission comparison,
permission end, first elapsed time, prepared elapsed time and original interval
installed time. All fit positive signed63-bit storage, except the two elapsed
values can be zero. Supported vault generation and selection epoch are 1.

Eighteen digest32 values end at 904: selected physical reader, archive reader,
phone role04 signer, root fingerprint, manifest digest, ancestry prefix, election
commitment, election bundle hash, origin, owner session, device session, physical
selection, original interval statement, original owner/phone/install signature
hashes, final signed envelope hash and exact unsigned envelope hash. There is no
plaintext body digest, replacement digest or dummy value.

The tail is peer-length1, canonical ASCII E.164 peer3..16, recipient-count1 and
one through seven sorted `(role byte,keyId32)` records. Exactly one archive role2
and zero through six explicitly selected role3 readers are allowed; role1 is
never an incoming recipient. Total intent length is 942..1153 bytes.

The selected actual role04 signs the distinct framed transcript
`ZTSE/conversation/capture-intent03/v1`: ASCII domain, NUL, u32 big-endian byte
length, exact intent. Signature is P256 raw64 strict low-S. The separate
unchanged envelope signature still uses `ZTSE/sign/v3`. The enrolled device
signer and original SEALED approval key are independently selected identities,
not aliases for role04.

## Durable order and recovery

The actual integration must retain the original dedupe/route identity before
network, then reserve a positive global profile03 sequence before hardware.
After sealing, persist the exact unsigned envelope and burn ENVELOPE_SIGN before
its hardware signature. Persist the final envelope, derive the exact commitment
and burn INTENT_SIGN before its separate signature. Persist the completed packet
before upload. A signature that may have run never regenerates. Sequence and
dedupe history survive bindings, connections, Stop and content retention.

The actual server independently verifies original interval proofs, current
owner/full lease/physical/manifest/registry context, both signatures and exact
ciphertext linkage in the same admission transaction as its sole content store
and unchanged shared quota debit. An ACK is emitted only after commit. Actual
socket epochs are JSON integers; projection counters, sequence and times are
canonical decimal strings. Closed shapes are in `profile03-capture.schema.json`.
Ingress is at most 48000 UTF8 bytes; replies at most 192 KiB. Both real transport
layers still need boundary qualification before mounting.

UNKNOWN preserves the exact original packet and burned history. There is no
automatic retry or re-signing. An explicit exact-byte retry needs the still-live
original scope and deadline; after Stop, expiry or reconnect only passive exact
receipt status is allowed. `not_found` is never proof of nonacceptance. A late
accepted status can mark historical completion without restoring RAM authority.
Expired effect-ineligible work may leave the 16-item live RAM set while immutable
history remains; retained history is not a lifetime capacity counter.

The actual receiver must select one permanent storage/content route per receipt
and refuse preexisting legacy capture/metadata identity. It must preserve local
withdrawal and all opt-in/opt-out reporting before new capture waits. Profile03
refusal cannot fall back to ordinary captured-content storage or spend a second
storage budget. Ordinary notification and consent reporting remain separate.

The public synthetic capture vector has exact 942/1153 intent and 426/34082 envelope
extrema, distinct real signing roles, original registration/activation/election
and interval proofs. The producer checks reciprocal software HPKE and changed
AAD before discarding private keys. These components do not prove a genuine OS
receipt, protected local journal, maintained hardware/provider, authenticated
current server records or database/carrier acceptance.
