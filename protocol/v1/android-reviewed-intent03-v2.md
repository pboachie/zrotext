# Android reviewed-intent03 V2 receiving path

The Android profile03 fetch path requires the explicit `ZTRI02030300` reviewed
intent. Its separate `ReviewedIntent03V2` parser accepts exactly592..803 bytes,
the ten ciphertext/context commitments through offset520, canonical recipients
and mandatory ceiling1..6. Vault generation and selection epoch must both be1.
The selected role5 signature uses the distinct framed
`zrotext/conversation/reviewed-send03/v2` domain. No plaintext digest, placeholder
or alternative body commitment exists in this receiving path.

The packet parser refuses historical V1 before producing a fetched execution
packet. Current selection and original installed interval checks require the
same explicit V2 type; preparation checks its exact final and unsigned envelope
hashes, both actual role5 signatures, original admitted time, whole-message and
current deadlines, physical lease, installed ancestry and one-use journal before
using the maintained nonexportable recipient. Strict authenticated body decoding,
selected sending subscription and both grant/reviewed segment ceilings remain
independent checks. Preparation does not hash the decrypted body.

The historical `ReviewedIntent03` codec and its V1 vectors stay unchanged. An old
preparing, prepared, aborted or uncertain message record remains a permanent
no-reentry fence; installing this source never translates, re-signs, renews or
removes it. The unchanged grant/fetch wire and current projection do not weaken
that restriction. Older profile02 behavior remains separate.

The [shared V2 vectors](vectors/reviewed-intent03-v2.json) are byte-identical to
the independent protocol producer. Raw component fields and signatures do not
prove actual installed113 permission, held server records, transport provenance,
hardware custody or an accepted radio effect. Source integration is not a release
or operational acceptance claim. Actual Kotlin, maintained provider, server,
device and hosted journey qualification must be reported separately.
