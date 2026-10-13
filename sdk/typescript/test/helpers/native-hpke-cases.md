# Ephemeral native HPKE interoperability corpus

From `sdk/typescript`, install the existing locked dependencies and run
`node test/emit-native-hpke.mjs`. JSON goes to standard output. `--tsv` emits
tab-separated rows without a header, in this order:

`name profile recipient_private_hex recipient_public_hex enc_hex info_hex aad_hex ciphertext_hex plaintext_hex`

Redirect output only to a temporary directory for the native consumer and remove
it afterward. Do not commit, upload or retain the emitted private scalars. These
are fresh, disposable software keys generated for each run, never application
keys. JavaScript strings and native key objects cannot be reliably wiped;
mutable scalar/CEK buffers are cleared without claiming secure-memory custody.

JSON has `format: "zrotext-native-hpke-interop-v1"`, an explicit scope description,
and six `cases`. Each case adds `role` and `recipient_key_id_hex` to the TSV fields.
Hex values are lowercase without prefixes. Profile 02 has an empty AAD field;
TSV readers must preserve that empty column. All plaintexts are 32-byte CEKs,
recipient and encapsulated points are 65-byte uncompressed P-256 points, and
ciphertexts are 48 bytes including the 16-byte tag. Each case has a fresh
recipient and a fresh encapsulation.

The producer uses the repository's locked `@hpke/core` implementation with base
mode P-256/HKDF-SHA256/AES-128-GCM. Recipient identities use the exact
`ZTSE/key/v1` domain, algorithm `0x0010`, and the serialized public point.
Info includes the applicable `ZTSE/wrap/v2` or `ZTSE/wrap/v3` domain, header,
protected bytes, role, and recipient identity. Profile 03 AAD uses the separate
`ZTSE/wrap-aad/v3` domain; profile 02 preserves empty AAD.

The profile 02 structural header/protected bytes come from the existing draft01
vector with the profile byte changed, as in the existing draft02 signature
corpus. Profile 03 uses the reviewed public contract context. Fresh recipient
keys are not enrolled in those fixture manifests. The resulting cases qualify
only HPKE recipient-wrap interoperability: they are not full envelopes and do
not establish manifest authorization, role eligibility, signature, freshness,
non-exportable custody, durable replay, receiver or physical SMS acceptance.

`native-hpke-cases.test.mjs` runs in the existing Node test discovery. It verifies
exact CEK recovery and refusal after info, AAD, ciphertext and truncation changes,
including refusal of empty profile03 AAD. Independent native consumers must also
run those failures and their own key/point/boundary checks; the producer's own
round trip is not cross-language evidence.
