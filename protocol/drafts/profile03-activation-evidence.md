# Original sealed activation evidence

This historical signature component supports the coordinated profile election
adapter under #1054. It does not capture a database receipt, mint an old binding,
select present authority, mount an endpoint, or enable profile03 messaging.
Missing original proofs cannot be reconstructed from hashes or legacy rows.

Registration evidence keeps the existing `RegistrationEvidence03.canonical()`
encoding unchanged. Its frame label is
`ZTSE/line/payload-profile/registration-evidence/v1`, followed by one NUL and an
unsigned32 BE payload size. The payload contains unsigned32 BE transcript length,
exact original RootLineRegister transcript, raw64 root and approval signatures,
approval point65, approval fingerprint32, paired fingerprint32, and unsigned64
BE original issue/expiry/completion times. Both original low-S signatures and
all redundant signed scope, key and timing metadata must agree.

Activation evidence uses label
`ZTSE/line/payload-profile/activation-evidence/v1`, one NUL and unsigned32 BE
payload size. Its closed payload is:

| Order | Bytes |
| --- | --- |
| registration identity | UUID16 |
| immutable old binding identity | UUID16 |
| original enrolled device point |65 uncompressed P-256 |
| original browser approval point |65 uncompressed P-256 |
| original SEALED-v2 device statement |255 |
| received device DER length | unsigned16 BE |
| exact received device signature | DER8..80; valid P-256 encoding is at most72 |
| original SEALED-v2 owner statement |314 |
| received owner DER length | unsigned16 BE |
| exact received owner signature | DER8..80; valid P-256 encoding is at most72 |
| historical accepted checkpoint | unsigned64 BE |

Every field is required, lengths are exact and trailing bytes refuse. IDs are
nonzero; times are positive and at most the signed64 storage maximum. The
existing v2 device statement and observation codec remains authoritative for
its ranges and purpose2. The owner statement must be its original domain,
exact device statement and SHA256 of the exact received device DER. Existing
v2 canonical high-S signatures remain accepted and are never normalized. The
separate profile03 election raw64 low-S policy is unchanged.

`activation_evidence::verify_original` repeats original registration root and
approval verification, both activation signatures and independently supplied
root/account/owner/session/device/line/generation/registration/key expectations.
It derives the existing `OldBindingIdentity03` commitment using exact original
registration bytes and original statement-plus-signature digests. An expected
binding UUID or reader ID is still an adapter input; equality alone cannot
prove its immutable allocation or accepted physical reader role.

The accepted timestamp is attributed historical metadata. The caller must
establish its actual durable acceptance provenance; the timestamp cannot become
a caller-selected current clock or permission. Original registration lease,
original observed activation lease and present device lease are separate
records. This binary component does not supply the actual observed activation
lease tuple or a present lease fence. Retained database provenance and actual
current state, signature-selected manifests, installed local reader authority,
owner authentication/MFA and effect permission remain mandatory elsewhere.
