# Candidate envelope integrity components

`SignedEnvelope.verify` (Java/Ruby) and `SignedEnvelope.Verify` (C#) require an
explicit expected profile and independently supplied signer point. Profile02
supports outbound and inbound shapes; profile03 currently supports outbound
only. Profile01, mismatches and unsupported profile03 inbound fail closed.

The parser checks exact lengths, flags, signed-range integer fields, canonical
peer syntax, nonzero profile03 message identity, bounded expiry, inbound event identity/sequence, body length,
recipient counts/roles/order, all encapsulated curve points, signer key identity,
raw P-256 scalar ranges and low-S canonicality. It verifies the exact
`ZTSE/sign/v2` or `ZTSE/sign/v3` transcript through native ECDSA before creating an
immutable snapshot. Input aliases and returned byte arrays cannot change that
snapshot. Recipient lookup uses the exact `(role,key ID)` pair.

Accessors derive body AAD, HPKE info, and wrap AAD from the verified bytes. Profile02
has empty wrap AAD; profile03 binds its own distinct domain and exact header,
protected bytes, role and key ID. No profile fallback or transcript retry occurs.

**This proves envelope integrity under the supplied key, not authority.** A signer
point supplied from an untrusted envelope or directory is insufficient. The
next reader layer must authenticate the historical manifest chain (including
profile02 predecessor for a first profile03 manifest), bind every expected
account/device/line/audience/key, and separately enforce current authorization,
expiry and replay policy before invoking HPKE or body decryption. An envelope's
internal expiry interval check is not a comparison with trusted current time.
Nonexportable custody and atomic journals remain separately gated under #1128.

## Independent public fixtures

`python sdk/native/crypto-envelope/java/envelope_rows.py` writes public fixture
rows on stdout. The exporter owns no signing or recipient private material.
It reproduces the existing Rust profile02 signature fixture construction from
`ztse-draft-01.json` and `ztse-draft-02-signatures.json` exactly. These two fixtures
prove profile02 signatures/transcripts only: their underlying profile01 payload
and wraps are not profile02 decryption vectors. Profile03 uses the existing
`sealed-profile03-sdk-outbound-01.json` signed envelope and its manifest's signer
point, checking stored body AAD, device info/AAD and unsigned digest independently.
Extracting that point for a test is not manifest verification.

Rows contain nine tab-separated fields: name, profile, envelope hex, signer point
hex, body AAD hex, recipient role, recipient key ID hex, wrap info hex, wrap AAD hex.
The six recipient rows span profile02 outbound/inbound and profile03 outbound.
Each language executes 153 checks, including exact transcripts, profile refusal,
signed-byte mutations, truncation/trailing bytes, high-S alias rejection,
recipient lookup and input/output mutation isolation. These tests do not imply
full reader acceptance or execution by a real recipient device.
