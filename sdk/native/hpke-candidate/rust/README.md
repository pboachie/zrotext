# Candidate native HPKE recipient

Implements RFC9180 base-mode DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
AES-128-GCM for opening one 32-byte CEK at sequence zero. Public and encapsulated
keys must be canonical 65-byte uncompressed valid P-256 points. The declared
recipient public point must exactly match the supplied private scalar. Info and
AAD are opaque exact bytes, each bounded to 36KiB; the ciphertext must be 48 bytes.
No sender, key derivation, PSK/auth mode, sequence advancement or exporter API
is provided. Never reuse this primitive as a streaming HPKE context.

`open_software_cek` / `OpenSoftwareCEK` explicitly accepts software, exportable
private material. Caller-owned keys are never consumed or claimed protected.
Rust uses zeroizing derived-key/output buffers; Go clears visible derived
buffers, but provider copies and caller buffers have no erasure guarantee.
Callers must clear returned CEKs after body decryption.

`open_protected_cek` / `OpenProtectedCEK` returns protected-provider-unavailable.
It never imports a scalar or silently falls back. This package does not supply a
maintained OS/hardware custody provider, atomic persistence, or device authority.

Use only after independently verifying the envelope signature and canonical
transcript, historical provenance, current manifest authority, recipient scope
and replay state. Those layers are not implemented by this primitive. A valid
HPKE tag is not authorization. Unsupported provider paths remain unavailable.

Rust requires 1.97.1 and the same RustCrypto dependency versions used in this
repository; Go requires 1.22 with standard-library cryptography only. Both
interop executables read ephemeral JSON vectors on stdin from the independently
implemented TypeScript `@hpke/core` producer in issue1144. They check all six
profile02/profile03 role vectors and context/key/point/tag/length corruption.
No private scalar or CEK fixture is committed. This is candidate component
interop, not full sealed-reader, registry, production or protected custody
acceptance. See issue1128 for the remaining native protocol layers.

Reference: https://www.rfc-editor.org/rfc/rfc9180.html sections4-5 and7.

## Envelope integrity

`VerifyEnvelope` (Go) / `envelope::verify_envelope` (Rust) validate profile 02 outbound/inbound and profile 03 outbound, including canonical layout, signed-storage integers, recipient ordering and P-256 points, signer key-ID binding, and domain-separated low-S ECDSA. Owned tokens produce exact body/wrap transcripts and unsigned-content digests.

This is signature integrity, not authority: correct verified manifests, current signer/recipient authorization, replay state and protected custody remain caller requirements. Profile 01 and profile 03 inbound are refused. No full reader is claimed. The pinned public exporter supplies six recipient rows; native tests cover exact transcripts, every single-byte mutation, truncation, trailing data and input aliasing.

## Manifest provenance

Root enrollment requires the separately compared fingerprint of a generation-one root pin. The native manifest verifier validates profile 02 genesis and exact successors, profile 03 upgrades from a still-fresh verified 02 predecessor, and profile 03 successors. Re-verifying the same semantic unsigned identity accepts an independently valid alternate signature; forks, gaps, downgrades and comparison-clock regression refuse. Tokens own signed bytes and root identity, and validate native points, key IDs, role/subject/scope rules, owner/archive counts, low-S signatures and signed validity windows.

The current implementation supports generation one with the zero genesis anchor. Root transitions and later generations refuse. These tokens prove signed provenance, not the freshness of an external authority source. Atomic durable selection, reader permission, replay/election/grant state, protected custody and a complete decrypting reader are not supplied by this module.

Run the `manifest` executable with `protocol/v1/vectors/sealed-profile03-contract-01.json` on stdin. Both native lanes exercise public signed genesis/successor/current fixtures and all single-byte mutations, root corruption, forks, gaps, downgrade, comparison rollback, wrong expected profile, and truncation/trailing data. No new private fixture material is introduced.
