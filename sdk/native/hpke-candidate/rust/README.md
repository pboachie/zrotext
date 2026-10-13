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
