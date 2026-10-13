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

## Candidate archive reader

The software archive reader now joins verified generation-one profile02 manifest history, current archive-key permission, canonical inbound envelope signature verification, HPKE CEK recovery and strict AES256GCM UTF-8 body opening. Caller routing (account/device/line/peer), reader key ID, trusted time and independently selected current manifest are mandatory. Historical manifest membership is checked against the exact verified current chain, bounded to1024 versions. A valid current successor retaining the reader can open old ciphertext; a successor rotating away that reader refuses.

Only inbound profile02 with exactly one archive wrap is supported here. The generic protected entry point remains refusal-only; Windows callers use the qualified hardware adapter described below. Software scalars never silently satisfy protected custody. This reader returns text, never a radio grant, live audience permission, durable replay receipt or SMS authorization. Root transitions, profile03 elections/receiver integration and other platform providers remain separate work.

CI pipes the pinned maintained TypeScript producer directly through a synthetic successor-control adapter into both native readers. The adapter uses only the producer's publicly known synthetic signer and fresh replacement archive keys; no real credentials are read. Tests cover actual cross-client plaintext, signed current-key rotation, routing/time/profile/private-key failures and every single-byte corruption. Test outputs remain transient; no fixture scalar is archived. Rust's base64 dev dependency decodes the independent JSON producer format only.

## Windows protected recipient

The native Windows adapter now opens and creates P-256 keys in Microsoft Platform Crypto Provider. Qualification requires the hardware provider flag, export policy zero, private export refusal, exact ECDH P-256 public blob and a native ECDH comparison against an independent ephemeral software peer. A provider label or unsupported private-blob response alone does not qualify a key. No private recipient scalar is imported or exported, and no software fallback or provisioning is attempted. This is local platform evidence, not remote attestation.

Creation requires a trusted callback to durably record the fresh exact alias before the key is created. Keep that receipt private and retain it if any cleanup fails. Reopening requires the independently expected public point. Deletion targets only the owned handle, never a namespace enumeration. Close releases handles without deleting a persistent key. Unsupported platforms keep the refusal-only entry points; Windows callers explicitly use the qualified hardware adapter and hardware archive reader.

`run-cng.py` builds native examples and verifies the pinned public-point-only TS producer. It exercises fresh creation, native archive opening, persistent reopen, binding/closed-handle refusal and exact owned-key deletion. Windows CI without a suitable provider reports **not qualified**, rather than claiming protected acceptance; any failure after creation is a test failure. Private pending receipts remain outside the source tree and are never uploaded. Getrandom is used by Rust for fresh aliases and the qualification peer. Temporary buffers are wiped where owned; provider/runtime copies are not guaranteed erased.

`HardwareRecipient` must not be copied after first use: it contains a mutex and owns native handles. Pass its pointer and explicitly close it when finished.

## Accepted profile03 election and opening

The election verifier requires independently authenticated exact expected core, accepted record and registry signing points. It verifies the original signed profile02 predecessor, exact successor profile03 evidence hashes, commitment and bundle hashes, device and owner low-S signatures, and account/root/device/line/reader identity. Application records use closed binary/numeric field maps; all numeric values are positive signed-storage integers. The returned proof owns the accepted snapshot. `newBindingId` comes from the independently authenticated accepted record and is compared to current authority; it is not invented from the signed core.

Current verification requires the exact accepted election on the selected manifest lineage, current binding generation, selected reader, root identity, commitment/bundle hashes and permission deadline. The outbound03 reader additionally binds the independent expected message and peer, current signer/recipient permissions at observed and comparison time, manifest and permission deadlines, HPKE wrap transcript and AES-GCM body authentication before strict text decoding.

Software entry points explicitly accept exportable scalars. Windows hardware entry points accept only the existing qualified native recipient. The conditional native acceptance runner exercises actual profile03 ciphertext through independently qualified Windows custody; software fixture checks remain separate. No live audience grant, backend/MFA authority, durable replay receipt, remote attestation or radio permission is supplied.

The pinned maintained TypeScript election producer feeds fresh synthetic ciphertext directly to native examples. Controls cover closed records, binary/numeric identity changes, signatures after independently recomputing the accepted bundle hash, comparison/deadline failures, exact peer/message, actual plaintext and every single-byte envelope mutation. No private fixture is committed. Durable CAS election persistence remains separate work.

`run-cng.py --profile 3 --producer <pinned-checkout> --language rust|go` selects the reviewed election producer revision and refuses a fixture exporting the selected reader scalar. Both examples open the actual maintained TypeScript ciphertext through a freshly created and reopened native PCP key, refuse wrong peer/valid wrong public point/closed handles, then delete only that owned key and reject reopening it. The receipt is flushed before creation and stays private if cleanup fails. Profile02 remains the default runner mode. Hosted capability absence is explicitly unqualified, never a software fallback or hardware acceptance. These tests do not establish remote attestation, live authority or durable election selection.
