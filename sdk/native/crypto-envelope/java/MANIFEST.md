# Candidate managed manifest provenance

Java `ManifestChain`, C# `ManifestChain`, and Ruby `ManifestChain` verify signed
generation-one historical manifest chains using native P-256 verification.
Enroll a profile02 root pin against an independently authenticated fingerprint,
verify profile02 genesis, then pass the returned token into each continuation.
Every received manifest is checked, including a different valid signature over
the same unsigned current manifest. Tokens own their byte snapshots; exported
arrays and key records are copies. The C# assembly and Ruby process are trusted
implementation boundaries, not sandboxes against reflection or hostile code.

The modules enforce canonical records, key/point/role binding, low-S signatures,
time windows, exact version and previous-digest continuity, and explicit expected
profile. The first profile03 manifest requires a still-fresh verified profile02
predecessor. Profile03 successors may outlive their historical predecessor.
Comparison time cannot move backwards. Time and fingerprint authenticity remain
caller responsibilities. Root rotation, generations above one, profile03
genesis, and downgrade to profile02 are refused.

These tokens establish historical cryptographic provenance. They do not establish
durable current selection, live authorization, envelope signer/recipient
eligibility, hardware custody, or complete decryption. Before application effects,
a subsequent integration must atomically persist the selected high-water state
and bind envelope identities and times to the appropriate authenticated manifest.
No registry package or release readiness is claimed.

`manifest_rows.py` exports only checked-in public fixtures from
`sdk/typescript/test/vectors/draft02-genesis.json` and
`protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json`. TSV fields are name,
comparison time, root pin, compared fingerprint, profile02 manifest, semantic
digest; the chain row appends profile03 manifest, successor, alternate current
signature, and later comparison time. Binary fields are hexadecimal. The exporter
independently checks the profile02 semantic digest before emitting it.

Run `manifest_rows.py` into a temporary TSV and pass stdin to Java `ManifestTest`,
C# `manifest-tests/ManifestTest.csproj`, and Ruby `manifest_test.rb`. The dedicated
workflow runs all three against the same public fixture bytes. Tests cover signed
genesis, transition, successor, semantic currentness, snapshot isolation, modified
records/signatures, truncation, fingerprint mismatch, expiry, rollback, downgrade,
clock regression, and chain gaps. These fixtures contain no recipient private keys.
