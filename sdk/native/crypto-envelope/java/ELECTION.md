# Candidate native profile03 election provenance

Java, C#, and Ruby `Election03` verify accepted profile02-to-profile03 election
bundles with their native P-256 cryptography. The returned proof owns captured
accepted records and the verified accepted manifest. The current-authority check
requires a verified profile03 manifest descending from that accepted manifest,
matching authenticated current selection, generations, commitment and permission
deadline. Historical signatures alone cannot renew permission.

Inputs named accepted record, expected core, device signing point, owner approval
point and current authority must come from independently authenticated application
sources. Copying these fields from an untrusted packet supplies no authority.
These modules perform no backend lookup, session/MFA, device attestation, atomic
election commit, grant issuance, replay transaction, SMS action or hardware custody.
Elected envelope decryption is a subsequent composition layer.

Records use the exact closed field sets from the maintained TypeScript accepted
record/current authority contracts. Java accepts maps containing byte arrays and
`Long`/`Integer`; C# accepts dictionaries containing byte arrays and `long`/`int`;
Ruby accepts hashes with string keys, byte strings and integers. IDs and digests
have exact widths and cannot be zero. Integers must be positive signed-64-bit
values, and profile fields must equal three. Unknown/missing fields are refused.
Returned byte fields are copies; no mutable caller arrays become proof authority.
C# token construction checks a private capability even when compiled into a
consumer assembly. Reflection and hostile code inside the same process are
outside these language-level boundaries.

Verification covers exact 500-byte core/628-byte bundle, captured expected core,
challenge/context fields, accepted record hashes of original signed manifests,
semantic manifest identities, root fingerprint, registry key IDs and native
low-S device and owner signatures. The owner transcript includes the device
signature digest. The authenticated commit's new binding ID is not a signed-core
field; it is trusted commit data and is separately compared to current authority.

The dedicated workflow pins the independent maintained producer to
`a5fb59c2c5bc81e80b5b8d4b836afd51c5304653` and runs all native verifiers. The TSV
adapter exports only public election evidence, excluding recipient scalar/body.
Tests mutate every accepted/current field, core and signature boundaries, clocks,
profiles and manifest identity; two signature negatives update the accepted bundle
hash too, proving refusal comes from signature verification rather than only a
digest mismatch. Snapshot isolation and C# same-assembly token forgery are covered.
These are candidate interoperability checks, not release or browser acceptance.
