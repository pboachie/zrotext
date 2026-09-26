# Unapproved sealed draft fixtures

`ztse-draft-01.json` contains nonsecret, synthetic candidate bytes. The fixture
keys are for tests only; the repeated `manifestDigest` bytes are a placeholder,
not a valid owner-signed manifest. `protectedHex`, `unsignedHex`, `signatureHex`
and `envelopeHex` pin byte boundaries for other runtimes. The TypeScript suite
checks RFC 9180 P-256 base mode, decrypts both fixture kinds and runs malformed
and re-signed tamper cases. The Python suite independently checks the byte
shape, transcript boundary and unsigned digest.

No production client may accept this fixture as an authorized message. The
accepted ZT-009 revision, Android and Rust differential results, manifest
chain/recovery and adversarial authorization corpus remain required before
these can become release vectors.

`ztse-manifest-identity-01.json` is a synthetic, unapproved profile-02
manifest-identity fixture for the ZT-009 Q6 correction: the manifest's
authorization identity is `SHA-256(exact_unsigned_bytes)`, not a digest of the
signature, and signatures are canonical low-s P-256. It pins one unsigned
Manifest02 prefix, two independently generated valid low-s signatures over it
(one semantic digest, two distinct complete-byte digests), the high-s twin a
strict receiver must reject, a strict DER corpus (nonminimal, negative, zero,
overflow, trailing and length-mismatch rejections plus one valid encoding), and
one mutated unsigned field with a different digest. The Rust suite
(`crates/server/tests/zt_manifest_identity_digest_vectors.rs`) and the
TypeScript suite (`sdk/typescript/test/manifest-identity-vector.test.mjs`)
consume these same bytes and must reach identical digests and accept/reject
verdicts. The root key was generated ephemerally and discarded; only its public
point is published.
