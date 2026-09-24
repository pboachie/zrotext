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
