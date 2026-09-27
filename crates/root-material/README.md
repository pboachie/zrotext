# Candidate root material codecs

This crate shares the proposed generation-one root-possession and encrypted
root-backup codecs without depending on the server, database or network stack.
It is a library, not an owner CLI or a custody implementation.

- `sealed_root_enrollment` encodes and verifies the exact candidate transcript.
  Possession is not enrollment authority or independently compared trust.
- `root_backup` seals and opens the candidate encrypted root-only container.
  Callers supply the root, recovery secret and independently expected identity;
  sealing obtains fresh cryptographic randomness from the operating system.

The server re-exports both modules at their existing public paths. Shared types,
formats, error behavior and public vectors are unchanged by this extraction.
The HMAC zeroization feature is explicitly enabled here so standalone use does
not depend on feature unification through the server.

Run `cargo test --locked -p zrotext-root-material` for the preserved codec and
enrollment tests, and
`cargo test --locked -p zrotext-server --test root_material_compatibility` for
server API interoperability against fixed vectors. Existing workspace CI
discovers both suites. Protocol tests also retain their independent Node/OpenSSL
verification.

There is no recovery-kit/card grammar, terminal or filesystem adapter, network
client, private-key cache, registration, rotation, reset or archive recovery.
These remain separate design and release gates. Memory zeroization is best-effort
hygiene and does not protect a compromised process or promise erasure of every
compiler/library temporary.
