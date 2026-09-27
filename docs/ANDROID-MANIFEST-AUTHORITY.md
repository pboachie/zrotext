# Dormant Android manifest authority

`Draft02ManifestAuthority` is a candidate-02 verifier in Android's main source
set. No production message flow calls it. It verifies an exact bounded RootPin02
and Manifest02 against caller-supplied authenticated account, root fingerprint,
generation, chain position and time. A relay response must never supply those
trust inputs merely because it also supplies the manifest.

The caller selects one explicit chain condition:

- `Genesis(anchor)` requires version one. Generation one requires a zero anchor;
  later generations require a nonzero anchor from a previously authenticated
  root transition. This verifier does not verify or accept transitions.
- `After(version, digest)` requires the exact next version and predecessor digest.
- `Current(version, digest)` permits only the same semantic manifest, preventing
  same-version forks while allowing another canonical signature of those bytes.

Parsing enforces exact sizes, signed storage ranges, canonical point encodings,
record order, derived key identifiers, distinct points, role/subject/scope rules,
owner and archive cardinality, a bounded validity window, and the candidate's
low-S owner signature over the exact domain-separated bytes. The semantic digest
excludes the signature. Inputs are copied before parsing; verified objects have
private constructors and never expose mutable internal arrays or records.

The context builder rechecks manifest freshness and selected key validity at use.
It accepts caller-selected account, message, device, line, peer, direction, signer and
ordered readers. Outbound requires the exact selected device and one archive;
inbound requires one archive and no device reader. Both allow at most six explicit
integration readers with the required scope. It returns exact values for a later
envelope signature verifier; it does not verify an envelope, inspect ciphertext,
decrypt a payload, or grant permission to store or send anything.

## Verification and remaining boundaries

The same corpus runs as a JVM test and as a selected no-radio instrumentation
test. It consumes the existing independent TypeScript/Rust genesis and rotation
manifest fixtures without rewriting them. It also constructs synthetic signed
adversarial manifests to test semantic rejection, chain/fork checks, signature
canonicality, time boundaries, signer/readers and array-mutation resistance.
The disposable emulator runner requires all selected tests to complete with zero
failures or skips; no broad instrumentation sweep is used.

Trusted time is an explicit input, not a trusted clock implementation. Durable
chain admission must still atomically compare and persist high-water state before
any effects. Root enrollment and independent fingerprint comparison, owner-key
ceremony, rotation acceptance, lost-key and vault recovery, trusted-clock recovery,
live session/line/grant binding, and a durable encryption/replay journal remain
separate prerequisites. A verified snapshot can become obsolete when durable
trust or live grants change; callers must revalidate those before effects.

This module performs no network access or persistence and requests no permission.
The general sealed send gate stays disabled. JVM and emulator checks provide no
physical SIM, carrier-delivery, reboot-journal or production recovery evidence.
This implementation alone does not complete the sealed-content roadmap capability.
