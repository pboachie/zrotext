# Managed native candidate packages

These experimental AGPL-3.0-only archives contain the reviewed Java, C# or Ruby
sealed companion modules. They are separate from generated workflow SDKs and raw
webhook packages. Nothing is published to a public registry by this helper.

Candidate coordinates are Maven
`io.github.pboachie.zrotext:zrotext-native-candidate:0.1.0-alpha.1`, NuGet
`Zrotext.Native.Candidate` version `0.1.0-alpha.1`, and Ruby gem
`zrotext-native-candidate` version `0.1.0.alpha.1`. Java requires Java 17 and the
ordinary pinned JNA 5.17.0 dependency; C# targets .NET 8; Ruby requires 3.3.
Ruby consumers use `require 'zrotext_native_candidate'`.

The closed package inventory includes body AEAD, HPKE, canonical signed envelopes,
manifest lineage, elected profile03 proofs/readers, software readers, native
protected recipients/signers, profile02/03 composition and retry journals, root
selection, election selection, and selected original-reply verification/opening.
See [the original-reply boundary and source acceptance](original-replies.md);
installed original-reply acceptance remains a separate gate. Existing authority
adapters remain mandatory.
This inventory does not imply full client/API parity, protected key portability,
production authorization, or registry release readiness. Protected custody uses
Windows PCP and requires actual native qualification; Java supports 64-bit Windows.
Outbound profile03 follows the signed key-lifetime policy; cross-language
alignment remains tracked in issue #1226.

`package-managed.py --target java --out <new-external-directory>` also requires
six exact producer/control checkout arguments listed by `--help`. Run `npm ci
--ignore-scripts` and `npm run build` in each producer's `sdk/typescript` first.
Use target `csharp` or `ruby` for the corresponding archive. Build tools must be
on PATH. The helper requires clean tracked fixture sources at the exact pins.

It builds licensed closed archives, removes runtime source staging, resolves
ordinary Maven/NuGet coordinates with a fresh cache or installs the gem into a
fresh GEM_HOME, and runs external consumers against the installed library.
Consumers reuse root/election restore and reader controls, native recipient
qualification, and both native composition/retry suites. Maintained TypeScript
independently verifies and decrypts native composed ciphertext. Runtime library
sources are never compiled into consumers. The fixture orchestration remains
external to the packages; private generated values and cleanup receipts are not
published artifacts.

On a host without the required native provider, only read-only precreation
capability refusal may be unqualified. Once key creation starts, every failure is
fatal and its exact owned cleanup receipt must be preserved. Inspect `QUALIFIED`
versus `UNQUALIFIED` output separately from archive and software success. Durable
journals assume trusted private paths and fail closed on torn writes; they do not
promise hostile rollback resistance or automatic partial-record repair.
