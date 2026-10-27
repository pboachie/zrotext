# Candidate managed contact fields

Java, C# and Ruby companions in the adjacent `contact` directories verify genuine
profile-02/generation-1 historical contact reader statements and signed field
commitments. They produce name/notes commitments through explicitly separate
software and protected signer APIs. A verified statement is owned immutable
evidence: callers cannot replace its signed account, reader, root or lifetime.
Independent expected account, canonical origin, root fingerprint, contact and
routing values remain required. This is historical integrity, not current owner
permission, field decryption, mutation acceptance or durable contact history.

Production takes already-framed unsigned `ZTCO01` bytes. It validates their exact
shape and statement binding before a signature. `Expected` captures the caller's
independent scope. `produceSoftware`/`ProduceSoftware`/`produce_software` accept an
explicit native software key; Java requires its public/private key pair. The
native public key must match the statement root before the contact signature.
`produceProtected` and equivalents require the concrete `ProtectedContactSigner`.
That capability signs only the contact-field domain; it cannot sign manifests,
reader statements or sealed messages. Tests use private setup machinery solely
to build genuine synthetic enrollment evidence, independently checked by the
maintained TypeScript implementation.

Production admits at most four unresolved operations and has a fixed ten-second
outward deadline. Cancellation uses Java `AtomicBoolean`, C# `CancellationToken`
or the concrete Ruby `ContactField::Cancellation`, never an arbitrary foreground
host callback. Public-key lookup and signing stay inside the admitted worker.
A cancelled or timed-out operation retains its admission slot until the actual
worker settles. The protected signer rechecks liveness after acquiring its lock
and reading the public key, immediately before signing; a blocked operation
cannot start a signature after cancellation. Native calls already executing
cannot be forcibly cancelled. Late results are suppressed. Callers own keys;
producer cancellation does not delete or close them. Owned temporary byte
buffers are cleared, without a claim of erasing immutable strings or provider
internal allocations.

The protected capability is Windows x64 Microsoft Platform Crypto Provider
P-256, with cumulative provider/hardware, public-point, export-policy,
private-export refusal and actual native ECDSA qualification. It is not remote
attestation. Creation writes a private pending receipt before key creation;
only the created owner can delete that key. Opening an existing matching alias
does not acquire deletion ownership. Keep pending receipts until deletion is
confirmed. A trusted application process and trusted local paths are required.

## Canonical origin dependency

All three targets use the same narrow C ABI over Ada 3.3.0, upstream revision
`9c0370e26b9f9ac1c07c91c5bd7301fc3aaf8794`. The build downloads hash-pinned
official release sources and the MIT license, compiles locally, and emits the
library, complete corresponding source, AGPL wrapper license, Ada notice and
hashed inventory. No prebuilt binary or private checkout path is embedded.
The host supplies the trusted artifact directory explicitly. A missing or
incompatible artifact fails; there is no URI-normalization approximation.
Loaders retain their native library for process lifetime.

Run `python build.py --out <new-directory-outside-checkout>` with C++20 available.
Windows requires a Visual Studio x64 developer environment. The actual local
qualification used Windows x64, Visual Studio 2022, Java 21 compiling release 17,
.NET 10 building net8, and Ruby 3.3.13. Linux CI builds its own platform artifact;
the macOS recipe has no executed qualification claim. This is a pinned build
recipe, not demonstrated byte-for-byte reproducibility or published SDK package
readiness. Ada 3.3 is deliberate: the tested 4.0 ASCII ACE fast path differed
from the maintained Node origin oracle. No hostname exceptions are embedded.

## Repeatable source acceptance

Use `../contact-field-run.py --language java|csharp|ruby --fixture <clean-native-fixture>
--producer <clean-maintained-fixture> --origin-asset <built-artifact>`. It verifies
exact source pins, relocates the complete artifact, compiles source probes, runs
991 shared controls (including 215 origins and three independent field
verifications), and requires missing-parser refusal. Java dependencies are
hash-pinned JNA 5.17.0 and the existing Gson probe dependencies.

On a qualified Windows host, add `--hardware --receipt <new-private-file>` to
require actual protected signing, reopened/closed handle checks, four blocked
cancelled workers retaining admission, fifth-operation refusal, an actual ten-second held-provider deadline, settlement and
exact owned deletion. Unavailable hardware fails this explicit gate. The hosted
workflow exercises software only and does not claim protected qualification.
The source runner is separate from ordinary installed-package acceptance.
