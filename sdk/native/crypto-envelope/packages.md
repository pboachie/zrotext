# Managed native candidate packages

These experimental AGPL-3.0-only archives contain the reviewed Java, C# or Ruby
sealed companion modules. They are separate from generated workflow SDKs and raw
webhook packages. Nothing is published to a public registry by this helper.

Candidate coordinates are Maven
`io.github.pboachie.zrotext:zrotext-native-candidate:0.1.0-alpha.1`, NuGet
`Zrotext.Native.Candidate` version `0.1.0-alpha.1`, and Ruby gem
`zrotext-native-candidate` version `0.1.0.alpha.1`. Java requires Java 17 and the
ordinary pinned JNA 5.17.0, Gson 2.14.0 and Error Prone annotations 2.48.0 dependencies; C# targets .NET 8; Ruby requires 3.3.
Ruby consumers use `require 'zrotext_native_candidate'`.

The closed package inventory includes body AEAD, HPKE, canonical signed envelopes,
manifest lineage, elected profile03 proofs/readers, software readers, native
protected recipients/signers, profile02/03 composition and retry journals, root
selection, election selection, selected original-reply verification/opening, accepted-history
checkpoints, bounded original-grant HTTPS, and authenticated current-proof clients.
See [the original-reply boundary](https://github.com/pboachie/zrotext/blob/a51c04d87ee51eaf1912b877f1cc9666f02af8cf/sdk/native/crypto-envelope/original-replies.md); the installed gate also
runs its software and protected-recipient consumers against the archived library. Existing authority
adapters remain mandatory.
This inventory does not imply full client/API parity, protected key portability,
production authorization, or registry release readiness. Protected custody uses
Windows PCP and requires actual native qualification; Java supports 64-bit Windows.
Outbound profile03 follows the signed key-lifetime policy; cross-language
alignment remains tracked in issue #1226.

`package-managed.py --target java --out <new-external-directory>` also requires
twenty-two exact producer/control checkout arguments listed by `--help`. Run `npm ci
--ignore-scripts` and `npm run build` in each producer's `sdk/typescript` first.
Use target `csharp` or `ruby` for the corresponding archive. Build tools must be
on PATH. The helper requires clean tracked fixture sources at the exact pins.

It builds licensed closed archives, removes runtime source staging, resolves
ordinary Maven/NuGet coordinates with a fresh cache or installs the gem into a
fresh GEM_HOME, and runs external consumers against the installed library.
Consumers reuse root/election restore and reader controls, native recipient
qualification, both native composition/retry suites, and selected original-reply
signature, authority, software-opening and native protected-opening controls.
Installed history consumers also run concurrent process CAS, restart and interrupted-append
refusal. Installed HTTPS/current-proof consumers run synthetic TLS framing, timeout,
redirect, duplicate-field, signed authority and durable checkpoint controls. These
controls retain their independent fixture revisions and execute without compiling
runtime sources into test drivers. HTTPS uses caller-held original grants and never
automatically retries uncertain outcomes. Installed consumers additionally run
verified reads with final network proof, signed page/cursor discovery, saved
owner-review consumption/status, and typed proposal binding/reconciliation.
Separate original and output credentials remain confined to their respective
operations. Exact saved descriptor bytes are retained after an uncertain
response; status recovery never issues a second consume. These checks use
independently pinned shared fixtures and ordinary installed runtime modules.
They do not establish deployed service authority or full legacy SDK parity.
On qualified Windows PCP hosts, the installed gate also opens selected replies
through native custody and repeats final-proof TLS negatives over an owned
protected key. A precreation capability refusal remains explicitly unqualified;
failures after key creation are fatal and preserve cleanup receipts.
The original-reply producer is pinned separately; its native mode receives only
the recipient public point and never supplies that recipient's private scalar.
Maintained TypeScript
independently verifies and decrypts native composed ciphertext. Runtime library
sources are never compiled into consumers. The fixture orchestration remains
external to the packages; private generated values and cleanup receipts are not
published artifacts.

Installed template consumers also compare canonical content and SMS segment
previews with the maintained TypeScript oracle. Authenticated ZTWT01 controls
exercise software sealing/opening, current-authority fences, malformed scopes,
clock regression, tampering and size limits. TypeScript independently opens two
fresh native seals. On a qualified PCP host, the same installed library opens
ciphertext addressed to a fresh nonexportable recipient; both normal completion
and interrupted fixture setup require exact owned-key deletion. No private
recipient scalar is supplied. Template content and crypto are included in the
closed runtime inventory. Separate owner-template modules add authenticated cold
reads and reviewed save, explicit retry and GET reconciliation. Twenty-two external
consumer suites now include the cold/save state-machine comparisons, exact
Cookie/CSRF and ciphertext identity, busy/close/deadline fences, lifecycle and
framing controls. A matching read never silently acknowledges an uncertain write.
The shared fixture explicitly uses a 1000ms post-handshake caller budget for
Java/C# and 100ms for Ruby; delayed responses/callbacks exceed that budget and
the separate 100ms pre-dispatch refusal remains enabled. No library default or
retry behavior changes. These are synthetic installed-client checks, not live
owner-service or full legacy-client acceptance.
The output manifest records the fixture revisions and this installed
owner-template acceptance separately from archive hashes and native qualification.
Installed opening and authoring consumers add independently pinned lifecycle
comparisons. Opening proves current client/recipient binding and suppresses
plaintext after client or provider loss; a matching pending read remains
unacknowledged. Reviewed authoring copies one draft, requires explicit approval,
preserves foreign reviewed tickets, and returns an opaque ticket without HTTP.
The original authoring lifetime still bounds subsequent client operations.
Ruby additionally rejects nonboolean objects with misleading equality methods
before sealing or dispatch. The protected opening fixture uses fresh owned keys
and verifies provider closure and exact deletion after interrupted setup; it
does not delete keys borrowed by application lifecycles. Software opening uses
an explicit 1000ms post-handshake fixture budget across these three targets.
The manifest records protected opening separately; unavailable custody is not
qualified by software success. These tests do not establish DOM/browser
activation, public registry installation or live owner authority.
C# internal primitive-width unit checks remain in the ordinary source harness.
The external installed assembly tests public template APIs; its dedicated
`ZROTEXT_INSTALLED_CONSUMER` symbol excludes only that internal-access prelude,
without exposing additional runtime methods or changing shared fixture controls.

On a host without the required native provider, only read-only precreation
capability refusal may be unqualified. Once key creation starts, every failure is
fatal and its exact owned cleanup receipt must be preserved. Inspect `QUALIFIED`
versus `UNQUALIFIED` output separately from archive and software success. Durable
journals assume trusted private paths and fail closed on torn writes; they do not
promise hostile rollback resistance or automatic partial-record repair.


Contact consumers add historical profile-02/genesis-root statement and field
verification plus domain-limited software/protected field production. The runtime
archives contain 26 Java, 32 C# and 32 Ruby modules. Consumers use only public
installed APIs. A separate platform-specific origin ZIP accompanies each feed:
its complete source, Ada 3.3.0 MIT notice, wrapper AGPL license and closed hashed
inventory are checked before fresh extraction. Callers pass that trusted installed
asset directory to ContactOrigin; there is no source-checkout library lookup.
The ZIP records its platform in its name and the outer qualification manifest;
only the exercised OS and architecture are qualified. Windows x64 was exercised
locally. Linux workflow qualification and macOS support must be assessed from
actual results, not inferred from another platform's binary. No public registry
or universal native asset readiness is claimed.

Pass `--origin-asset <trusted-build-output>` to the package helper after running
`contact-origin/build.py` outside the checkout with the appropriate C++20 compiler.
The ZIP is installed separately from the managed runtime coordinate. It retains
complete corresponding source so this distribution does not depend on a private
build tree. Software controls compare 991 cases with the maintained independent
oracle. Protected consumers create their own key and receipt, then an external
fixture borrows only that alias to sign synthetic enrollment evidence. It closes
its borrowed handle without deletion. The ordinary installed field capability
produces three independently verified commitments and rejects cancellation,
closed handles and wrong scope. EOF during setup must still delete the exact
owned key. A read-only precreation signing-capability refusal is recorded as
unqualified; failures after creation remain fatal. Historical integrity is not
current contact permission or durable history.

Installed mutation consumers additionally exercise 1536 signed mutation and transition
controls and independently verify four produced transitions. The separate
`--mutation-fixture` checkout is pinned in the helper and workflow. Protected
consumers use the same exact-owned synthetic enrollment lifecycle, then produce
four transitions through the public mutation-only signing capability and reject
twelve closed, cancelled or foreign-scope attempts. Worker-lock/admission controls
remain source tests; installed probes do not reflect into private runtime state.
The archives retain all inherited acceptance suites and the relocated origin asset
boundary. Mutation integrity does not establish current permission or persistence.
