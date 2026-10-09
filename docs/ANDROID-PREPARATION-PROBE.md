# Isolated candidate preparation probe

The optional debug probe compiles the existing candidate preparation, envelope,
body, Keystore, HPKE and Room code. It does not enable gateway operation. Its
independent test sender uses the existing test-only Tink dependency. Trust,
session, line and time inputs are synthetic: passing this probe does not prove
their independent provenance, reboot freshness, SIM continuity or carrier delivery.

Build with `-PisolatedPreparationProbe=true` and the existing
`:app:assembleDebug :app:assembleDebugAndroidTest` tasks. In that mode the app ID
is `org.zrotext.gateway.preparationprobe`, the instrumentation ID adds `.test`,
and release variants are disabled. The source namespace stays unchanged.
Without the property, ordinary debug and release packaging remain unchanged.

The probe replaces both application manifests with a plain `Application`, without
gateway startup, dependency components, permissions, package queries or a shared
UID. A fixed runner admits only three synthetic tests or the exact staged custody
method; the source set contains only
that runner, those tests, two fixture helpers and the maintained wolfSSL bridge tests. Each test creates
an unpredictable owned key alias. Ordinary test runs remove that alias in
`finally`; staged custody runs retain their one synthetic alias between explicit
invocations. Preparation uses an in-memory journal. It never enumerates aliases, samples a SIM, opens the
gateway journal, invokes a service or calls an SMS send method.

`python scripts/android_preparation_probe.py` validates the actual APK manifests,
verified signing identities and SHA-256 hashes. This is required on every run:
opt-in and ordinary builds share debug output paths. It first copies artifacts to
distinct temporary names. No installation occurs without an explicit `--serial`.
An emulator is required unless `--allow-physical` is also explicitly supplied
after the operator has reviewed the target and installation plan.
Physical execution also requires `--expected-sha256 APP_HASH TEST_HASH`, checked
before any device access. `--apk-dir` can select a reviewed private directory
containing `isolated-preparation-app.apk` and `isolated-preparation-tests.apk`.

Both probe packages must be absent. Installation uses neither replacement nor
permission grants. Before execution and cleanup, installed APK bytes must match
the verified artifacts. Cleanup uninstalls only packages successfully created by
that invocation; a changed installed artifact causes a failure instead of deletion.
The ordinary gateway package, its data, keys and role assignments are not accessed.

The first test unwraps independently encrypted ciphertext using an actual existing
Keystore key and rejects changed context and key loss. The second invokes the
shipping preparation entry: platform-reported TEE/StrongBox custody must produce
a one-use `Prepared` handle, while software custody must report `Unsupported`.
Unsupported is not evidence of successful hardware preparation. Selected transport
segmentation is exercised by preparation only; this probe makes no claim about
six/seven segment boundaries on an active SIM. The custom HPKE receiver remains
a candidate, regardless of hardware test results.

The third test enrolls, reloads and performs ECDH through the actual Keystore,
compares the original public key ID and reported security level, then checks
loss and local revocation without replacement. The host also runs this exact
method in five separate instrumentation invocations: `enroll`, `reload`, `lose`,
`revoke`, `cleanup`. All later stages receive the same pinned public ID,
reported level and observed `BOOT_COUNT` from enrollment. Cleanup refuses a
different pinned ID and deletes only the owned synthetic fixture.

The host also selects exactly four maintained wolfSSL bridge tests through the
same permissionless isolated runner. These exercise enrollment-only key creation,
cross-client seal/open with distinct nonempty info/AAD, framing and binding
rejections, and key-loss/revocation refusal. The staged custody reload additionally
opens a synthetic wrap through the maintained receiver using the same pinned
existing key. Loss and revocation also check receiver refusal without regeneration.
The earlier custom candidate tests remain separate and do not establish maintained
provider acceptance. The ordinary gateway remains dormant.

By default the host never reboots, force-stops or clears data. A separately
authorized physical drill can add `--require-hardware` and
`--reboot-between-custody-stages` to the reviewed physical invocation, which
also requires `--serial`, `--allow-physical`, both `--expected-sha256` values
and the reviewed artifact directory. Reboot is refused without explicit physical
and hardware options. The host requires a reported TEE or StrongBox level before
reboot, waits on the same selected transport with bounded timeouts, verifies
installed bytes again, and requires increased `BOOT_COUNT` at reload. The default
sequence requires unchanged `BOOT_COUNT`. The counter and security level are
platform observations, not trusted UTC, rollback protection or independent
hardware attestation. No sequence relaxes the maintained provider's distinct
nonempty info/AAD profile.

CI runs the three preparation tests and four maintained-provider tests in separate
allowlisted invocations, requiring zero failures/skips and an explicit custody
result. Physical execution is a
separate controlled operation, not an automatic consequence of building the probe.
Each of the five staged invocations must separately report one successful
completion of the exact custody method and zero skips. Missing, duplicate,
malformed or unknown baseline metadata fails the host check before later stages.
Any stage failure stops the sequence; the existing artifact-verified cleanup
still removes only this invocation's installed isolated packages.
