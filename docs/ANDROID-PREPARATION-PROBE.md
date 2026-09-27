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
UID. A fixed runner admits only two synthetic tests; the source set contains only
that runner, those tests and the two required fixture helpers. Each test creates
one unpredictable owned key alias, removes that exact alias in `finally`, and
uses an in-memory journal. It never enumerates aliases, samples a SIM, opens the
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

CI runs both tests on a disposable emulator and requires exactly two successful
completions, zero skips and an explicit custody result. Physical execution is a
separate controlled operation, not an automatic consequence of building the probe.
