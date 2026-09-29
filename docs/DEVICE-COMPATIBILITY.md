# Android device compatibility

ZROtext does not yet claim support for any specific phone. This page records which devices have been exercised, what those runs show, and what is still untested. A single successful run on one device and carrier does not establish repeat delivery, long-running reliability, or behavior on other hardware.

The supported-device list is also published as a machine-readable matrix in [device-compatibility.json](device-compatibility.json). Every entry records a status, an evidence level, the repository checks that exercise that class, and the repeatable run or runs that define how the class is re-verified. `python scripts/check_device_compatibility.py` re-verifies the matrix against the Gradle `minSdk`/`targetSdk`, the repository tree, this page, and the no-radio allowlist that the `selected-device-tests` CI job executes; `python -m unittest discover -s scripts -p 'test_*.py'` runs the same rules as regression tests in CI. The validator checks the consistency of the recorded claims and that referenced tests and jobs exist; it does not run any device, and passing it says nothing about hardware behavior.

Statuses mean: **supported** — exercised by repeatable repository checks for the role stated in the entry; **partial** — some recorded evidence with known limits; **excluded** — outside the app's supported envelope by construction; **unevaluated** — no recorded evidence. Evidence levels mean: **physical** — a controlled run on real hardware recorded on this page, which is a manual record rather than an automated test; **emulator** — an Android Virtual Device check; **device-sim** — the host-side `zrotext-device-sim` fault model. Emulator and host-simulator results never prove carrier delivery, OEM power management, or Keystore hardware behavior.

The SMS gateway requires Android 9 (API 28) or later. Sealed-content mode, which is not yet enabled, requires API 31 or later. See [Android development and testing](ANDROID-TESTING.md) for how to run the device and emulator suites.

## Repeatable runs

Each device entry in the matrix links one or more repeatable runs through its `no_radio_run` field, and a physical entry may additionally link an opt-in radio run through `radio_run`. **A link defines how a configuration is re-verified; it is not a claim that the run executed.** What executed and what it proved is recorded only by the status, the evidence level, and the notes of the entry. Every entry with the supported or partial status must link at least one no-radio run, and the validator rejects a matrix row that claims otherwise.

| Run id | Kind | What it is | What it proves | What it does not prove |
|---|---|---|---|---|
| `selected-device-tests` | CI job | The [selected-device-tests](../.github/workflows/android-device-smoke.yml) job runs `scripts/android_device_smoke.py`, which executes the exact no-radio class allowlist (preconditions, accessibility, manifest authority, network service, outbound envelope, root storage, sealed body, sealed preparation) plus the preparation probe on a disposable API 36 `google_apis;x86_64` AVD with no SIM, on every pull request that touches `android/**`, the scripts, or the workflow. | The app-level, no-radio behavior of the current build on that one virtual configuration, repeatedly, on fresh emulators. | Carrier delivery, OEM power management, Keystore hardware behavior, any physical device, and any other Android level. |
| `api-28-emulator-suites` | Documented command | The foreground-refusal, stale-evidence, and virtual inbound SMS suites run on an API 28 AVD through the documented commands in [Android development and testing](ANDROID-TESTING.md). | The virtual regression behavior they assert on API 28. Repeatable by anyone with the SDK. | The same limits as all emulator evidence; freshness depends on the last manual run because CI does not execute it. |
| `api-34-emulator-suites` | Documented command | The same suites on an API 34 or later AVD. | The virtual regression behavior they assert on the exercised levels. | The same limits as all emulator evidence. |
| `device-sim-suite` | CI job | The `rust` job in [ci.yml](../.github/workflows/ci.yml) runs the workspace test suite, which includes the inline tests of `crates/device-sim`, plus the simulator timeline. | The host-side delivery-state logic: writer promotion and ambiguous radio outcomes. | Anything about a phone: it models no hardware, Android level, SIM, or carrier. |
| `physical-no-radio-classes` | Documented command | The hardware-agnostic subset of the CI allowlist (preconditions, manifest authority, outbound envelope, sealed body) run through the documented `am instrument` command on a connected, founder-authorized phone; see [Android development and testing](ANDROID-TESTING.md). | App-level, no-radio behavior of the current build on that phone, once actually executed and recorded. | Carrier delivery, power management, any other phone. **No execution on any listed device is recorded in the matrix today.** |
| `opt-in-radio-instrumentation` | Opt-in radio | `LocalRadioPreflightDeviceTest` and `LocalAuthorizedOneSendDeviceTest`, which use the radio for real. They require the founder-authorized phone and a controlled recipient, are gated behind explicit instrumentation flags, and never run in CI; see [Android development and testing](ANDROID-TESTING.md). | When actually executed and recorded: SIM selection preflight, and exactly one authorized send with its one-use grant consumed. | Carrier reliability, delivery beyond the controlled recipient, or any uncontrolled sender. **No passing run on any listed device is recorded in the matrix today.** |

## Reading the matrix: supported-device guidance

- A virtual configuration (emulator level, host simulator) is recorded as **supported** only while a repeatable run actually executes it: the `selected-device-tests` CI job for the API 36 CI emulator, the documented emulator commands for the API 28 and API 34 or later emulators, and the `rust` CI job for the host simulator.
- A physical configuration cannot move beyond **partial** on a manual record alone. To strengthen it, run the linked `physical-no-radio-classes` procedure on that hardware and, only where the founder-authorized test phone allows, the linked opt-in radio run. Each executed run updates the entry's notes with a summarized outcome; the raw run evidence stays in the private operations repository and never enters this repository.
- Radio evidence exists today only as the manual physical record below. No opt-in radio instrumentation run has been executed or recorded on any listed device, and no carrier, delivery reliability, or second device is proven.
- A run link without a recorded outcome proves nothing. When this page says a run has not been executed, that is the exact state: the procedure exists and is repeatable, and no result is claimed from it.

## Physical devices

| Device | Android | Result | Limits |
|---|---|---|---|
| Samsung Galaxy S24 Ultra (SM-S928U), one active SIM | 16 (API 36) | One authorized outbound SMS produced one server message and attempt, one platform send, positive sent and delivery callbacks, and recipient confirmation. | One send to one controlled recipient on one carrier. |
| | | One inbound SMS was captured, journaled, uploaded over the authenticated socket, and acknowledged by the server. | RCS was off on the gateway, and the sender manually retried as SMS. This does not show that an unchanged iPhone or RCS sender falls back to SMS automatically. |
| | | The authenticated socket stayed up for about 275 seconds unplugged with the screen off, with regular heartbeats across two sessions. | A short local run with no SMS and no carrier data. It does not establish 24-hour liveness. |
| | | After a deliberate interruption of the local TLS proxy, the gateway re-authenticated and resumed heartbeats. | A loopback proxy cut is not a mobile-network switch, process death, or site failover. |
| Samsung Galaxy S24 Ultra (SM-S928U), two active eSIM lines | 16 (API 36) | The no-radio SMS line activation check read real telephony, observed two embedded lines, and the activation gate declined before any signature was requested. | One decline on one dual-eSIM device. It does not validate an activation, carrier service, or the physical-SIM path. |
| | | The physical-SIM activation suite skipped all four checks on this phone — no single active physical SIM and no recorded card baseline — rather than passing vacuously. | The skips document correct gating on ineligible hardware; they are not physical-SIM evidence. |

The one-active-SIM runs used a debug build, a local server, and a loopback TLS route over ADB; they did not exercise production ingress or a release-signed build. The dual-eSIM rows used the no-radio SMS line activation instrumentation described in [Android testing](ANDROID-TESTING.md); that run needed no server, sent no SMS, and changed no phone setting, SIM state, or stored key. The matrix entry for this phone links the `physical-no-radio-classes` and `opt-in-radio-instrumentation` procedures as its re-verification path; neither has been executed on this phone, so the records above remain its only claimed evidence — the send, inbound and liveness rows for delivery behavior, and the dual-eSIM rows for activation-gate behavior only. Raw evidence for any future run is kept in the private operations repository; only summaries belong here.

## Emulators

The foreground-refusal and stale-evidence regressions run on API 28 and API 34 or later Android Virtual Devices. The virtual inbound SMS check also runs on an emulator. [Android development and testing](ANDROID-TESTING.md) describes each one. In addition, the `selected-device-tests` CI job exercises its own no-radio allowlist and the preparation probe on a disposable API 36 emulator for every pull request that touches `android/**`; the matrix records that exact configuration as its own entry. Emulator results are virtual evidence only: they do not prove carrier delivery, OEM power management, or Keystore hardware behavior.

## Host simulator

`crates/device-sim` models writer promotion and ambiguous radio outcomes deterministically on the host, with inline Rust tests and a simulator-timeline run in CI. It is evidence for delivery-state logic only: it represents no phone hardware, Android level, SIM, or carrier, and the matrix records it with the `device-sim` evidence level and no API range.

## Not yet tested

- The `physical-no-radio-classes` procedure executed on the physical test phone
- The opt-in radio instrumentation classes executed and recorded on the physical test phone
- 24-hour unplugged, screen-off run with connection-gap and battery measurements
- Controlled Doze and battery-saver restrictions
- Wi-Fi/mobile-data switch, airplane-mode transition, and network loss and recovery
- Force-stop, process death, and reboot recovery on physical hardware
- SMS and phone permission revoke and restore
- SIM removal, no default SIM, and SIM selection change
- App upgrade and a release-signed build on a physical device
- A physical Pixel or another OEM for comparison

Device reports are welcome through the [device report issue template](../.github/ISSUE_TEMPLATE/device_report.yml). Use synthetic message content and never include phone numbers, IMEIs, or raw logs.
