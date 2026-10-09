# Android development and testing

The `android/` project contains the gateway app and local tests. Build and check it with JDK 21:

```sh
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug --no-daemon
```

On Windows, use `gradlew.bat`. The app needs a compatible Android device, an active SIM, and the permissions presented in the app to exercise SMS behavior. Emulator and JVM tests cover protocol and local-state behavior; they cannot verify a carrier send or receipt.

## Foreground-service refusal regression

`ForegroundRefusalDeviceTest` starts both services with invalid settings and checks that each refusal leaves the process alive, keeps the explanatory status, and removes its foreground notification. It is gated by `virtualForegroundRefusal=true` so a normal physical-device suite skips it. Run it on API 28 and API 34 or later emulators using the explicit emulator serial:

```sh
cd android
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s emulator-5554 install -r app/build/outputs/apk/debug/app-debug.apk
adb -s emulator-5554 install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s emulator-5554 shell am instrument -w \
  -e class org.zrotext.gateway.ForegroundRefusalDeviceTest \
  -e virtualForegroundRefusal true \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

Change the serial for the second emulator. These cases use only invalid inputs and never open a gateway socket or call the SMS radio.

Repeatable run ids: `api-28-emulator-suites` (an API 28 emulator) and `api-34-emulator-suites` (an API 34 or later emulator). Each id covers this suite, the stale-evidence suite, and the virtual inbound receiver check below, and is recorded with its exact test list in [device-compatibility.json](device-compatibility.json).

## Stale-evidence virtual regression

`StaleEvidenceVirtualDeviceTest` exercises the Room outbox and reconnect
policy on API 28 and API 34 or later emulators. It verifies that a re-paired
device or changed WSS origin quarantines old radio and inbound rows, that a
fresh row remains selectable, and that three same-row closes from an older
writer quarantine only that row before a heartbeat-only retry. Use
`-e class org.zrotext.gateway.StaleEvidenceVirtualDeviceTest` and
`-e virtualEvidenceOnly true` with the `am instrument` command above. These
tests never start a service, connect a socket, or send SMS. JVM tests also
cover Room 5→6 identity and 6→7 suppression migrations, plus a previously
signed inbound upload.

The Android 12+ `dataExtractionRules` resource excludes the app's database,
preferences, and files from both cloud backup and device transfer. The
manifest retains `allowBackup=false` for older versions. The virtual suite
checks the installed schema and local routing behavior; actual device-to-device
transfer and carrier behavior remain separate hardware checks.

## Outbound MMS spike

The "Controlled MMS spike" screen is the stage-one tool from [issue #438](https://github.com/pboachie/zrotext/issues/438).
It exists only in **debug builds**: the screen section, the sent-callback
receiver, the file provider and the only `sendMultimediaMessage` call live in
the `debug` source set, and the `release` source set replaces the entry points
with stubs that draw nothing and reject the grant frame. A release APK cannot
reach it.

It composes one `m-send.req` PDU (an OMA-MMS minimal envelope whose byte shape
mirrors AOSP's `com.google.android.mms.pdu.PduComposer`) around a
synthetically generated 1x1 PNG and submits it through
`SmsManager.sendMultimediaMessage` with a null location URL, so the
carrier-configured MMSC is used. Before the one-use gate is spent, every one
of these must pass:

1. **Debug build** (`BuildConfig.DEBUG`).
2. **Build allowlist.** The recipient must appear exactly in the
   `zrotextMmsSpikeAllowlist` Gradle property of the debug build
   (`-PzrotextMmsSpikeAllowlist=+E164[,+E164]`). The default is empty, which
   refuses every recipient; one malformed entry empties the whole list.
3. **Confirmation dialog.** The operator reviews the exact recipient and SIM
   in a dialog and arms one attempt. The arm is held in memory for five
   minutes and consumed by the first grant.
4. **Server grant.** After the operator arms the attempt, the app sends an
   `mms_spike_ready` frame on the authenticated device stream naming the
   session's connection epoch and the SHA-256 digest of the confirmed
   recipient, and the phone sends only after the hub answers with an
   `mms_spike_grant` frame. Like `synthetic_grant`, it must carry exactly
   `v`, `type`, `grant_id`, `device_id`, `connection_epoch`,
   `recipient_digest`, `expires_at_ms` and `recipient_e164`, and match the
   authenticated device and connection epoch, the confirmed and allowlisted
   recipient, and an expiry at most 35 seconds ahead. An unarmed or invalid
   grant fails the session. The hub issues the frame only when the founder
   has enabled it with `MMS_SPIKE_GRANT_ENABLED=true`, named the one gateway
   device in `MMS_SPIKE_GRANT_DEVICE`, and allowlisted the recipient in
   `MMS_SPIKE_GRANT_RECIPIENTS`, and only in answer to the ready frame: a
   client that never asks — an unarmed debug build, a release build, or a
   client predating the frame — never receives one, so ordinary sessions are
   unaffected. The hub also enforces the one-use gate server-side (one grant
   per device and recipient per 90 days) and withholds the grant while the
   recipient has an active suppression or unreleased owner hold. The
   Android app from #442 does not yet send the ready frame; until it does,
   the armed spike stays armed-but-silent. Spec:
   `protocol/v1/synthetic-alpha-stream.md`.
5. **STOP suppression.** The keyed `sender-v1` token (the Android Keystore
   HMAC used by the SMS path) is looked up in the local suppression list, and a
   lookup failure counts as suppressed. The lookup is repeated under the local
   suppression lock immediately before the radio call.

One attempt is allowed per installation. The gate is committed before any
radio call, and an uncertain result is journaled as unknown and never retried
automatically.

Privacy: the local journal (`files/mms_spike/journal.log`) records only the
attempt and transaction IDs, event kinds and fixed result codes; it holds no
recipient, recipient token or hash, subject or media, and its validator
rejects any other detail text. The composed PDU
(`files/mms_spike/<attempt>.pdu`) necessarily contains the plaintext recipient
and subject while the platform MMS service may read it. It is deleted when the
sent callback arrives, when the five-minute timeout fires, when the radio call
throws, and on every exit before the radio call. If the process dies in
between, the next time the screen opens it deletes any PDU whose attempt is no
longer awaiting its callback. The recipient and subject are otherwise held
only in memory and are not logged.

This tool is JVM-tested for composition, journaling, gating and PDU cleanup
only. The emulator cannot prove MMS. A physical-device spike must still find
out whether the platform MMS service can read the FileProvider URI and whether
the carrier's MMSC accepts the PDU; both are recorded as device findings in the
issue, not as claims of this repository.
## SMS line activation device checks

`SmsLineActivationPhysicalSimDeviceTest` and `SmsLineActivationEsimDeviceTest` read real telephony state on hardware. They never call the radio, never send an SMS, and leave the app's device key, settings and stored data untouched: the physical-SIM class signs with a throwaway software key against an in-memory journal, and the eSIM class uses a throwaway software signer and a RAM-only challenge ledger. Build both APKs, install them on the phone under test, run the class, and remove the test package afterwards:

```sh
cd android
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s SERIAL install -r -t app/build/outputs/apk/debug/app-debug.apk
adb -s SERIAL install -r -t app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s SERIAL shell am instrument -w -e class org.zrotext.gateway.SmsLineActivationEsimDeviceTest \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
adb -s SERIAL uninstall org.zrotext.gateway.test
```

Use `gradlew.bat` on Windows. Grant only the phone-state permission the app already holds; never grant SMS permissions for these checks.

Each check states its own gate. The only skip in the physical-SIM class is `readSinglePhysicalLine`'s: it proceeds only when telephony is readable and exactly one active, non-embedded line is present, so a phone whose active lines are all eSIMs — for example a dual-eSIM device — skips every check that reads a physical line. A single physical line whose card ID or subscription ID is unreadable or negative is not a skip: the eligibility `assertNotNull` fails, because a line that cannot be identified cannot back a signed declaration. The reboot and different-card checks additionally need `-e expected_sub N -e expected_card M`, copied from the `reference` line the activation test logs while the original card is inserted; without a baseline they skip, and a partial or malformed baseline fails instead of passing vacuously. The absence check has its own gate: it needs that baseline plus a readable telephony read that reports zero active lines — it never asks for a physical line — and asserts the recorded card no longer matches anything observed. The eSIM class requires API 33+ and a readable, coherently observed active profile. It exercises explicit subscription selection and profile-lease signing with a throwaway software key, without installing authority or sending SMS. An eUICC card ID identifies the chip, not a profile; it is never sufficient on its own. The earlier dual-eSIM decline record describes the older physical-only implementation and is retained as history, not a passing result for this implementation. These checks prove the gate's behavior on the observed hardware; they do not validate an activation with carrier service or a physical-SIM swap. The opt-in radio leg and the STOP-reply leg have not been run on any dual-eSIM configuration.

## Inbound SMS transport

The inbound pilot receives carrier SMS through Android's `SMS_RECEIVED` broadcast. An RCS message visible in Google Messages does not exercise this receiver. The [Android SMS API](https://developer.android.com/reference/android/provider/Telephony.Sms.Intents) defines the broadcast for SMS; the app cannot turn Google Messages RCS on or off through that API.

For each dedicated SMS gateway phone, turn off **RCS chats** in Google Messages once during setup, then verify a reply from a controlled sender with the sender's messaging settings unchanged. Confirm that the sender offers SMS or Text Message before sending and that the gateway records and acknowledges one inbound event. A failed RCS send followed by a manual **Send as Text Message** action proves the SMS capture path, but does not prove automatic fallback for other senders. RCS capability changes may not appear immediately on other phones; keep the line unready until an unchanged sender succeeds without that manual action. Google documents that [SMS/MMS remains available when the recipient lacks RCS](https://support.google.com/messages/answer/9487020?hl=en), and Apple documents the [manual fallback after a red send failure](https://support.apple.com/en-ca/118433).

The gateway app reports one local RCS signal on its setup screen: whether the phone's default messaging app is one known to register RCS chats (Google Messages or Samsung Messages). Android has no public API that reports whether RCS chats are actually enabled or registered on a line, so the app can only flag this capable-app configuration; an unrecognized or unobservable default app is reported as unknown. No outcome proves RCS is off, that capture will work, or carrier readiness. Treat a capable-app report as a reminder to disable RCS chats and run the controlled-sender verification above; the messaging app can re-enable RCS on its own after an update, so repeat that verification after messaging-app updates on the gateway phone.

What exactly the gateway misses when a sender uses RCS: an RCS message is delivered client-to-client through the carrier's RCS service. While this phone's RCS chats are registered, the sender's messaging app receives a delivery acknowledgment at the RCS layer, shows the message as delivered, and never re-sends it as SMS — no fallback can occur, and the `SMS_RECEIVED` broadcast this gateway captures never fires. The message exists only inside the default messaging app, and no public Android API exposes another app's RCS messages, so the gateway cannot read, forward, or acknowledge it. When this phone's RCS chats are off or unregistered, the sender's RCS client cannot deliver and falls back to SMS per the platform behavior linked above, on a schedule chosen by the sender's client. This mechanism analysis was not confirmed by a live RCS send in this session; that needs a second authorized sender line and remains the controlled-sender procedure above. `DefaultSmsAppRcsRiskDeviceTest` is the no-radio repeatable check of the capable-app observation on real hardware, and the CI emulator run keeps the observation path working; neither proves RCS is off.

Google also documents [RCS archival for fully managed Android Enterprise devices](https://developer.android.com/work/dpc/rcs-messages-archival). That is a separate deployment model and is outside this SMS pilot.

When reporting device behavior, include the model, Android version, app revision, power state, network type, SIM state, and the action taken. Test reconnects after screen-off, network changes, reboot, permission changes, and app upgrades. Use only a phone and recipient you control, and remove personal numbers and message bodies from logs and issues. A successful callback is evidence of the corresponding platform event; it does not make all future deliveries reliable.

The [device-stream contract](../protocol/v1/device-stream.md) documents the authenticated connection. The [architecture](ARCHITECTURE.md) explains why an ambiguous radio attempt remains unknown rather than being automatically resent.

## Long liveness runs

A liveness run keeps one enrolled phone connected for hours while you change
the conditions around it: screen off, unplugged, Wi-Fi to mobile data and
back, a different carrier or SIM, a reboot, or a different device model. The
server records the run with content-free markers; `scripts/liveness_report.py`
turns them into a comparable summary. No SMS is sent, and nothing in this
procedure needs message content or phone numbers.

1. Start a server you control with `ZT_DEVICE_STREAM_DIAGNOSTIC=1` in its
   private environment (the Compose file passes it through). Keep one gateway
   phone connected to that server for the run. Markers carry no device ID, so a
   log with several devices mixes their connections; the report warns when
   connections overlap.
2. The device stream prints to standard error:
   - `ZTDeviceStream heartbeat_ack connection_epoch=N since_prior_accepted_ms=M handling_ms=H`
     for the first 256 accepted heartbeats of each connection (about two hours
     at the 30-second cadence);
   - `ZTDeviceStream close_reason=R connection_epoch=N since_heartbeat_ms=M heartbeats=C max_gap_ms=G connected_ms=T`
     when the connection ends. The totals cover the whole connection, including
     heartbeats after the per-heartbeat markers stop. `R` is one of the stream
     exit reasons in `crates/server/src/device_socket/mod.rs`, for example
     `heartbeat_deadline`, `superseded` or `site_drain`.
3. Collect the log with timestamps, for example
   `docker compose --env-file .env -f deploy/compose/compose.yaml logs --no-color --timestamps app > run.log`.
   Keep the raw log private; it contains other server output.
4. Summarize it:

   ```sh
   python3 scripts/liveness_report.py run.log --min-observed-seconds 86400 \
     --label device_model="Example Phone 7" --label network="wifi to lte"
   ```

The report is JSON: connections and reconnects, total heartbeats, connected
time, the worst accepted heartbeat gap, sampled gap percentiles, close reasons
and, when every marker has a timestamp, the downtime between connections. The
tool never copies log lines into the report; malformed markers are only
counted. It exits `0` when every check passes, `1` when one fails, and `2` when
the log has no markers.

| Check | Fails when |
|---|---|
| `max_gap` | Any accepted heartbeat gap exceeds `--max-gap-seconds` (default 45, the server's heartbeat deadline). |
| `well_formed_markers` | A `ZTDeviceStream` line does not match the grammar above. |
| `min_observed` | With `--min-observed-seconds`, the connections together stayed up for less time. |
| `max_reconnects` | With `--max-reconnects`, the run reconnected more often. |

Labels accept only `android_version`, `app_version`, `carrier_class`,
`device_model`, `network`, `power` and `screen`, with short values and no run of
five or more digits, so a serial, IMEI or phone number cannot slip into a
report. Use a coarse carrier class such as `prepaid-mvno` rather than an
account detail.

A passing report shows that this server kept a stream alive under the stated
conditions for the stated time. It does not prove SMS delivery, carrier
behavior on other plans, or behavior on another device model. Logs from a
server before these totals existed still parse; the report then marks connected
times as estimates.

## Virtual inbound receiver check

On a freshly booted `sdk_gphone` emulator with neither gateway APK installed,
put Android SDK `platform-tools` (including `adb`) on `PATH`, build the debug
app and test APKs, then run:

```sh
cd android
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
python tools/virtual_inbound_sms.py --serial emulator-5554
```

Use `gradlew.bat` on Windows. The script requires an explicit emulator serial and
checks the emulator property before installation. It grants receive and phone-state
permissions, denies send permission, and injects one synthetic SMS through the
emulator console. An opt-in instrumentation test seeds a fabricated prior successful
send record without invoking the radio, then verifies Android's SMS broadcast made
one encrypted local event and one pending upload row. The script removes only the
gateway APKs it installed. The synthetic message can remain in the emulator's
messaging inbox; use a disposable AVD. This check does not prove carrier delivery,
real SIM attribution, a server upload, or RCS fallback.

## No-radio classes on a connected phone

Repeatable run id: `physical-no-radio-classes`. This is the documented procedure
that re-verifies the app-level, no-radio behavior of the current build on a
connected physical phone. Only the founder-authorized test phone may be used. The
four classes below are the hardware-agnostic subset of the CI no-radio allowlist;
the remaining CI classes (accessibility, network service, root storage, sealed
preparation) assert emulator isolation flags on purpose and are excluded from this
procedure, so this run is not the CI run and never replaces it.

```sh
cd android
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
adb -s <phone-serial> install -r app/build/outputs/apk/debug/app-debug.apk
adb -s <phone-serial> install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
adb -s <phone-serial> shell am instrument -w \
  -e class org.zrotext.gateway.DevicePreconditionsDeviceTest,org.zrotext.gateway.ManifestAuthorityDeviceTest,org.zrotext.gateway.OutboundEnvelopeDeviceTest,org.zrotext.gateway.SealedBodyDeviceTest \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

Use `gradlew.bat` on Windows. The classes read device preconditions, the installed
manifest, and envelope logic; none of them sends, arms, or reads the radio, and none
requires granting SMS or location permission. A passing run proves the app-level
no-radio behavior of that build on that phone; it does not prove carrier delivery,
power management, or any other phone. Record the summarized outcome (model, Android
level, pass or fail) in the private operations repository and, if the device is
listed, in the compatibility matrix; never publish raw output, numbers, or device
identifiers. Linking this run for a device defines how it is re-verified; it is not
a claim that it ran.

## Opt-in radio instrumentation

Repeatable run id: `opt-in-radio-instrumentation`. These two classes use the radio
for real, so they are opt-in, never run in CI, never run on an emulator, and only
run on the founder-authorized test phone with a controlled recipient.

`LocalRadioPreflightDeviceTest` runs only with `-e m1RadioPreflight true`. It checks
that the pilot permissions are granted, requires exactly one active SIM (or exactly
one matching `-e m1SubscriptionSlot N`), refuses if the one-send pilot was already
consumed, and stores the selected subscription in the app's local selection. It arms
no radio operation and sends nothing.

`LocalAuthorizedOneSendDeviceTest` runs only with `-e m1AuthorizedOneSend true`,
`-e m1DeviceId <paired-device-id>`, and `-e m1ControlledRecipient <controlled-recipient>`.
It performs exactly one authorized send to the controlled recipient and asserts that
the one-use grant was consumed, so a second invocation fails until the pilot state
is reset. Use a phone and recipient you control.

```sh
adb -s <phone-serial> shell am instrument -w \
  -e class org.zrotext.gateway.LocalRadioPreflightDeviceTest \
  -e m1RadioPreflight true \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

Both classes log fixed status strings, not message content or numbers. Raw run
output stays in the private operations repository; only the summarized outcome
belongs in the compatibility matrix. No passing run of either class is recorded in
the public matrix today.

## Selected eSIM profile continuity

The ordinary line path now has a separate API 33+ local profile-record lease. It observes the explicit subscription, nonnegative containing-card ID, port and logical-slot mapping under one subscription-listener lifetime. Two active profiles may share a card and reported slot when their ports are distinct. Duplicate or unreadable mappings refuse. No ICCID, EID, phone-number identity or privileged telephony access is acquired.

`EsimProfileContinuityTest` and `EsimProfileMonitorTest` cover the initial callback/registration barrier, equal-tuple callbacks, two profiles, stop/restart, permission recovery, ambiguity, durable deny-only challenge reservations and shared generation fences. Activation, Room, grant, connection and STOP tests cover final ACK publication, exception cleanup, migration 12 to 13, saved-record refusal and retirement after the durable radio CAS. These tests do not prove OEM callback delivery, carrier ownership or carrier delivery. The new implementation's execution results must be recorded separately; none is claimed here.

Every subscription callback, permission/read failure, selected-SIM change or observer/process restart retires the prior eSIM authority. A saved binding or receipt cannot restore it. Recovery requires fresh applicable owner acceptance, a new authenticated higher-generation challenge and its exact final ACK. Android 12L/API 32 and older remain outside this eSIM continuity path. Alpha diagnostics and message-body restrictions are unchanged.

## Complete-set selection preparation

The API 33+ complete-set foundation observes the whole active physical SIM and
eSIM list, including hidden peers, and locally prepares one explicitly selected
profile. Other profiles remain active. Successful listener registration, its
initial callback and coherent whole-list reads are required; a missing,
ambiguous or unreadable selected mapping cannot fall back to another profile.

Selection replacement, callbacks, permission or read failure, selected-profile
disappearance, pause, stop and destruction retire the held preparation. Saved
preferences record a choice and cannot restore preparation or establish
activation, installed authority or send readiness. The existing v1 selected-line
and count-one proof gates remain in place.

The following ordinary `src/test` classes contain 116 inventoried methods:

| Test class | Methods |
|---|---:|
| `CompleteSubscriptionObservationTest` | 15 |
| `CompleteSubscriptionObservationAdapterTest` | 16 |
| `CompleteSelectionPreparationBridgeTest` | 8 |
| `SimCardCompleteSelectionPreparationTest` | 4 |
| `LineActivationV2Test` | 16 |
| `CompleteSetPrivacyProjectionV2Test` | 19 |
| `LineActivationV2IncomingFramesTest` | 19 |
| `CompleteSelectionPreparationCoordinatorTest` | 13 |
| `MainActivityCompleteSelectionPreparationTest` | 6 |

These are source inventories, not executed acceptance. The complete-set
candidate's 116 controls and four-ABI native/Android graph remain uncompiled and
unrun; lint and APK acceptance remain pending. The Activity controls use
Robolectric API 34 and the v2 incoming-frame controls use API 33. This coverage
does not prove OEM callback behavior, enabled multi-profile messaging or carrier
delivery.
