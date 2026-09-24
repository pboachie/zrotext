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

## Stale-evidence virtual regression

`StaleEvidenceVirtualDeviceTest` exercises the Room outbox and reconnect
policy on API 28 and API 34 or later emulators. It verifies that a re-paired
device or changed WSS origin quarantines old radio and inbound rows, that a
fresh row remains selectable, and that three same-row closes from an older
writer quarantine only that row before a heartbeat-only retry. Use
`-e class org.zrotext.gateway.StaleEvidenceVirtualDeviceTest` and
`-e virtualEvidenceOnly true` with the `am instrument` command above. These
tests never start a service, connect a socket, or send SMS. JVM tests also
cover Room 5→6 migration and a previously signed inbound upload.

The Android 12+ `dataExtractionRules` resource excludes the app's database,
preferences, and files from both cloud backup and device transfer. The
manifest retains `allowBackup=false` for older versions. The virtual suite
checks the installed schema and local routing behavior; actual device-to-device
transfer and carrier behavior remain separate hardware checks.

## Inbound SMS transport

The inbound pilot receives carrier SMS through Android's `SMS_RECEIVED` broadcast. An RCS message visible in Google Messages does not exercise this receiver. The [Android SMS API](https://developer.android.com/reference/android/provider/Telephony.Sms.Intents) defines the broadcast for SMS; the app cannot turn Google Messages RCS on or off through that API.

For each dedicated SMS gateway phone, turn off **RCS chats** in Google Messages once during setup, then verify a reply from a controlled sender with the sender's messaging settings unchanged. Confirm that the sender offers SMS or Text Message before sending and that the gateway records and acknowledges one inbound event. A failed RCS send followed by a manual **Send as Text Message** action proves the SMS capture path, but does not prove automatic fallback for other senders. RCS capability changes may not appear immediately on other phones; keep the line unready until an unchanged sender succeeds without that manual action. Google documents that [SMS/MMS remains available when the recipient lacks RCS](https://support.google.com/messages/answer/9487020?hl=en), and Apple documents the [manual fallback after a red send failure](https://support.apple.com/en-ca/118433).

Google also documents [RCS archival for fully managed Android Enterprise devices](https://developer.android.com/work/dpc/rcs-messages-archival). That is a separate deployment model and is outside this SMS pilot.

When reporting device behavior, include the model, Android version, app revision, power state, network type, SIM state, and the action taken. Test reconnects after screen-off, network changes, reboot, permission changes, and app upgrades. Use only a phone and recipient you control, and remove personal numbers and message bodies from logs and issues. A successful callback is evidence of the corresponding platform event; it does not make all future deliveries reliable.

The [device-stream contract](../protocol/v1/device-stream.md) documents the authenticated connection. The [architecture](ARCHITECTURE.md) explains why an ambiguous radio attempt remains unknown rather than being automatically resent.
