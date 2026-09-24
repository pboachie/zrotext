# Android development and testing

The `android/` project contains the gateway app and local tests. Build and check it with JDK 21:

```sh
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug --no-daemon
```

On Windows, use `gradlew.bat`. The app needs a compatible Android device, an active SIM, and the permissions presented in the app to exercise SMS behavior. Emulator and JVM tests cover protocol and local-state behavior; they cannot verify a carrier send or receipt.

## Inbound SMS transport

The inbound pilot receives carrier SMS through Android's `SMS_RECEIVED` broadcast. An RCS message visible in Google Messages does not exercise this receiver. The [Android SMS API](https://developer.android.com/reference/android/provider/Telephony.Sms.Intents) defines the broadcast for SMS; the app cannot turn Google Messages RCS on or off through that API.

For each dedicated SMS gateway phone, turn off **RCS chats** in Google Messages once during setup, then verify a reply from a controlled sender with the sender's messaging settings unchanged. Confirm that the sender offers SMS or Text Message before sending and that the gateway records and acknowledges one inbound event. A failed RCS send followed by a manual **Send as Text Message** action proves the SMS capture path, but does not prove automatic fallback for other senders. RCS capability changes may not appear immediately on other phones; keep the line unready until an unchanged sender succeeds without that manual action. Google documents that [SMS/MMS remains available when the recipient lacks RCS](https://support.google.com/messages/answer/9487020?hl=en), and Apple documents the [manual fallback after a red send failure](https://support.apple.com/en-ca/118433).

Google also documents [RCS archival for fully managed Android Enterprise devices](https://developer.android.com/work/dpc/rcs-messages-archival). That is a separate deployment model and is outside this SMS pilot.

When reporting device behavior, include the model, Android version, app revision, power state, network type, SIM state, and the action taken. Test reconnects after screen-off, network changes, reboot, permission changes, and app upgrades. Use only a phone and recipient you control, and remove personal numbers and message bodies from logs and issues. A successful callback is evidence of the corresponding platform event; it does not make all future deliveries reliable.

The [device-stream contract](../protocol/v1/device-stream.md) documents the authenticated connection. The [architecture](ARCHITECTURE.md) explains why an ambiguous radio attempt remains unknown rather than being automatically resent.

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
