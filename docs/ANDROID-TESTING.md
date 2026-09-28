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
cover Room 5→6 identity and 6→7 suppression migrations, plus a previously
signed inbound upload.

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
