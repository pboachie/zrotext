# Local browser and Android pairing handoff

`LocalPairingBindingDeviceTest` is an opt-in device test for an isolated,
synthetic owner and an actual Axum/PostgreSQL enrollment server. It uses the
ordinary `PairingClient`, Android Keystore identity, saved public locator and
`PairingBindingClient`. It does not replace the transport with fake responses.
Normal instrumentation discovery skips it unless `setupHandoff=true` is set.
CI compiles the test with the other `src/androidTest` sources; running the
same-instance browser/device scenario requires the private fixture below.

Use a disposable debug installation with SMS send and receive permissions
denied. Keep gateway services stopped. The tests refuse other conditions and
never start a service, grant permission or send SMS. The existing debug
network security configuration trusts its bundled development CA only for
`localhost`; release trust and cleartext restrictions remain unchanged.

Prepare a loopback HTTPS frontend at `https://localhost:8443`, with a valid
localhost server certificate signed by the bundled debug development CA. Keep
the CA and server private keys outside the public checkout. Development
certificates are deliberately short lived. If a disposable review build needs
a fresh CA, temporarily substitute only the public debug CA resource, record
the source revision plus local certificate/APK digests privately, and restore
the tracked resource after building. Never commit the disposable fixture CA
or describe that APK as an unmodified source-head build. Do not disable
certificate or hostname verification or change device clocks. Reverse the
selected device's port to the owned host frontend:

```sh
adb -s "$EMULATOR_SERIAL" reverse tcp:8443 tcp:8443
```

The fixture must start with an unpaired synthetic owner and mount the real
owner assets, auth, account setup and enrollment routes. In the browser, create
a pairing through the normal owner setup screen. Supply the exact canonical
QR payload rendered by `ZrotextPairingCode` to the app's private file
`files/setup-handoff-qr.json` using a private staging file and `run-as`.
The input is bounded to 512 bytes and removed before parsing. Do not put the
one-use QR token in instrumentation arguments or public logs. The selected
trusted service is fixed independently to `https://localhost:8443`; a QR from
another origin is refused.

Run one method per instrumentation invocation:

```sh
adb -s "$EMULATOR_SERIAL" shell am instrument -w -r \
  -e setupHandoff true \
  -e class org.zrotext.gateway.LocalPairingBindingDeviceTest#claimBrowserQrAndReadPending \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

The private `files/setup-handoff-receipt.json` appears only after all assertions
pass. It is replaced atomically, and an earlier receipt is removed before each
test. Its closed fields are `schema_version`, `operation`, `process_id`,
`origin`, `pairing_id`, `key_fingerprint`, `status`, `device_id`,
`comparison_code`, `stream_endpoint`, `services_running` and
`locator_unchanged`. The version is 1; the stream endpoint is derived locally.
The device UUID is an output of the authenticated binding result, never an
instrumentation input. Receipts and QR material stay in private scratch.

Compare both complete values from the pending native receipt to the actual
browser comparison, then explicitly approve in the browser. Force-stop the
app before invoking `readSavedPairingApproved` with the same arguments except
the method name. Do not clear app data or supply a device UUID. Compare its
output UUID to the real browser/server approval result and verify the process
ID changed. `readSavedPairingPending` similarly checks a pending attempt after
restart using only the existing key and locator.

The orchestrator can drop the browser approval response after the upstream
commit, then use the browser's Check progress action and the native approved
read to confirm one device was created. After actual owner revocation,
`readSavedPairingUnknown` must retain the same locator and key fingerprint
without claiming again. `readSavedPairingCancelled` and
`readSavedPairingExpired` check the corresponding authoritative server outcomes.
Replacement after a terminal attempt remains an explicit app action.

Run `confirmedKeyLossBlocksBeforeNetwork` last, with the additional
`setupHandoffDeleteTestKey=true` argument. This intentionally deletes the
disposable installation's default signing alias. It verifies confirmed loss,
retention of the public locator, zero binding calls and no recreated key.
Never opt into this destructive fixture method on an installation whose
signing identity must be retained.

This test establishes the pairing proof and approval handoff only. SIM
selection, permission interactions, explicit connection start, writer leases,
SMS line activation, hosted billing and carrier behavior need their respective
acceptance checks. A pending/approved receipt does not claim those steps ran.
