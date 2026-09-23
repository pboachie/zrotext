# M0 Android gateway-mode feasibility test

This is a dated test procedure, not a passed hardware matrix. The debug APK builds, but no real phone, SIM, carrier, background-connection, or SMS delivery result has been recorded.

## Runtime and distribution choice

The user starts a visible gateway session from the app. The service declares `remoteMessaging` and its foreground-service permission because the intended operation transfers text-message work to a dedicated phone. The M0 build opens only an authenticated WSS test socket and emits heartbeat records; it does not send or receive SMS. Android's [foreground service type rules](https://developer.android.com/develop/background-work/services/fgs/service-types) describe `remoteMessaging` as transferring text messages between devices, while [foreground service guidance](https://developer.android.com/develop/background-work/services/fgs) requires a user-visible, appropriate long-running task. This classification remains a policy review gate before distribution. `dataSync` is unsuitable for a perpetual socket and is subject to [timeouts and boot restrictions](https://developer.android.com/develop/background-work/services/fgs/timeout).

Initial distribution is a signed direct APK to consenting pilot operators of dedicated phones. The debug APK is for development only. Google Play [restricts SMS permissions and requires a default handler or approved exception](https://support.google.com/googleplay/android-developer/answer/10208820); Play distribution is a separate review, and sideloading does not bypass Android runtime restrictions. The M0 manifest requests `SEND_SMS`, `RECEIVE_SMS`, `READ_PHONE_STATE`, and notification permission, but no SMS API is called. The selected subscription ID stays in app memory and is not yet a durable routing setting.

Use a short-lived test token entered locally; the app does not persist it. Set `M0_TEST_TOKEN` to a private random value of at least 32 characters on the M0 server and connect to `wss://<test-host>/m0/device-test` behind a valid TLS proxy. Rotate the token after testing; the M0 server does not enforce token expiry. Without that variable, the endpoint is disabled. The socket accepts only the exact M0 heartbeat frame and returns an acknowledgment; it does not dispatch. A real pairing protocol and journal are M1 work. There is no automatic restart after force-stop or reboot; the UI says so. A socket heartbeat is not evidence that SMS was delivered.

## Exact hardware procedure

1. Record date/time zone, model, build fingerprint, Android/API version, carrier, SIM count, power settings, APK commit and SHA-256 in a private test log. Do not publish identifiers or message content.
2. On a dedicated Pixel and Samsung, include the current supported Android version and one prior version; add a third OEM before launch. Install the signed test APK, grant requested permissions, select the active SIM, enter a short-lived WSS test token and start gateway mode. Record any FGS start failure or permission prompt behavior.
3. Use a private test server that validates the bearer token and records only synthetic device ID, heartbeat timestamp, connection open/close, and test-case ID. With the screen on, verify at least three 30-second heartbeats. Pause from the notification and confirm the socket closes and the service stops.
4. Repeat with screen off and charging, then unplugged, Doze, battery saver, Wi-Fi/mobile switch, airplane mode and recovery, permission revocation, SIM removal/no default SIM, force-stop, reboot, app upgrade, and 24-hour idle. Capture exact heartbeat gaps, reconnect behavior, OS notifications, battery settings, and manual recovery. Current M0 code has no reconnect after failure; record the observed limitation rather than infer continuous operation.
5. At M1, after a durable journal and permission review exist, send one synthetic SMS to a number the operator controls and receive a reply. Record radio sent and delivery callbacks separately from recipient observation. Repeat the crash boundaries on real phones. Emulator and socket tests never count as carrier delivery.

## Evidence matrix

| Device / OS build | Carrier / SIM | Screen off + charging | Unplugged / Doze | Network switch | Force-stop / reboot | 24 h gap | SMS round trip |
|---|---|---|---|---|---|---|---|
| Pixel — pending hardware | pending | unverified | unverified | unverified | unverified | unverified | unverified |
| Samsung — pending hardware | pending | unverified | unverified | unverified | unverified | unverified | unverified |
| Third OEM — before launch | pending | unverified | unverified | unverified | unverified | unverified | unverified |
