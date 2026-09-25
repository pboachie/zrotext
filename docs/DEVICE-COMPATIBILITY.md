# Android device compatibility

ZROtext does not yet claim support for any specific phone. This page records which devices have been exercised, what those runs show, and what is still untested. A single successful run on one device and carrier does not establish repeat delivery, long-running reliability, or behavior on other hardware.

The SMS gateway requires Android 9 (API 28) or later. Sealed-content mode, which is not yet enabled, requires API 31 or later. See [Android development and testing](ANDROID-TESTING.md) for how to run the device and emulator suites.

## Physical devices

| Device | Android | Result | Limits |
|---|---|---|---|
| Samsung Galaxy S24 Ultra (SM-S928U), one active SIM | 16 (API 36) | One authorized outbound SMS produced one server message and attempt, one platform send, positive sent and delivery callbacks, and recipient confirmation. | One send to one controlled recipient on one carrier. |
| | | One inbound SMS was captured, journaled, uploaded over the authenticated socket, and acknowledged by the server. | RCS was off on the gateway, and the sender manually retried as SMS. This does not show that an unchanged iPhone or RCS sender falls back to SMS automatically. |
| | | The authenticated socket stayed up for about 275 seconds unplugged with the screen off, with regular heartbeats across two sessions. | A short local run with no SMS and no carrier data. It does not establish 24-hour liveness. |
| | | After a deliberate interruption of the local TLS proxy, the gateway re-authenticated and resumed heartbeats. | A loopback proxy cut is not a mobile-network switch, process death, or site failover. |

These runs used a debug build, a local server, and a loopback TLS route over ADB. They did not exercise production ingress or a release-signed build.

## Emulators

The foreground-refusal and stale-evidence regressions run on API 28 and API 34 or later Android Virtual Devices. The virtual inbound SMS check also runs on an emulator. [Android development and testing](ANDROID-TESTING.md) describes each one. Emulator results are virtual evidence only: they do not prove carrier delivery, OEM power management, or Keystore hardware behavior.

## Not yet tested

- 24-hour unplugged, screen-off run with connection-gap and battery measurements
- Controlled Doze and battery-saver restrictions
- Wi-Fi/mobile-data switch, airplane-mode transition, and network loss and recovery
- Force-stop, process death, and reboot recovery on physical hardware
- SMS and phone permission revoke and restore
- SIM removal, no default SIM, and SIM selection change
- App upgrade and a release-signed build on a physical device
- A physical Pixel or another OEM for comparison

Device reports are welcome through the [device report issue template](../.github/ISSUE_TEMPLATE/device_report.yml). Use synthetic message content and never include phone numbers, IMEIs, or raw logs.
