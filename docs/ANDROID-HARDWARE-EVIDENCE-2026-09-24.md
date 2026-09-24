# Samsung gateway hardware evidence — 2026-09-24 UTC

This is a partial M0/M1 device test record, not a supported-device or reliability claim. Tests used one dedicated Samsung SM-S928U with one consented active SIM, Android 16 (API 36), build `S928USQS6DZH3`. The debug gateway was built from public revision `1c702b35` with opt-in local instrumentation and a disposable loopback TLS test route. The phone connected over Wi-Fi debugging. Personal numbers, message contents, device credentials, and raw logs are kept outside this repository.

| Check | Observed result | Limit |
|---|---|---|
| Authorized outbound carrier SMS | One synthetic test message produced one writer message and attempt, one platform send attempt, positive sent and delivery callbacks, and recipient display confirmation. | One send to one controlled recipient does not establish repeat delivery or behavior on another carrier or device. |
| Inbound carrier SMS | With RCS off in Google Messages on the gateway, one iPhone message arrived as SMS. The receive-only test captured one inbound event and received one writer upload acknowledgment. Outbound dispatch was disabled. | The iPhone first showed a red send failure. The sender selected the conversation's second retry action before SMS arrived. This was a manual SMS retry, not evidence that an unchanged sender automatically falls back from RCS. An earlier RCS reply visible in Google Messages did not reach the SMS receiver. |
| Unplugged screen-off authenticated transport | A separate no-radio instrumentation test passed `1/1` after **274.947 seconds**. The screen was turned off 12.879 seconds into the unplugged run and remained off through the end; battery changed from 50% to 49%. Ten approximately 30-second heartbeat samples were recorded across two authenticated WSS sessions. | This is a short local transport test. It did not send an SMS, test carrier data, or establish 24-hour liveness. |
| Local transport interruption | The test TLS proxy was deliberately interrupted after roughly 150 seconds. The gateway authenticated a second session and recorded five further heartbeat samples while screen-off and unplugged. | A loopback proxy cut does not simulate a mobile-network switch, remote outage, process death, or site failover. |

The inbound SMS result proves the gateway's SMS broadcast, local journal, authenticated upload, and writer acknowledgment for that controlled message. It does not prove arbitrary iPhone or RCS senders will reach an SMS-only gateway without a sender action. Keep inbound line readiness unverified until an unchanged sender completes an automatic SMS delivery on the intended carrier path. [Android testing](ANDROID-TESTING.md) describes the SMS/RCS setup boundary.

## Open physical matrix

| Scenario | Status |
|---|---|
| 24-hour unplugged screen-off run with connection-gap and battery measurements | Open |
| Controlled Doze and battery-saver restrictions | Open |
| Wi-Fi/mobile-data switch, airplane-mode transition, and network loss/recovery | Open |
| Force-stop, process death, and reboot recovery | Open |
| SMS/phone permission revoke and restore | Open |
| SIM removal, no default SIM, and SIM selection change | Open |
| App upgrade and signed pilot build on the device | Open |
| Physical Pixel or other OEM/build comparison | Open; a Pixel AVD provides only virtual evidence |

The test used a local writer and TLS proxy reached through ADB reverse. Production ingress, release signing, long idle behavior, and external network reliability need separate evidence before a supported-device claim.
