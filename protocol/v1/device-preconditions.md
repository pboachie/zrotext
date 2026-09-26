# Android-reported device preconditions

This optional device-stream extension reports selected SIM availability, SMS
permission and airplane mode. It carries no SIM/card/subscription identifiers,
phone numbers, carrier names, location, message content or client clock. These
are untrusted observations from an authenticated app, not hardware attestation,
permission to dispatch, a statement of carrier readiness or delivery proof.
Positive sent/delivery callbacks remain separate message-timeline evidence.

## Negotiation and compatibility

A new phone offers `Sec-WebSocket-Protocol: zrotext-device-status-v1` during
upgrade. It samples and sends reports only if the hub selects that exact
subprotocol in its response. Existing hello, challenge, proof, session and
heartbeat frames are unchanged. An old hub selects no extension, so a new phone
continues its existing heartbeat behavior without sending status. An old phone
does not offer the extension and receives no new frames from a new hub.

After authentication the phone may send the `device_status` frame in
[the shared schema and examples](device-stream.schema.json): version, current
connection epoch, `selected_sim` (`not_selected`, `active`, `inactive`,
`unavailable`), `sms_permission` (`granted`, `denied`, `unavailable`) and
`airplane_mode` (`enabled`, `disabled`, `unavailable`). Unknown fields and enum
values are rejected. The existing 4 KiB frame bound applies. A status received
before proof, without negotiation or for another connection epoch is refused.
There is no status acknowledgment, durable phone queue or replay history.

The client samples after its regular heartbeat, no more often than every 30
seconds. The hub ignores excess reports per connection before acquiring a
database client. Reconnection still consumes the existing shared device
challenge/proof budgets; it does not create an unbounded upload path.
The writer derives identity from the socket and checks its account, device,
key, site, lease, connection epoch and deployment epoch for each accepted
write. It stores only the latest snapshot per device with its own receipt time.
Both account deletion and device deletion cascade to the snapshot. Reports
older than one day become eligible for the bounded retention worker's prune
batches; there is no historical telemetry log.

## What the observations mean

An active selected SIM means Android listed the locally selected subscription
as active. A missing READ_PHONE_STATE grant, unavailable subscription service
or platform exception yields `unavailable`, not a claim that the SIM is absent.
The local subscription ID is used only for matching and is never serialized.
SEND_SMS permission and airplane mode are independent observations: permission
granted plus airplane mode disabled does not prove the radio can send.

This slice does not request location permission or sample network registration.
Android's [TelephonyManager.getServiceState documentation](https://developer.android.com/reference/android/telephony/TelephonyManager#getServiceState())
requires READ_PHONE_STATE and ACCESS_COARSE_LOCATION. Radio registration and
carrier readiness therefore remain explicitly unknown. No device state here
changes the synthetic-send guard or enables sealed-message dispatch.

## Owner display

The existing owner device list returns `reported_preconditions` only for that
account's current connection and deployment epochs. It returns the three enums,
server `received_at_ms` and a `fresh` flag. Fresh requires a current socket lease
at an enabled, non-draining site and receipt within 90 seconds. Future-dated or
over-one-day snapshots are not returned. Revoked devices/keys, disabled accounts,
replacement sessions and deployment changes cannot restore an old report.

The dashboard labels the report fresh **at snapshot time**, stale, disconnected
or unavailable. It retains the receipt time and explicitly says carrier
readiness is unknown. Turning off automatic refresh or viewing an old page does
not transform the saved report into a current observation. Missing or malformed
reports never become affirmative readiness or an empty/absent-SIM claim.

## Automated platform smoke test

The read-only Android device-smoke workflow builds the debug APKs and starts a
fresh API 36 emulator. It selects only `DevicePreconditionsDeviceTest` and,
when present, `GatewayAccessibilityDeviceTest` with its explicit isolated-emulator
opt-in. It requires one precondition test and five accessibility tests when
selected, with zero failures or skips. It does not run the full instrumentation
suite or SMS probes. Commands target only the disposable emulator; no physical
device is selected. This verifies platform behavior, not carrier delivery.
