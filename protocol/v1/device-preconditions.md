# Android-reported device preconditions

This optional device-stream extension reports selected SIM availability, SMS
permission, airplane mode and optional coarse network service. It carries no SIM/card/subscription identifiers,
phone numbers, carrier names, location, message content or client clock. These
are untrusted observations from an authenticated app, not hardware attestation,
permission to dispatch, a statement of carrier readiness or delivery proof.
Positive sent/delivery callbacks remain separate message-timeline evidence.

## Negotiation and compatibility

A new phone offers `zrotext-device-status-v2, zrotext-device-status-v1` in
`Sec-WebSocket-Protocol`. The hub prefers v2 when both are offered; it selects
v1 for existing phones. The phone samples only for the exact selected extension.
An old v1 hub receives exactly the existing v1 frame. A hub that selects neither
extension receives heartbeat traffic only. Hello, challenge, proof, session and
heartbeat frames are unchanged; this versions only optional metadata.

After authentication the phone may send the `device_status` frame in
[the shared schema and examples](device-stream.schema.json): version, current
connection epoch, `selected_sim` (`not_selected`, `active`, `inactive`,
`unavailable`), `sms_permission` (`granted`, `denied`, `unavailable`) and
`airplane_mode` (`enabled`, `disabled`, `unavailable`). Unknown fields and enum
values are rejected. The existing 4 KiB frame bound applies. A status received
before proof, without negotiation or for another connection epoch is refused.
There is no status acknowledgment, durable phone queue or replay history.

Under v2 selection the distinct strict `device_status_v2` type retains stream
`v:1` and the existing fields, and requires `network_service`: `in_service`,
`out_of_service`, `emergency_only`, `power_off` or `unavailable`. The old type
is accepted only with v1 selected, and the new type only with v2 selected.
Both share one report budget, identity and authority checks. Neither accepts
subscription identifiers, client clocks, unknown fields or readiness flags.
A later v1 report clears any previously stored network-service value.

The client samples after its regular heartbeat, no more often than every 30
seconds. The hub ignores excess reports per connection before acquiring a
database client. Reconnection still consumes the existing shared device
challenge/proof budgets; it does not create an unbounded upload path.
The writer derives identity from the socket and checks its account, device,
key, site, lease, connection epoch and deployment epoch for each accepted
write. After acquiring mutation locks it rechecks the lease against the current
clock and the local draining flag, rolling back if either fence was lost during
a lock wait. It stores only the latest snapshot per device with its own receipt time.
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

Network service uses an initial `TelephonyCallback.ServiceStateListener`
callback for the explicitly selected active subscription on API 33 and later,
with `INCLUDE_LOCATION_DATA_NONE`. Only `ServiceState.getState()` is mapped;
the full platform object, cell/operator details and subscription identifier are
not retained or sent. No location or SMS permission is added. The
[callback contract](https://developer.android.com/reference/android/telephony/TelephonyManager#registerTelephonyCallback(int,java.util.concurrent.Executor,android.telephony.TelephonyCallback))
provides redacted service state; the differently permissioned `getServiceState`
getter is not used. API 28–32 report unavailable for this field.

Sampling is asynchronous and bounded to five seconds, so it does not wait on
or interrupt regular heartbeats. Only the initial callback is used. Timeout,
missing phone-state permission, inactive selection, platform error, changed
selection or reversed monotonic time yields unavailable. Socket replacement
cancels the sample; late or repeated callbacks cannot revive it. Registration
is removed after completion, cancellation or timeout. No old cached callback
is relabeled as a newly sampled report. Android may itself return cached radio
state, so an in-service result still proves neither SMS ability nor delivery.
No report changes the synthetic-send guard or enables sealed-message dispatch.

## Owner display

The existing owner device list returns `reported_preconditions` only for that
account's current connection and deployment epochs. It returns the three existing enums, nullable network service,
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
fresh API 36 emulator. It selects `DevicePreconditionsDeviceTest`, the one-case `NetworkServiceDeviceTest` and,
when present, `GatewayAccessibilityDeviceTest` with its explicit isolated-emulator
opt-in. It requires one precondition test and five accessibility tests when
selected, with zero failures or skips. It does not run the full instrumentation
suite or SMS probes. The network-service case requires a real selected-subscription
callback; unknown-only output and skips fail. Only the existing READ_PHONE_STATE
grant is applied to that disposable emulator app; no location or SMS grant,
radio action or stored subscription selection is changed. Commands target only
the disposable emulator; no physical
device is selected. This verifies platform behavior, not carrier delivery.
