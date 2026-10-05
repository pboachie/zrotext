# ADR 0003: Proposed shared per-device pacing

Status: proposed and unapproved. This document enables no policy, route or
runtime behavior. Implementation requires a separate reviewed issue.

## Existing behavior

The [device stream](../../crates/server/src/device_socket/mod.rs) uses
`MIN_SECONDS_BETWEEN_GRANTS = 60` to space grant frames on a socket. The
synthetic dispatch path also uses the delivery store's
[`synthetic_grant_may_be_due`](../../crates/delivery-store/src/lib.rs): an
unlocked pre-claim check of recent device attempts, dispatch enablement and
active fences. The actual grant still checks current authority under lock.
These restricted guards are not an owner-configurable general rate policy.

[Encrypted scheduling](../encrypted-scheduling.md) separately paces admissions
across a routine, starting at committed dispatch admission. A different routine
is not the same pacing scope. Neither mechanism proves when the phone or
carrier actually transmits a message, nor a carrier-safe volume.

## Proposed contract

Add a device-wide prerequisite at the existing authoritative writer, shared
by eligible routines and connections for the same account and enrolled device.
Reuse the existing queue, attempt identities and grant fences. Keep routine
pacing and current fixed safety guards; satisfying one limit cannot bypass
another. An owner may narrow an approved operator policy, never widen authority
or bypass its bounds. Defaults, ceilings, counting units and supported routes
remain product decisions requiring review; none are selected here.

The pacing check and admission debit must share the transaction that grants
new work, with one durable identity for that admission. Check current writer
and connection epochs, account/device/line authority, exact action approval,
consent, STOP, expiry, applicable windows and entitlement after lock waits.
Recheck time and authority before commit. Missing policy/state or an uncertain
writer refuses new admission; a cached timer or browser value grants nothing.

Pacing alone must defer otherwise eligible unsent work before a new claim or
attempt is created. An already queued message remains `queued`; the delay does
not create `unknown`, extend expiry or manufacture owner approval. STOP or
expiry can still cancel or expire unsent work under the existing fences. A
new grant must recheck eligibility when the pacing interval becomes available.

A committed admission consumes capacity once, even if its grant frame or commit
response is lost. Reconnect, restart, another routine or another replica cannot
reset the device's recorded consumption or mint a replacement attempt. An
uncertain attempt retains its existing fence and outcome; time passing is not
proof that no submission happened. Any permitted recovery uses the existing
[delivery-state evidence](../DELIVERY-STATES.md), not a pacing refund or retry.

## Owner visibility and unresolved decisions

Propose content-free status showing the applicable policy, whether unsent work
is waiting for pacing, and a next eligibility observation when knowable. Missing
state stays unavailable. An observed time is not a promised send/delivery time
or admission permission. Do not expose recipient, message content or SIM IDs.
The owner can narrow pacing but cannot lift STOP or resolve unknown work through
this control.

Before implementation, agree the admission counting unit and window model,
policy scope/version/change semantics, storage/lock order, fairness between
routines, supported dispatch paths, and the owner configuration/status surface.
Define conservative recovery and any proven-not-started accounting with the
existing delivery owners. No physical-device, carrier or provider acceptance
has been performed for this proposal.

## Future acceptance cases

These are required test designs, not implemented or executed regressions.

| Proposed behavior test | Required evidence |
| --- | --- |
| `device_pacing_defers_a_burst_without_creating_attempts` | Only admitted work consumes capacity; remaining queued work has no new attempt or grant. |
| `device_pacing_survives_restart_and_reconnect` | Durable consumption and uncertain fences survive; replay creates no second debit or attempt. |
| `device_pacing_shares_capacity_across_routines` | Two routines on one device cannot each spend the same remaining capacity. |
| `device_pacing_isolates_two_devices` | One device's debit does not consume another device's policy capacity. |
| `device_pacing_serializes_concurrent_last_admission` | Concurrent workers admit at most the remaining capacity under current writer/session epochs. |
| `device_pacing_rechecks_stop_and_expiry_after_wait` | Withdrawal, expired approval or deadline during a wait refuses later grants without extending time. |
| `device_pacing_retains_unknown_liability` | Lost commit/frame response and unknown submission do not reset capacity or authorize another attempt. |
| `device_pacing_missing_policy_and_status_fail_closed` | Missing state cannot become a zero-use budget, permission, or promised next send time. |

The implementation review must also cover policy changes and owner visibility.
A source proposal does not establish general sending, hosted availability,
carrier delivery or completion of the existing readiness gates.
