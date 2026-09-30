# Dormant future conversation adapter boundaries

These libraries are code-only future-feature candidates. No production builder,
service, receiver, UI entry, owner route or SMS transport mounts them. Migration
allocation/rebase and normal release gates remain independent.

## Explicit owner/browser setup

`prepareConversationSignerSetup02` consumes a mandatory affirmative setup decision
for the exact account, owner session, selected phone/line generation, conversation
interval, peer and readers. It creates an in-memory, non-exportable role-5 key.
Only the public point/ID leave the closure; no root, bearer, private-key export,
persistent store, network endpoint or automatic enrollment exists. The owner's
existing signing authority must enroll that public key in a verified current
manifest. Pending/unapproved keys cannot prepare an envelope or sign confirmation.

Setup pins the independently verified owner root point/generation. Same-root
manifest renewal is monotonic; root change, same-version replacement, rollback,
logout, withdrawal or lost custody closes this signer. Reload requires explicit
new setup/enrollment. This deliberately favors session-lifetime custody over
persistent browser keys; persistent custody is a separately reviewed future choice.

`prepareReview` uses the existing profile-02 cryptographic preparer with fresh
CSPRNG material and exactly the approved phone/archive recipients. It never signs
the separate confirmation. `signReviewed` binds canonical ZTCS01 bytes to exact
body/ciphertext hashes, session/interval/line/peer, reader, root and manifest and
consumes an exact affirmative content decision. It rechecks current authority and
expiry after signing. No retry or transport is exposed. The existing main-line
production SDK composer should replace the candidate preparer when the blocked
stack can be rebased; this adapter remains unmounted until that dependency is
aligned and its production path is independently verified.

## Authenticated monotonic time

`ConversationTrustedClock` accepts only a nonce-bound reply installed by the owner
of the already authenticated device socket. Session identity is copied from
`SealedDispatchExecutor.Session`, including account/device/session, connection
and deployment epochs and origin hash. The proposed reply carries that exact
challenge and the server's send UTC timestamp. A server-authenticated socket is
the time authority; this creates no new signing key or external time credential.
The existing wire protocol does not yet emit this reply, so its authenticated
server/frame adapter is a remaining integration gate.

The adapter allows at most two seconds of round-trip time and uses the full RTT
as conservative uncertainty added to server UTC. It advances by elapsed monotonic
time, expires after thirty seconds, and is unavailable after restart/session loss.
No wall-clock fallback or persisted anchor exists. Nonce/session mismatch,
regression, overflow and unavailable clocks fail closed. Root/session authority
must still be independently sampled; a time lease never authorizes content or SMS.

## Execution and lifecycle

`ConversationExecutionBoundary` reuses `SealedDispatchExecutor`, existing manifest
verification, hardware-only `DevicePayloadKeyStore`, and sealed preparation journal.
It requires current owner/session/consent/permissions/SIM truth and exact approved
scope, root generation and manifest activation floor. Returned prepared ownership
is consumed under the same admission monitor as receiver/Stop, including all
stored preparation callbacks; a delayed consumer cannot escape that fence.
This boundary yields prepared ownership, never a radio permit or delivery result.
The separate canonical confirmation and durable confirmed-attempt journal remain
mandatory before any real submission, as do queue/billing/suppression and grants.

`ConversationLifecycleHooks` disables that gate and time before durable capture/send
closure and invokes a mandatory authenticated server-close adapter, even after
local storage failure. Only verified local and server success permits durable
Closed; uncertain remote closure remains disabled/failure. It reports `IN_PROGRESS`, `DURABLY_CLOSED` and
`DISABLED_CLOSURE_FAILED` distinctly with sanitized enum reasons. Close retains
receipt fences and is not deletion or recall of a submitted message.

`ConversationFreshReviewRecovery` is the future worker's only recovery port.
Construction disables admission and blocks any cold-loaded interval. Only a new
verified interval with a consumed affirmative phone decision can prepare/recover;
old local installation must durably close first. Stopped intervals cannot use
recovery as an error shortcut. No worker/builder exposes direct journal recovery.
This conservative cold-start policy costs another phone approval after process
loss. Supporting benign same-interval automatic recovery requires a durable
withdrawal-intent/server-revocation protocol that survives local close failure;
that alternative is not implemented or silently claimed here.

## Presentation ownership

`ConversationPresentationPort` supplies `observe`, `refresh`,
`approvePhoneReview(requestId, observedVersion)`,
`declinePhoneReview(requestId, observedVersion)` and
`requestStop(intervalId, observedVersion)`. `ConversationPresentationSnapshot`
contains only immutable sanitized phase/version/selection/budget/capability and
closure/failure enums. Only `ConversationPhoneReview` exposes the deliberate peer
and exact canonical disclosure. Decode alone cannot populate a trusted review.
Runtime owns stale action validation, worker dispatch and authoritative snapshots;
presentation owns UI-thread delivery, expiry display and no saved approval/secrets.
No activity/receiver/service files are changed by these libraries.

Before mounting: coordinate both service Pause paths and first-PDU receiver with
one shared runtime, finish server/frame/verifier adapters and signer enrollment,
integrate export/retention/guarded deletion/backup/reconciliation, update consent
policy and verify hardware plus real-device behavior under specific SMS approval.
