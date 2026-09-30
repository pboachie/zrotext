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

`ConversationPresentationRuntime` now dispatches this port through mandatory serial
worker and UI executors. It consumes exact observed versions, rechecks review
authority and expiry, ignores budget-only countdown differences, and cancels an
installation before waiting for the shared admission monitor on Stop. Observers
are removable, receive no secrets, and cannot break other observers by throwing.
`ConversationJournalPresentationDomain` connects review to the protected journal,
fresh-review recovery, authenticated acceptance/install exchange, live admission
budget and durable local/remote closure hooks. Prepared or pending exchange never
reports Active. Its exchange/verifier remain mandatory; no service mounts it.
Review request IDs are ephemeral UI decision challenges, distinct from the durable
server receipt ID. The domain retains the exact verified scope/evidence, checks the
displayed disclosure digest, and consumes that review once. It checks both review
expiry and cancellation after installation waits while holding the shared gate.

`ConversationAuthorityTransport` implements nonce/session/scope matching and
bounded time/closure replies through a mandatory `ConversationAuthenticatedChannel`.
The channel owner must derive session identity from the authenticated connection,
not payload fields. Closure success requires the exact request and durable server
commit acknowledgement; timeout, session change, wrong peer or uncertain response
cannot claim Closed. The existing socket still has no production implementation
of these new messages: these are tested dormant adapters, not a deployed protocol.

`ConversationChannelCodec` now encodes the proposed frames as `ZTCW`, version 1,
and kind 1=time request, 2=time reply, 3=closure request, 4=closure reply. Network
order header: account/device/phone-session UUIDs, connection/deployment i64 epochs,
32-byte origin hash, and challenge UUID. Header size is 118 bytes; time reply adds
positive i64 UTC. Closure adds account/device/line/interval/receipt/owner-session
UUIDs, line/root/manifest i64 generations/version, four 32-byte disclosure/reader/
manifest/activation-transcript digests, and one-byte-length ASCII canonical peer.
Reply adds exactly one durability byte (0 or 1). Requests are 370–383 bytes and
replies 371–384 bytes. No trailing bytes, unknown kinds, zero UUIDs, oversized or
truncated frames are accepted. Embedded account/device must match channel identity.
`ConversationSerializedChannel` requires the existing authenticated socket owner
to supply response identity out of band and rechecks current identity after waits.
The codec is not a signature or transport-integrity mechanism: socket authentication
and integrity remain mandatory. Matching nonce/scope and committed-state truth are
verified by the authority adapter/server, not inferred from successful decoding.

## Owner-root enrollment integration boundary

The session-lifetime browser signer exposes only its public point and role-5 key
ID after deliberate setup. The existing owner-controlled root custodian must
independently verify the account, device, line and reader selection; show that
exact new signer and bounded authorization for owner confirmation; and sign a
successor manifest using the existing verified chain/version and role bindings.
The signer cannot sign confirmations until that successor is independently
verified and installed in its current authority source. No root private key is
exported to the conversation runtime, and no new root is silently generated.
Reload, root rotation or setup failure discards the session key and requires fresh
setup. If the existing root custodian is unavailable, enrollment stays unavailable;
fixture root signing demonstrates the boundary without provisioning user custody.
An actual custodian UI/sign/publish adapter remains an integration gate. It must
not accept a transport-success response as verified manifest enrollment, overwrite
the pinned root on recovery, or automatically replay a failed owner confirmation.

`createConversationEnrollment02` implements a single-use dormant custodian adapter:
verify current phone/archive reader authority before approval or signing, preserve
all existing manifest records, add one exact-line role-5 key with a maximum
30-minute lifetime, sign through an existing custodian callback, independently
verify that root signature and exact successor chain, and require an atomic
predecessor/session/consent installation callback. Every callback receives owned
copies; the verified high-water preserves its actual transition anchor. Account,
session, reader, root or predecessor change, expiry, refusal and uncertain install
consume the attempt without replay. The returned manifest alone never activates
the conversation signer; its current-authority source must independently read the
installed verified successor. Fixture custodian/CAS demonstrates this path; no
user root, persistent credential storage or actual publication adapter is created.

The isolated candidate also contains the reviewed `FutureConversationPane` without
an activity mount. `ConversationPaneRuntimeTest` joins that pane to the real runtime,
Room state machine and serialized closure adapter. Synthetic verifier, protection
and server fixtures prove explicit approval before installation, no capture while
pending, synchronous local Stop, and negative/unconfirmed remote ACK behavior.
These tests do not establish actual server authentication, encrypted production
custody, permission grants, carrier execution or device accessibility readiness.

Before mounting: coordinate both service Pause paths and first-PDU receiver with
one shared runtime, finish server/frame/verifier adapters and signer enrollment,
integrate export/retention/guarded deletion/backup/reconciliation, update consent
policy and verify hardware plus real-device behavior under specific SMS approval.
