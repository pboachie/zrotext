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
The dormant authenticated server/frame adapter emits this reply. Its ordinary
socket policy remains disabled; installing it requires explicit future composition.

The adapter allows at most two seconds of round-trip time and uses the full RTT
as conservative uncertainty added to server UTC. It advances by elapsed monotonic
time, expires after thirty seconds, and is unavailable after restart/session loss.
No wall-clock fallback or persisted anchor exists. Nonce/session mismatch,
regression, overflow and unavailable clocks fail closed. Root/session authority
must still be independently sampled; a time lease never authorizes content or SMS.

## Authenticated content transfer

The binary channel retains the 118-byte `ZTCW01` header and exact out-of-band
account/device/phone-session, connection/deployment epochs, origin hash and nonce.
All integers use network byte order. The canonical scope is the six UUIDs,
three positive u64 generations/version, four 32-byte digests, and the length-prefixed
ASCII peer already used by closure and installation.

| Kind | Body after the header |
|---|---|
| 12 capture request | Canonical scope, u32 envelope length, exact sealed envelope |
| 13 committed capture ACK | Event UUID, SHA-256 of the full envelope, canonical created byte 0 or 1 |
| 14 confirmed-packet request | Canonical scope, exact message UUID |
| 15 confirmed-packet reply | u32 packet length, exact packet |

Envelopes and reply packets are bounded to 40,000 bytes; all frames reject trailing
bytes. The confirmed packet is `ZTCR01`, u32 envelope length and bytes, u16
confirmation length and bytes, then the exact 64-byte signature. A packet transfer
does not claim a dispatch job or grant carrier execution. The phone independently
verifies current authority and exact requested message before durable send admission.

Capture allocates and commits a durable counter before encryption, then protects
the single sealed packet in its receipt journal. Upload retries reuse those exact
bytes and identity; renewal never reseals captured content. The server supplies
the stored activation provenance and current manifest to the existing fenced ingest,
then acknowledges only after commit. Stop/retention erase protected packet content
while retaining identity/counter fences. Network waits never hold the shared
admission monitor; admission is checked before and after transfer, and late replies
cannot restore a stopped interval. These handlers and process mounts remain dormant.

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

## Dormant server handlers

`http_owner_conversations::channel::handle` now verifies the exact frame header
against socket-owned identity and database-backed account/device/key/site/epoch
and lease authority. Time uses server UTC. Stop compares every scope byte against
the canonical stored activation, serializes with capture using manifest-before-
account locking, and returns an ACK only after the closure transaction commits.
Active-to-history Stop is idempotent and preserves authorized retained history;
owner logout does not prevent an otherwise authenticated phone from closing it.
No handler is registered in the socket or an HTTP router. The socket owner still
must negotiate the phone-session UUID/origin and supply the independently proven
context. Scope/nonce decoding never creates that context.

`http_owner_conversations::enrollment::install` implements the SDK installation
callback boundary as a dormant PostgreSQL transaction. It verifies the existing
root-signed exact successor, requires current owner session/selection/consent and
line/readers, preserves all old records, permits one bounded exact-line role-5
addition, and performs a predecessor CAS. Acceptance provenance advances with the
new manifest. Current reader and owner expiry are rechecked before commit;
replay, tamper, withdrawal and expired session roll back the transaction.
The root custodian and owner authenticated endpoint adapters remain unconnected.

Pending closure now supports explicit authenticated kind-5 reconciliation. The
phone supplies its original canonical approval bytes with a fresh channel nonce.
The server compares the original transcript digest and every retained scope field
under the interval lock and acknowledges only history/expired/withdrawn rows with
a durable closure timestamp. It never changes phase, restores statement bytes,
authorizes reads or reopens capture. The original proof is protected inside the
existing journal's protectedScope column/AAD (format 2); legacy scope-only records
remain readable but cannot recover a missing original proof. No SQL change or
separate persistent credential store is required.

Before mounting: coordinate both service Pause paths and first-PDU receiver with
one shared runtime, finish server/frame/verifier adapters and signer enrollment,
integrate export/retention/guarded deletion/backup/reconciliation, update consent
policy and verify hardware plus real-device behavior under specific SMS approval.

## Authenticated dormant runtime assembly

`ConversationAuthenticatedRuntime` joins the shared presentation port, journal,
canonical verifier, authenticated channel clock, fresh phone-decision recovery,
and lifecycle closure under one serialized worker and admission gate. Proposal
alone cannot capture; installation completes only after the exact current phone
decision and active lease. `observeFirstReceipt` records authenticated receipt
time, and `confirmedSender` shares the same admission and monotonic clock. Its
receive/submit operations remain worker-only and explicit; no automatic replay
or actual radio transport is supplied. Session/permission/consent authority is a
mandatory live callback, not a cached UI permission check.

Lifecycle loss closes eligibility synchronously, then queues durable local and
verified remote closure. Worker rejection reports disabled admission with failed
closure. Rejected UI notification delivery cannot discard closure work. A serial
worker submission is resolved before a concurrent submission can be accepted.
The presentation port signatures are unchanged; no activity, service or receiver
mount is added.

`scripts/conversation_simulator.py --assembly` runs one explicitly supported
synthetic scenario against the actual dormant server handlers, Android Room
journal and browser SDK. It covers approval/install, authenticated channel/time,
protected inbound and readable history, unchanged ciphertext after benign
renewal, exact-confirmed synthetic reply, UNKNOWN sender-instance recreation
refusal, durable Stop and subsequent withdrawal of history access. Fixture
sessions/signers and radio callbacks are ephemeral and synthetic. Database-reopen
send fences remain separate tests; this scenario does not claim process-restart,
emulator, physical-device, carrier or Play approval evidence.

## Isolated Android emulator and Chromium probe

The explicit Gradle property `isolatedConversationProbe=true` creates a separate
`org.zrotext.gateway.conversationprobe` test-only debug APK. Release variants are
disabled for that property. Its only permission is INTERNET; the separate test
APK requests no permissions. Neither APK declares a telephony receiver or actual
SMS dispatch adapter. Normal application manifests/components remain unchanged.

The probe mounts the existing pane and runtime in an isolated activity, binds an
actual Android service, and delivers synthetic decoded receipt broadcasts on a
background receiver thread through the same admission gate. An affirmative pane
choice completes fixture-signed installation; receipt time comes from the
verified channel clock. Synthetic input is not a carrier or protected system
SMS broadcast. Ephemeral fixture keys and loopback adapters supply custody.

`scripts/conversation_emulator.py` requires an explicitly selected emulator in an
isolated conversation profile, installed `adb` and `aapt`, and the existing local
fixture database/toolchain. Both APK package identities, testOnly declarations,
and exact permission sets are verified BEFORE installation, even with
`--skip-build`. This switch refuses stale ordinary gateway APKs. The runner uses
only target-specific ADB reverse mappings and cleans up its own fixture resources.

The host-only bridge invokes the existing SDK with explicit UTF-8 encoding.
`conversation-browser-emulator.mjs` opens the actual product page in headless
Chromium with fresh in-memory fixture custody and blocks off-origin browser
requests. It reads the emulator's stored encrypted event, verifies exact Unicode
and trailing spaces, cancels without signing/submission, and checks the browser
revision between signing and dispatch. A deterministic mid-sign edit yields an
abandoned signature but zero accepted sends; a fresh exact confirmation yields
one accepted synthetic packet. Android durably claims before the fake callback
reports UNKNOWN and refuses sender-instance replay. Stop retains eligible history;
withdrawal blocks history access. This does not prove process-restart recovery,
real SIM continuity, radio execution, production custody or Play eligibility.

Before ordinary release mounting: replay the isolated stack onto each coordinator
pin, finish production receiver/service and authenticated socket/key-custodian
adapters, verify consent/export/retention/guarded-deletion integration and policy,
and obtain release-owner signing/reviewer-access evidence. Physical/carrier testing
is outside this explicitly simulator/emulator-only pass.

## Release integration dependencies

`ConversationServiceIngress` is the dormant service/decoded-receipt integration
port. Construction defaults to disabled. Its explicit enable parameter is a code
assembly option, not owner consent or an execution grant. The owning service must
supply an independently sampled lifecycle-loss callback. Sampling failure closes
admission. Pause closes eligibility synchronously and permanently for that port;
its presentation snapshot separately reports durable local/remote closure success
or failure. A new session requires a fresh runtime and explicit phone review.
The isolated probe alone enables this port. Normal services have disabled process
mount hooks; no ordinary activity installs or authorizes the mount.

A deployable release must assemble these dependencies in order; none is supplied
by turning on the ingress parameter:

| Dependency | Required configuration/evidence | Current boundary |
|---|---|---|
| Schema and lifecycle | Verified ordered migrations 064 and 065, existing inventory/export, retention and guarded deletion | Dormant transactions and lifecycle tests; coordinator merge pins required |
| Owner and phone authentication | Existing authenticated owner session and device socket; independently negotiated phone session/account/device/key/site/epoch | Canonical handlers verified, socket registration and authenticated context adapter pending |
| Root and browser custody | User-initiated existing owner-root custodian, verified successor CAS and exact current reader authority; recovery must not silently grant a replacement key | Enrollment/signing interfaces and fixture custody tested; live custody wiring pending |
| Device protection | Existing hardware-backed device keys, authenticated clock and protected journals, independently sampled permissions and exact selected-line continuity | Disabled ordinary receiver/service hooks and runtime/execution adapters tested; runtime construction and exact observed-line mapping remain unconnected |
| Consent and closure | Separate browser selection and phone body-transfer disclosure, exact interval/peer/key binding, both Pause paths, logout/permission/SIM/expiry fences | Pane/runtime, ordinary Pause hooks and closed-only ACK recovery tested; production consent policy and activity integration remain gates |
| Browser and confirmed reply | Authenticated event discovery/reader adapter, safe text rendering, exact recipient/body/line confirmation, revision fence before dispatch | Actual page plus SDK tested with synthetic adapters; authenticated endpoint/transport wiring pending |
| Release packaging | No fixture source, credentials, loopback bridge or synthetic dispatch in ordinary APK; release-owner signing and reviewer access | Probe is a separate test-only APK; ordinary build remains separate |

This candidate creates no environment flag that mounts routes or enables radio
execution. Live credential provisioning, access grants, production enablement and
any future carrier test require their own explicit authorization. Simulated
results are not carrier delivery, physical accessibility or Play approval evidence.

## Disabled ordinary integration ports

Both ordinary service Pause paths, authenticated service halt and service teardown
now synchronously close the shared process mount. The ordinary SMS receiver takes
an opaque admission/clock fence before queuing decoded receipt work. A receipt
observed before installation cannot become eligible after phone approval. Worker
capture still verifies current authenticated session, permissions, consent, line,
reader and lease through the same journal gate. Missing observed subscription or
an unselected line commits a discarded receipt fence; it never falls back to the
default SIM. Mapping/preparation/storage failures close the mount. Failure before
an HMAC or durable receipt reservation cannot prove that a later redelivery was
already recorded; normal activation must remain disabled until that failure and
redelivery recovery case has accepted device evidence and a recovery policy.

The process mount is uninstalled by default. Install requires explicit code-owner
configuration and independent live authority/line mapping callbacks; it does not
authorize body transfer. No ordinary activity creates a runtime, generates keys,
installs a mount or enables radio execution in this candidate.

`ConversationSocketWire` binds an existing authenticated OkHttp socket to one
bounded binary exchange. It verifies independently held session and nonce, rejects
rotation, timeout, late/duplicate replies and submission refusal, and never
replays requests or falls back to HTTP. Its owner must negotiate the phone session
and origin through the authenticated connection and invalidate it on socket loss;
production negotiation/registration remain separate code gates. The emulator uses
a loopback WebSocket with out-of-band fixture identity to exercise this exact wire.

Closed-only reconciliation uses request kind 5: the authenticated channel header,
a two-byte canonical-statement length and the original approved statement. The
server verifies its retained immutable digest and complete scope under the same
interval lock and returns a fresh nonce-bound kind-4 closure acknowledgement only
for an already closed interval. It never reinstalls approval, grants history or
reopens capture. The protected phone journal retains these original bytes inside
its existing protected installation field; legacy scope-only records remain
readable but cannot reconstruct this proof. Recovery requires both local journals
closed and keeps admission closed throughout. Socket loss invalidates session,
unblocks pending exchange and closes admission synchronously, including concurrent
duplicate listener callbacks. No automatic cold-start capture recovery is added.

`conversation-owner-adapter.js` defines a disabled-by-default owner transport port.
It requires current authority, current CSRF and custody callbacks plus explicit
owner endpoint paths. Sealed reads and confirmed submissions use owner cookies,
CSRF headers, same-origin mode, no-store and refused redirects. The adapter checks
session/scope and CSRF before signing and immediately before dispatch; one-use
confirmation never retries an ambiguous POST. It delegates local verification,
decryption and signing to the existing reviewed SDK/custodian interfaces and
creates no root credential. A queued result is valid only after a real durable
server queue adapter accepts the exact proof; authorization-only verification is
not queued acceptance. Production custody, queue persistence/transport endpoints
and browser mounting remain unconnected code gates.

## Explicit authenticated installation extension

The ordinary device socket router rejects the extension. The explicit
`router_with_conversations` constructor requires a configured WSS origin and
retains the existing enrolled-device proof and current database session checks.
After ordinary stream authentication, the client sends `conversation_ready`
with its connection epoch and a fresh challenge. The server creates a fresh
per-connection phone-session UUID. Its `conversation_session` reply echoes the
challenge and binds the account, device, connection and deployment epochs and
SHA-256 of the canonical `wss://host:port` origin. Neither side accepts a duplicate
negotiation or a caller-supplied replacement account/session. The JSON contract
is [conversation-channel.schema.json](conversation-channel.schema.json).

Only then can binary `ZTCW` version-1 exchanges use the existing 118-byte header:
magic/version, kind, account/device/phone-session UUIDs, connection/deployment
epochs, origin digest and fresh challenge UUID. All integers use network order.
The socket owner supplies independently held authority to the handler; parsing
the header never establishes authority. Existing time, closure and closed-only
reconciliation messages retain their encodings.

| Request | Payload after header | Reply |
|---|---|---|
| 6: approve | Two-byte statement length, complete canonical activation statement, 64-byte low-S approval signature | 7: exact retained scope |
| 8: install | Same statement encoding, distinct installation-domain signature | 9: exact scope followed by eight-byte lease duration |
| 10: refresh lease | Exact retained scope | 9: exact scope and lease duration |

The request bound is 1,208 bytes. Lease duration is positive and at most 60,000
milliseconds. Approval ACK alone never makes capture eligible. The phone verifies
its existing accepted root/manifest, exact phone signer and archive reader, signs
with its existing hardware-backed key, verifies both nonce-bound replies and
installs through the shared admission gate. A callback must follow an explicit
affirmative phone decision; pending installation remains ineligible. Session loss
invalidates the wire before closing runtime admission. Blocking installation work
runs on a distinct worker, never the socket listener, and checks cancellation
before mounting. No new root or device credential is created by these adapters.

## Finite candidate assembly checks

These are code-completion checks for the dormant candidate, distinct from live
credential configuration. An entry is complete only after aggregate tests and
independent review establish the stated behavior.

| Owned files | Acceptance |
|---|---|
| `device_socket/conversation.rs`, `ConversationSocketNegotiation.kt` | Existing device proof, exact negotiated identity, expiry/rotation rejection and no listener blocking |
| `channel/installation.rs`, `ConversationPhoneActivation.kt`, existing trust/key stores | Actual two-stage acceptance, current manifest authority, no pending capture or late promotion after Stop/loss |
| SDK custody/reader and owner page | Explicit owner initiation, exact root CAS, fresh session/key fences, readable authenticated text and complete verified renewal history |
| Confirmed-send queue and lifecycle hooks | Atomic proof plus delivery admission, exact idempotent retry, export inventory, retention redaction and guarded deletion |
| Owner endpoint composition and phone transport | Existing owner cookie/CSRF, independently held phone authority, real queue acceptance and decoded receipt upload; no claimed-request authority |
| Receiver/service mount and presentation port | Explicit disabled defaults, shared first-receipt/Stop gate, durable failure shown separately and no radio dispatch in test build |
| Packaged SDK assets and isolated emulator runner | Compiled native app, actual dormant server handlers and browser crypto complete the synthetic round trip |

No ordinary entry point or deployment flag is mounted here. Existing-root custody
configuration, exact selected-line observation, policy/disclosure approval,
release signing and reviewer access remain separate runtime/release gates.

Confirmed-submit responses acknowledge durable admission, including exact retries;
they do not report current delivery state or cause a previously claimed attempt to
be submitted again. The unnumbered proof schema candidate remains outside the
standard migration directory and is explicitly applied only by isolated fixtures.
Queue and lifecycle integration requires its allocated, reviewed migration before
deployment; disabled conversation routes do not replace that schema prerequisite.


The SDK now supplies explicit finite session custody composition and a bounded
profile-02 inbound reader. Custody joins the existing setup signer, exact owner-root
enrollment and verified successor re-read, then supplies the owner transport's local
prepare/sign/open methods. An existing nonextractable owner-root CryptoKey can be
adapted without generating or persisting credentials. Root approval, predecessor
CAS and independently sampled authority remain mandatory. A supplied AbortSignal,
session expiry, logout, revoked reader/signer or failed authority permanently close
custody. No returned transport success alone activates the signer.

Historical opening verifies the original signer and wraps at authenticated receipt
time, then current reader authority before and after plaintext opening. Reload can
restore accepted history by verifying a complete signed same-root successor chain
to the existing trust store's exact persisted high-water, without moving it backward.
Incomplete, forked, oversized or root-transition chains are refused. The authenticated
manifest-history source remains an integration dependency; it supplies public signed
bytes, never replacement reader keys or a new trust pin.

The page's owner configuration path requires an affirmative session-custody checkbox
and setup click before importing the packaged SDK or accessing custody. It assembles
the real owner transport, closes custody on pagehide/visibility/logout/expiry and
renders queued acceptance separately from delivery. The source-only packaging script
copies the existing built SDK and locked HPKE ESM graph to an explicitly selected
asset directory. Serving that directory on the disabled conversation router and
supplying existing-user custodian/authority/endpoint configuration are separate
assembly responsibilities; this change creates no default production mount.
