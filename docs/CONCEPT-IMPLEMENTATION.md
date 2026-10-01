# Owner and Android concept implementation contract

This is the durable component/state mapping for #606 and the #605 candidate
requirement. The [fleet](assets/fleet-console-concept.png) and
[Android](assets/android-app-concept.png) concepts contain sample data. This
mapping specifies implementation and acceptance; it is not a visual acceptance
report or permission to publish a candidate. #612 must review actual integrated
browser/APK renders. No scope deferral below is a maintainer-approved waiver.

Use the canvas, surface, raised-surface, text, secondary, accent, caution and
border tokens in [DESIGN.md](DESIGN.md). Shared owner navigation uses the mark,
current-page indication and meaningful headings. Keep compact mobile navigation
and a desktop rail equivalent; never make essential controls hover-only. Keep
native Android controls, 48dp targets, 200% text, Back and system insets.

## Component, source and acceptance matrix

Status describes current source, not feature enablement. Owner routes keep
cookie/CSRF/Origin and owner-only fences; observer navigation stays separate.
Existing IDs, event wiring, secret clearing, MFA and destructive confirmation
are contracts for every presentation change. No UI can widen authority.

| Component/reference | Current implementation and authoritative source | Required presentation or missing behavior | Owner and acceptance |
|---|---|---|---|
| Owner desktop rail/mobile navigation | Shared responsive shell on owner devices/account/SMS-lines/seats pages (`owner-shell.js`, merged #683), with fleet-first navigation and current destination; observer page retains separate role navigation | Use shared tokens/mark, current destination, keyboard focus and responsive navigation; fleet first, administration discoverable | #607; rendered mobile/desktop navigation and every real link, including observer refusal on owner destinations |
| Fleet overview | `web/owner/devices.*`; merged #685 fleet overview and selectable bounded snapshots from `/v1/enrollment/devices`, owner event stream plus fallback snapshots | Prominent account fleet with truthful lease/precondition/queue columns; preserve pairing and input/focus on refresh | #609; synthetic empty/multiple/revoked devices, SSE reconnect, resume and paging |
| Selected device side panel | Merged #685 selects an immutable device ID into a desktop detail/mobile stacked panel; missing, stale or failed snapshots retain explicit uncertainty | Select by immutable device ID; desktop detail/mobile stacked view; disappearing selection becomes unavailable | #609; keyboard selection, missing/revoked device, pending input and stable focus |
| Device readiness | `active_socket_lease`, `status_observed_at_ms`, optional `reported_preconditions` from enrollment | Distinguish transport proof, Android local preconditions, report freshness, line authority and unknown carrier readiness | #609; missing SIM, denied SMS permission, airplane/network unknown, quarantined/revoked/stale observations |
| Activity table | `/v1/owner/messages`, writer event expansion, alpha cancellation; `devices.js` history controls | Responsive time/device/recipient/state table, text-labelled chips, preserve cursor and expansion | #610; pending/granted/submitted/delivered/failed/unknown, paging, active interaction and device link |
| All/outbound/inbound filter | Inbound history requires an explicit message identity; there is no unified inbox feed | Outbound metadata is available; a unified filter remains unavailable until an actual scoped feed ships | #610; no cosmetic inbound filter or claim of full conversation availability |
| Account/security and credentials | `/owner/account` and existing devices-page security/session/API-key controls | Preserve registration, email verification, password/MFA/reset, session revocation, masked secrets and explicit grant widening | #607; form wiring, token clearing, sign-in failures and step-up error/focus behavior |
| SMS lines and SIM choice | `/owner/sms-lines`, owner approval key and default-off line activation; phone selected subscription | Link existing key/approval/activation flow; display permitted slot/state, not sample phone digits | #607/#609; stale/changed SIM, cancelled comparison, revoked line and disabled activation |
| Team and observer | `/owner/seats` and `/owner/observer`; device-status-only observer seats | Separate role navigation, seat lifecycle and current status; no decrypted-content/team/root authority for observer | #607/#633; cross-role destinations, removed membership and stale sessions |
| Plans/usage | `/billing` and existing `/v1/billing` session, capacity and entitlement endpoints, TEST-only provider flow | Link the real owner billing dashboard; unavailable live prices/public usage stay labelled; do not add dead pricing links | #607/#631; TEST/disabled/pending/hold/over-cap states, no payment-success inference from navigation |
| Android wordmark and signal | `GatewayCompanion.kt`, `GatewayVisuals.kt`, native theme; merged #603/#604 | Retain connection-state signal, reduced motion and lifecycle suspension, never artwork-derived connectivity | #611/#612; actual debug APK cold launch/resume/rotation and disabled animations |
| Android Home | `GatewayHome`, session heartbeat acknowledgements, selected SIM, Pause and widgets; merged #693 adds read-only lifecycle-aware local Power | Compact Sending from/Power/Connection rows; truthful summary placeholders until Android consumes the merged #695 authenticated source | #611; missing observations, large text, portrait/landscape/keyboard and TalkBack order |
| Android Setup | `GatewaySetupGuide`, merged #648; explicit disclosure from #602 | Preserve steps, permission explanation/decline and fingerprint comparison; navigation itself grants nothing | #611/#612; Back, dismissal, interrupted setup and no permission/service/radio side effects |
| Android Connection | Existing credential fields, test/authenticated statuses and explicit start/pause controls | Keep masked credentials and precise connecting/authenticated/repair states, reachable from Home | #611/#612; validation errors, revoked credentials, reconnect and resumed stale state |
| Android Tools | Existing controlled test/diagnostic controls | Keep explicit test-only limitations and diagnostics; no widget or navigation auto-starts tests | #611/#612; opening/dismissing is free of radio/service effects |
| Android consent/widgets | Native access disclosure and Android-access/phone-detail sheets | Pause limitation adjacent to main action and sheets; decline/dismiss never requests permission | #611/#612; 48dp, focus return, 200% text and actual TalkBack traversal |

## Metrics and action decisions

The concept numbers are never fallback values. A server snapshot has its own
observation time; a phone's session counter, heartbeat ACK or local journal
length cannot substitute for an account/device message total.

| Concept element | Binding and semantics | Current support / required decision |
|---|---|---|
| Submitted today | Merged #695 exposes account or selected-device observations through `/v1/owner/message-summary`; the first complete successful sent callback counts once in the UTC day of server receipt, with no recipient or body | One writer snapshot, values through 1,000 exact and larger totals labelled `1000+`; observations expire after at most 30 seconds or at the UTC day boundary. Owner-session/CSRF and device-scoped `messages:read` fences apply; submitted is never delivered |
| Waiting in queue | Existing per-device `pending_messages` and `in_flight_messages` are separate capped writer states (1,000); granted work is not pending | Label device scope and cap; at cap show `1,000+`/bounded, not exact account total. Never sum a page of devices into an account total; merged #695 separately supplies explicit account or device waiting/claimed observations, including claimed work with grants; do not relabel that count as ungranted queue depth |
| Connected devices | `active_socket_lease` at `status_observed_at_ms`, among explicitly displayed/paginated devices | Label page scope; no claim of all-account count from a partial page, SIM readiness or delivery success |
| Monthly usage | Authoritative metering reservations/refunds and applicable UTC period, not visible message page length | Do not manufacture a percentage without permitted queried quota/usage and units; public projection remains #631, independently gated |
| Heartbeat age | Owner snapshot records status observation time; phone counts ACKs this session | Exact last-heartbeat timestamp is unavailable in the owner projection. Say observation age and authenticated lease, not sample heartbeat age |
| Battery/Power | Android read-only battery percentage and charging observation with lifecycle refresh | Merged #693 supplies read-only local Home Power, refreshed across lifecycle changes and labelled unavailable without an observation. Owner battery remains unavailable until a separate remote contract is reviewed |
| Sending from / masked SIM | Permitted subscription slot/display/state and independently activated line | Do not request phone-number access or invent sample last digits. A changed/missing SIM invalidates readiness; owner receives no SIM serial/number |
| Remote Pause | No owner remote-pause API | Unavailable. Revoke permanently removes device authority and is not Pause; never relabel it. New remote action requires its own reviewed contract |
| Local Pause | Existing `onPause` stops connections, not permission-enabled local SMS processing | Keep the local-processing limitation beside the action; Android settings can revoke receiving access. No claim of suppressing already granted or submitted work |
| Simulate a message | Existing synthetic receptionist demo is a separate local script | Label simulation and link only to that demo; it cannot grant real sending or stand in for the stable API |

## State and freshness grammar

Apply this independently to each panel/metric; a loaded account does not make a
missing device report fresh. Preserve input/focus during refresh and announce
meaningful state changes politely without recurring heartbeat speech.

| State | Required treatment and safe action |
|---|---|
| Loading | Visible text/progress for the pending region; no fabricated zero or success, preserve existing data as stale if shown |
| Empty / true zero | Empty list and authoritative fresh zero are separate labels; pair/setup is reachable only with actual owner authority |
| Error / unavailable | Explain unavailable source or request failure and allow bounded explicit retry; never keep stale success styling |
| Stale / offline | Show observation time, stale/offline label and last-known provenance; no implication of current SIM/radio readiness |
| Paused | Describe the actual local connection pause and remaining local processing; remote pause remains unavailable |
| Connecting | Transport attempt only; cannot use authenticated, ready, submitted or delivered styling |
| Authenticated | Valid socket lease/ACK proves transport identity only; display local preconditions/line authority separately |
| Revoked / quarantined | No success state or sending controls; distinguish known revoked authority from unavailable readiness, retain inspection/repair guidance |
| Missing/changed SIM | Unknown or changed selected subscription is a blocker, not healthy zero traffic; no sample identifiers |
| Denied permission | Show specific denied access and reachable explicit explanation/setup; do not request it on navigation or dismissal |
| Pilot gated / unsupported | Explain the implemented restriction; credentials, a local preview or a lease cannot enable a missing feature |
| Submitted / delivered / unknown | Use writer evidence: accepted/queued/granted are not submitted; submitted is not delivered; unknown never automatically resends |

## Candidate acceptance and intentional differences

#607 common shell/DOM conventions and #609 fleet selection are implemented in
merged #683/#685. #610 activity presentation remains separately tracked; #612
still owns their integrated visual and accessibility acceptance. #608 owns authoritative count contracts;
#611 extends the merged #602 → #603 → #604 → #648 Android foundation. #612
compares the integrated source and debug APK against both reference concepts at
compact mobile/wide desktop, portrait/landscape, default/200% text and keyboard
open. Check keyboard/focus/live refresh, Back/cold start/resume/rotation,
contrast, actual TalkBack reading order and motion on a physical phone before
claiming those checks. Use synthetic no-radio fixtures; captures stay private.

Native permission disclosure, observer fences, masked credentials, pilot gates
and truthful unavailable metrics intentionally differ from the artwork. These
are security/accuracy requirements, not permission to omit concept acceptance.
Full inbox, conversation content, remote Pause, live payments, provider sending
and managed AI remain unavailable unless their own runtime contracts and gates
ship. Locally authorized decrypted content is rendered as plain text; never
upload it for relay search/analytics or inject it as HTML.

Current roadmap reconciliation preserves capability stages and general-send
gates. The existing signed rc.2 artifact is prior restricted-candidate evidence,
not acceptance of the new Home/owner concept or a date/tag for the next release.
The dormant conversation groundwork in merged #613/#650/#651/#652/#655 is not
general customer conversation delivery. Sealed admission, inbound upload and metadata-only read/lifecycle projections
are default-off prerequisites. Dormant Android grant execution groundwork is
implemented. Merged #698 adds negotiated, default-off grants, device-bound
payload fetch and dispatch metadata. The Android service gate remains
unintegrated; live service routing and final API/runtime acceptance remain open.
