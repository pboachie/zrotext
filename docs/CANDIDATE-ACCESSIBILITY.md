# Integrated candidate accessibility gate

The owner and Android concepts in [DESIGN.md](DESIGN.md) guide presentation;
their sample numbers are not live observations. The implementation contract in
#606 and integrated acceptance in #612 remain release prerequisites. Automated
checks and an emulator do not approve unresolved scope decisions, establish
accessibility conformance, or authorize publication or sending.

## Repeatable rendered checks

| Surface | Automated check | Scope and remaining review |
|---|---|---|
| Owner shell and forms | `web/owner/browser/shell.test.js` and `candidate.test.js` render the actual HTML, CSS and controllers in Chromium | Owner/observer session responses are synthetic API fixtures. Compact 320px and wide 1440px at default and 200% text cover visible text contrast, control names, headings, polite status regions, keyboard focus and reflow. Compact navigation also preserves whole words at 320px/390px with default and doubled text. This is not a live server-session or spoken screen-reader test. |
| Fleet and selected details | `fleet.test.js` and `candidate.test.js` | Empty/multiple/revoked, permission/SIM/network blockers, absent reports, local aging, failed refresh, selected identity, paging, keyboard selection and input/focus preservation. Remote Pause, battery and phone digits are explicitly unavailable in this projection. |
| Integrated state matrix | `browser/statematrix.test.js` | One deterministic rendered pass over the #612 state grammar: authenticated lease, unknown lease, no lease, changed (inactive) SIM with named blockers, denied SMS permission, absent precondition report, revoked authority, pilot-gated note, writer state wording (`queued`/`submitted`/`delivered` always carry their evidence and limit, `unknown`/unrecognized carry the duplication caution), loading, empty true zero, failed refresh with retained stale snapshot, paused automatic refresh (no polling), and an unavailable summary that never renders a zero. Asserts directly that no branch styles or words unknown work as connected or delivered. |
| Authoritative summaries | `summary.test.js` | Loading, genuine zero, exact/capped counts, selected scope, unavailable responses, offline/historical observations and UTC rollover. A missing source never becomes zero. |
| Combined fleet overview | `overview.test.js` and `shell.test.js` | Summary precedes hardware/detail and outbound activity at 320px, 390px and 1440px with default/200% text. Combined selected scope, pending input, keyboard focus, failed summaries and refreshed message history preserve their independent states. |
| Android navigation and Setup | `GatewayCompanionInteractionTest`, `GatewaySetupGuideTest` and shared accessibility checks | Back, step navigation, dismiss/decline, labels, token masking and no permission/service/radio effects. Navigation is not completion or readiness. |
| Android Home and local power | `GatewayHomePowerLifecycleTest` and shared accessibility checks | Missing/malformed and zero power values, receiver lifecycle, read-only observation order, conservative paused status and adjacent Pause disclosure. No remote fleet or SMS-readiness inference. |
| Android writer summary reader | `GatewaySummaryClientTest`, `GatewaySummaryStateTest`, `GatewaySummaryUiTest` and shared accessibility checks | Separate masked read credential and explicit selected-device HTTPS request; bounded metadata parsing, real zero/capped counts, expiry, generation-based late-response rejection, page/lifecycle cancellation and fresh/historical labels. Synthetic JVM/UI fixtures do not establish an integrated authenticated network, emulator or physical run. |
| Android landscape and large text | `GatewayLandscapeAccessibilityTest` and `GatewayDefaultScaleLandscapeAccessibilityTest` render the actual activity with the Compose frame clock | Actual scrolling reveals the platform-visible polite status node and keeps Pause/disclosure reachable in 640×360dp at default/200% text. Static off-screen bounds are not accepted as visible. |
| Actual debug APK | Opt-in `GatewayAccessibilityDeviceTest` on an explicitly selected disposable emulator | Same six heading, order, naming, target, masking and live-region checks across Home, Setup substeps, Connection and Tools. Revealing an off-screen status uses real UI scrolling. Platform flags do not prove spoken TalkBack announcements. |

Browser fixtures disable external requests and provider/radio actions. The
contrast traversal checks rendered visible text and its opaque ancestor
background, excluding disabled controls; it is not a complete pixel audit of
input values, transparency, every focus/selection state or disabled appearance.
Existing theme contrast tests complement it. Normal CI discovers browser tests
through `browser/*.test.js` and Android regressions through the JVM suite; the
existing no-radio class selection also runs the shared APK checks. The emulator
runner requires all six named accessibility methods; six arbitrary successes,
replacements, duplicate names or skipped methods cannot satisfy that selection.

Run owner-controller and rendered suites:

```sh
node --test web/owner/*.test.js
cd web/owner
npm ci --ignore-scripts
npm run test:rendered
```

Run Android lint, JVM and actual APK builds:

```sh
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon
```

Use `gradlew.bat` on Windows. Follow [Android accessibility](ANDROID-ACCESSIBILITY.md)
for the explicitly selected disposable-emulator command. Test normal and 200%
text in compact portrait and landscape with animations disabled. Record the
Git source revision and APK SHA-256 in the PR or private test record. Screenshots,
device logs and recordings belong in temporary/private storage; optional browser
captures use `ZT_OWNER_SCREENSHOTS=1` and a fresh OS temporary directory.

## Executed #612 acceptance method and durable findings

The integrated candidate was verified by rendering the authenticated owner
fleet overview in Chromium from the served HTML/CSS/controllers with synthetic
owner-session fixtures at 375px and 1440px, default and 200% text, and with a
pairing input focused; and by installing the actual `assembleDebug` APK on a
disposable emulator and capturing Home in portrait and landscape at default and
200% text with animations disabled, plus the Setup and Connection screens in
portrait. Concept comparison used the DOM/semantics inventory of those renders
against `docs/assets/fleet-console-concept.png` and
`docs/assets/android-app-concept.png` via the #606 matrix. Captures stay in
temporary/private storage; nothing dated belongs in this repository.

Computed WCAG 2.1 contrast for the implemented token palette (web and Android
share it): text `#f0f3e9` on `#0b0f0c`/`#111712`/`#161e17` = 17.19/16.19/15.18;
secondary `#99a696` on the same = 7.58/7.14/6.69; accent `#b6f36a` as link or
quiet-button text on the same = 14.72/13.87/13.00; button text `#0b0f0c` on the
accent fill = 14.72; caution `#edbe70` on canvas/surface = 11.21/10.56. All pass
AA 4.5:1. Non-text: the accent focus outline (13.87+) and input borders
`#99a696` (7.14+) pass 3:1; the Android outline `#677363` is 3.42:1 on
`#161e17` and 3.64:1 on `#111712`. The structural card border `#29332a`
(1.30–1.47:1) is decorative separation; every interactive control carries its
own passing border or fill, so no required indicator relies on it. The
rendered `candidate.test.js` traversal enforces the text ratios at 320/1440px
and 100/200% on the served owner pages, and `GatewayContrastTest` enforces the
Android pairs in the rendered Compose tree.

Verified state honesty on the integrated build: an unknown
`active_socket_lease` renders "live status unavailable" and never lease
wording; writer `delivered` always reads "Delivered callback · unread status
unknown" and `submitted` "Sent callback · delivery unconfirmed"; unknown and
unrecognized states carry the duplication caution and caution styling; summary
unavailability renders "Unavailable", never a zero; Android `GatewayConnectionMood`
maps unrecognized statuses to the attention treatment and only named
authenticated observations to the connected treatment (JVM-tested). The web
event-stream fallback (SSE failure to 15-second snapshots) has no dedicated
status line; freshness stays visible per row through snapshot timestamps and
the fleet summary, and the behavior is documented on the page's own
freshness help text.

Open items found by this matrix: the local receptionist-demo page's secondary
control borders remain below the 3:1 non-text minimum (the historical M1
finding; that page is not served by the server, and the recommended fix is a
`#99a696`-class at-rest border). The conversation simulator page inherits the
audited `devices.css` palette but is not itself part of the rendered contrast
traversal. Android disabled-animations support is verified source-side only
(`gatewayMotionAllowed` reads `ANIMATOR_DURATION_SCALE` and `GatewayEntrance`
snaps to its final state); it has no deterministic JVM regression.

## Acceptance still requiring a human session

The integrated candidate requires actual TalkBack traversal and spoken status
changes, heading navigation, focus return from sheets, editing/masking with the
keyboard, permission revocation, rotation, cold launch and resume. Review
connecting/authenticated/offline/paused, revoked/quarantined, missing/changed SIM,
permission-denied, error and pilot-gated states using synthetic no-radio fixtures.
Verify system insets and reachable Pause/disclosure with the keyboard open.

Compare actual browser/APK captures with both approved concepts and the #606
component/state matrix. Any intentionally unavailable metric/control, navigation
or visual divergence needs an explicit maintainer scope decision. An unresolved
dependency or test failure must remain an acceptance blocker, not a passing
checkbox. No artwork, source assertion, historical scrolling-screen review or
new Home semantics test alone completes this gate.

Physical-phone motion performance, representative OEM behavior, interactive
TalkBack/Switch Access and carrier behavior require separate evidence. Do not
infer them from an emulator or enable a release/sending gate after these tests.
