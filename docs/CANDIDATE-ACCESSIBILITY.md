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
| Authoritative summaries | `summary.test.js` | Loading, genuine zero, exact/capped counts, selected scope, unavailable responses, offline/historical observations and UTC rollover. A missing source never becomes zero. |
| Android navigation and Setup | `GatewayCompanionInteractionTest`, `GatewaySetupGuideTest` and shared accessibility checks | Back, step navigation, dismiss/decline, labels, token masking and no permission/service/radio effects. Navigation is not completion or readiness. |
| Android Home and local power | `GatewayHomePowerLifecycleTest` and shared accessibility checks | Missing/malformed and zero power values, receiver lifecycle, read-only observation order, conservative paused status and adjacent Pause disclosure. No remote fleet or SMS-readiness inference. |
| Android landscape and large text | `GatewayLandscapeAccessibilityTest` and `GatewayDefaultScaleLandscapeAccessibilityTest` render the actual activity with the Compose frame clock | Actual scrolling reveals the platform-visible polite status node and keeps Pause/disclosure reachable in 640×360dp at default/200% text. Static off-screen bounds are not accepted as visible. |
| Actual debug APK | Opt-in `GatewayAccessibilityDeviceTest` on an explicitly selected disposable emulator | Same six heading, order, naming, target, masking and live-region checks across Home, Setup substeps, Connection and Tools. Revealing an off-screen status uses real UI scrolling. Platform flags do not prove spoken TalkBack announcements. |

Browser fixtures disable external requests and provider/radio actions. The
contrast traversal checks rendered visible text and its opaque ancestor
background, excluding disabled controls; it is not a complete pixel audit of
input values, transparency, every focus/selection state or disabled appearance.
Existing theme contrast tests complement it. Normal CI discovers browser tests
through `browser/*.test.js` and Android regressions through the JVM suite; the
existing no-radio class selection also runs the shared APK checks.

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
