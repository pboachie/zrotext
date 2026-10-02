# Android gateway accessibility review

## Scope

The gateway presents a Home screen, with connection diagnostics, heartbeat
settings, controlled SMS setup and device pairing in its Setup and Tools screens.
This review covers these screens and their enabled controls. It does not certify
accessibility conformance or establish device, radio or carrier support.

The review follows Android's guidance for
[semantics](https://developer.android.com/develop/ui/compose/accessibility/semantics)
and [accessible apps](https://developer.android.com/guide/topics/ui/accessibility/apps).

## Findings and behavior

| Area | Behavior and verification | Limits |
|---|---|---|
| Labels and secret fields | All eight text fields retain visible Material labels. Buttons retain text names and native click semantics. Both token fields retain password semantics and visual masking. Rendered-tree assertions verify these properties. | No localization, autofill-service or spoken-password session was exercised. |
| Headings and order | The app title and four sections expose heading semantics. Sections remain in a column. The two primary metrics form a traversal group with a label-first observation per cell; platform-node tests verify Submitted today, In queue, then Awaiting receipt in either responsive layout and RTL. Section tests retain their sequence and vertical-position checks. | Actual TalkBack heading navigation, keyboard traversal and Switch Access scanning require a separate interactive review. |
| Contrast | A themed `Surface` paints the dark background and supplies the matching foreground. Tests check enabled body/label/action/error text against at least 4.5:1 contrast and field borders against at least 3:1, using the configured colors. | These are color-pair checks, not a complete pixel audit of every focus, disabled, selection or system-dialog state. |
| Touch targets | Gateway buttons explicitly reserve at least 48 by 48 dp in their visible/semantic layout. Tests measure rendered action bounds; the app does not rely only on Material's expanded hit area around a 40 dp button. | Reachability with alternate input devices has not been established. |
| Text scaling and insets | Content can grow vertically without fixed text heights or ellipses. Safe drawing and keyboard insets keep the scrolling area separate from system UI. JVM checks exercise a compact portrait viewport at normal and 2× font scale. | Landscape, magnification, display-size combinations and every supported Android version need further device checks. |
| SIM selection | A SIM action exposes its selected state and a state description. A JVM test uses a synthetic subscription and verifies the semantics change after selection. | This does not validate physical SIM detection or service availability. |
| Status and errors | Connection, authenticated connection and pairing statuses are polite live regions. Heartbeat counters remain separate ordinary text to avoid recurring announcements. Validation errors continue to use these status fields. | A semantic live region is not proof of speech delivery. Off-screen status updates and focus recovery after validation errors need a real screen-reader session. |

## Repeatable checks

Home groups the sending line, local power observation and connection state into
read-only rows. Each row exposes its label and value together, wraps at larger
font sizes and has no click action. The power row uses the phone's sticky battery
broadcast while Home is resumed and unregisters when paused or left. Missing or
malformed observations say unavailable; an actual zero percent remains zero.
Charging or full is distinct from not charging. These observations do not grant
permissions, start a service or establish remote fleet freshness. Lifecycle tests
exercise pause, resume, navigation and unavailable observations without radio
activity. The adjacent Pause disclosure continues to describe local SMS processing.

There are six shared accessibility checks, including the Home observation rows.
The historical emulator results below predate that additional check.

The existing Android CI unit-test task discovers `GatewayAccessibilityTest`,
`GatewayDefaultScaleAccessibilityTest`, `GatewayCompactAccessibilityTest`,
`GatewayRtlAccessibilityTest` and `GatewayContrastTest`. They render the
actual activity through Robolectric on API 34, inspect its Compose semantics and
exported platform accessibility nodes, and measure action bounds. Native graphics
enable the region calculations used to expose unobscured accessibility nodes.
Android resources are included so the real Material fields
are rendered. The shared checks also run through the opt-in
`GatewayAccessibilityDeviceTest` instrumentation wrapper in the
[no-radio device smoke workflow](../.github/workflows/android-device-smoke.yml).
That workflow selects its six accessibility checks alongside one device
preconditions check on a disposable emulator. The earlier five-check version in the
[merged accessibility change](https://github.com/pboachie/zrotext/pull/313) passed
the [hosted selection](https://github.com/pboachie/zrotext/actions/runs/36269589242)
with six actual tests and zero failures or skips.

The current six shared checks cover the Home observation rows and separate
screens/substeps. The harness verifies the initial title heading, then scrolls
to reveal a Home status below the fold before asserting its visible platform
live-region flag. Landscape and 200% text must retain that assertion. Separate
Compose-clock JVM landscape regressions verify actual scrolling and reachable
Pause/disclosure; see [the integrated candidate gate](CANDIDATE-ACCESSIBILITY.md).
These checks validate platform semantics, not spoken announcements.

Home uses the common dark canvas for its observations and transparent outlined
actions. Navigation remains named text with native button semantics; an underline
and selected/state descriptions identify the current page. The compact navigation
regression measures visible targets between 48 and 52 dp high at default text size
and checks that navigation does not request access or start services. A 320 dp
viewport uses two navigation columns so complete names stay on one line. Existing
heading, live-region, observation order, 48 dp target, masking, disclosure and
large-text assertions remain. Normal-width primary metrics share a row; compact
viewports or font scales above 1.3 use a stack. Bounds checks require equal-width,
non-overlapping columns or non-overlapping stacked cells, with Awaiting receipt
below both. Each metric supplies its full label and value once, without a click
action or live region. The platform check really scrolls the observations into
view and verifies exported text and traversal links. RTL mirrors the columns
while preserving logical reading order. The JVM RTL fixture enables RTL support
only in its test application and asserts the actual root direction; this does
not establish app-wide localization. At large text sizes, quick actions use one column
and observation labels and values stack. The app keeps its dark palette under
either system theme; changing system appearance does not change authorization.

```sh
cd android
./gradlew :app:lintDebug :app:testDebugUnitTest :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon
```

Use `gradlew.bat` on Windows. For the emulator harness, first install the debug
and instrumentation APKs on a **disposable emulator**. Select it explicitly with
`adb -s "$EMULATOR_SERIAL"` for every command. Run at normal font scale, then at
2× scale, and restore the original setting afterward:

```sh
adb -s "$EMULATOR_SERIAL" shell settings put system font_scale 1.0
adb -s "$EMULATOR_SERIAL" shell am instrument -w -r \
  -e a11yIsolatedEmulator true \
  -e class org.zrotext.gateway.GatewayAccessibilityDeviceTest \
  org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner
```

Repeat with `font_scale 2.0` before restoring the emulator's original scale.

The wrapper checks for an emulator and an explicit opt-in. It launches the screen
but does not press gateway buttons, grant SMS permissions, enroll keys, connect to
a hub or send a message. Opening the real activity can affect its reboot-resume
preferences, so do not run it on an operator's configured device.

## Remaining interactive review

Before claiming assistive-technology usability, exercise TalkBack and Switch
Access on representative supported phones. Check all sections, heading navigation,
input editing and masking, SIM selection, validation errors, asynchronous pairing
results, off-screen updates, focus retention and keyboard appearance. Use synthetic
data and no-radio fixtures. Do not treat these semantics tests as carrier evidence
or as a substitute for observed screen-reader output.
