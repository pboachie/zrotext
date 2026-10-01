# ZROtext visual direction

## Brand

Display name: **ZROtext**, pronounced “zero text.” Wordmark: heavier `ZRO`, regular `text`, no separating underscore. Domain, repository, CLI and package identifiers remain lowercase `zrotext`. Tagline: **Your phone. Your number. Your SMS API.** The slashed-Z mark is an editable SVG asset.

The visual direction uses dark green surfaces, monospace labels, connection states and lime accents. Use contemporary readable typography for prose and product controls. No CRT flicker, boot delay, scanline overlay on text, or sound on send. Avoid implying that retro visuals provide security.

| Token | Value | Use |
|---|---|---|
| Background | `#0b0f0c` | Main canvas |
| Surface | `#111712` | Panels |
| Raised surface | `#161e17` | Hover / contextual panels |
| Text | `#f0f3e9` | Primary text |
| Secondary | `#99a696` | Supporting copy |
| Accent | `#b6f36a` | Primary action / connected indicator |
| Caution | `#edbe70` | Offline, queued, recovery |
| Border | `#29332a` | Subtle structure |
| Fonts in concept | Segoe UI/Arial; Consolas/Courier New | Offline-renderable system fonts |

Never put essential status meaning in color alone. Buttons and inputs need keyboard focus, accessible names, adequate tap area, and reduced-motion behavior.

## Screens and behavior

| Screen | Design direction |
|---|---|
| Landing | Explain the phone/SIM gateway and link to source and setup instructions |
| Fleet console | Show device health, messages, and clear offline and empty states |
| Android gateway | Use Compose UI for pairing, permissions, SIM selection, and connection state |
| Two-location topology | Explain routing and the single-writer boundary |

Account and device screens should include loading, empty, error, and stale states. Never represent offline or unknown as delivered.

Sealed dashboard rules: fetch metadata and ciphertext; decrypt locally; render messages as plain text; never send decrypted content through HTMX forms or analytics; server search only metadata. Keep a clear vault-locked state, local-search limit, and explicit export sensitivity prompt.

## Android companion screens

The native gateway opens on **Home**, showing actual authenticated-service status, session heartbeat acknowledgments, the selected SIM, lifecycle-scoped local battery/charging observations and this session's pairing proof status. Test socket state stays separate. No sample queue, usage or SMS-readiness metrics are displayed.

**Setup** contains purpose-specific permission disclosures, SIM selection and device pairing. **Connection** contains authenticated heartbeat controls and the explicit reboot-resume choice. **Tools** contains transport diagnostics and controlled inbound metadata, one-shot SMS and debug-only MMS pilots. Changing screens does not request permissions or start a session; Back returns to Home. Each screen scrolls with large text and the keyboard. Pause stops connections but does not revoke Android SMS receiving access or stop permission-enabled local SMS processing.

These screens organize existing pilot capabilities; they do not implement full conversation synchronization. The sample artwork below remains a design reference.

The concept-inspired Home uses a signal ring, compact labelled icon shortcuts and spring-in cards. Only known connection proof/authentication observations animate; paused/offline states remain still and unknown or repair states use attention styling. Custom motion stops when the activity is not resumed or Android animations are disabled. Secondary phone details and Android access observations open in dismissible, scrollable bottom sheets. Access grants are independent observations, not authorization to start a pilot or send; app notification enablement does not guarantee a particular channel's delivery. Pause stays in the main Home flow.

Setup presents an overview and separate access, SIM and pairing steps. Steps are navigation, not completion or readiness claims. Pairing can proceed without SIM selection; current connection-start controls require a selected SIM, while SMS access remains optional for pairing and connection tests. Back returns from a step to overview, then Home. Step changes reset the scroll position and expose a named accessibility pane. The activity supplies existing controls and handlers; pairing values remain masked and activity-local, and a recreated screen requires re-entering them. The access step exposes verified public privacy and deletion-request instructions through browser-only links; tapping a link sends no deletion request.

## Reference assets

- [ZROtext mark](assets/zrotext-mark.svg): editable SVG used in the README.
- [Android app concept](assets/android-app-concept.png): browser-rendered phone artwork with the planned gateway interface.
- [Fleet console concept](assets/fleet-console-concept.png): sample account, devices and message activity.
- [Two-location concept](assets/two-location-concept.png): sample routing and database-authority view.

These are design references with sample data, not Android hardware captures. When adding screenshots, remove personal numbers, email addresses, device identifiers, and tokens.
