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

The [concept implementation matrix](CONCEPT-IMPLEMENTATION.md) binds each owner
and Android concept component to its actual data source, current implementation,
missing behavior and owning acceptance issue. It defines metric scope/freshness,
unavailable controls and the joint #612 candidate gate. Artwork is not runtime
evidence and a design change does not advance a release stage.

Sealed dashboard rules: fetch metadata and ciphertext; decrypt locally; render messages as plain text; never send decrypted content through HTMX forms or analytics; server search only metadata. Keep a clear vault-locked state, local-search limit, and explicit export sensitivity prompt.

## Android companion screens

The native gateway opens on **Home**, showing actual authenticated-service status, session heartbeat acknowledgments, the selected SIM, lifecycle-scoped local battery/charging observations and this session's pairing proof status. Test socket state stays separate. No sample queue, usage or SMS-readiness metrics are displayed.

**Setup** contains purpose-specific permission disclosures, SIM selection and device pairing. **Connection** contains authenticated heartbeat controls and the explicit reboot-resume choice. **Tools** contains transport diagnostics and controlled inbound metadata, one-shot SMS and debug-only MMS pilots. Changing screens does not request permissions or start a session; Back returns to Home. Each screen scrolls with large text and the keyboard. Pause stops connections but does not revoke Android SMS receiving access or stop permission-enabled local SMS processing.

These screens organize existing pilot capabilities; they do not implement full conversation synchronization. The sample artwork below remains a design reference.

The concept-inspired Home uses a compact brand and signal ring, named text navigation and flat observation sections on the same background. Thin separators organize the sections; Home actions use transparent outlined buttons. The current page has an accent underline and selected semantics. All actions retain visible touch targets of at least 48 dp, and navigation reflows into two columns on narrow viewports or at large text sizes, and quick actions reflow at large text sizes. Shared permission and consent buttons retain their existing presentation.

The two main message counts share a row when the content is at least 312 dp wide and the font scale is at most 1.3. Each value sits above its label, as in the concept. Compact windows and larger text use a stack, followed by the shorter awaiting-receipt observation. Each metric exposes one label-first observation; a traversal group keeps Submitted today before In queue in either layout and in right-to-left presentation. Real device-scoped values, capped counts, refreshing/stale labels and full UTC/scope explanations remain; a missing authorized reader says unavailable rather than zero. Phone observations align their values to the right at normal text sizes and stack at large type without truncation.

Only known connection proof/authentication observations animate; paused/offline states remain still and unknown or repair states use attention styling. Entrance motion stops when the activity is not resumed or Android animations are disabled. Secondary phone details and Android access observations open in dismissible, scrollable bottom sheets. Access grants are independent observations, not authorization to start a pilot or send; app notification enablement does not guarantee a particular channel's delivery. Pause and its local-processing disclosure stay in the main Home flow.

Setup presents an overview and separate access, SIM and pairing steps. Steps are navigation, not completion or readiness claims. Pairing can proceed without SIM selection; current connection-start controls require a selected SIM, while SMS access remains optional for pairing and connection tests. Back returns from a step to overview, then Home. Step changes reset the scroll position and expose a named accessibility pane. The activity supplies existing controls and handlers; pairing values remain masked and activity-local, and a recreated screen requires re-entering them. The access step exposes verified public privacy and deletion-request instructions through browser-only links; tapping a link sends no deletion request.

## Reference assets

- [ZROtext mark](assets/zrotext-mark.svg): editable SVG used in the README.
- [Android app concept](assets/android-app-concept.png): browser-rendered phone artwork with the planned gateway interface.
- [Fleet console concept](assets/fleet-console-concept.png): sample account, devices and message activity.
- [Two-location concept](assets/two-location-concept.png): sample routing and database-authority view.

These are design references with sample data, not Android hardware captures. When adding screenshots, remove personal numbers, email addresses, device identifiers, and tokens.

## Conversation review presentation

MainActivity exposes **Open conversation review** on Connection. Review remains
off by default. Opening the view or selecting a public file does not start setup,
capture, approve a request, or start a service. After selecting a public file,
**Enable review for this session** provides a foreground-only opt-in. A separate
**Review selected conversation** action uses the actual setup provider/controller;
it still requires current pairing, exact line binding and an existing enrolled
hardware reader. Software-only emulator custody is not accepted as hardware
enrollment. The opt-in is not saved or restored from intents or preferences, and
closing, backgrounding or recreating the activity turns it off.
Pausing a still-visible activity also revokes review and closes its setup;
visibility alone does not preserve foreground authority. Returning from
the initial picker requires a fresh opt-in. This review control does not grant
SMS permissions or replace the separate selected-conversation phone agreement.
An explicitly selected public setup file is bounded before
decoding and resolves existing pairing, line bindings and hardware enrollment;
the screen never creates a missing key. `FutureConversationPane` shows the
owner-provided port only after setup accepts the selected request. Approval
requires a verified label for the exact line generation and
binds the request identity and observed version. Decline and Back close the
review without granting approval. Choices remain vertically stacked and
scrollable at large text sizes.

Pending and recovery states do not claim confirmed activity. Observations expire
against monotonic receipt time, including delayed UI delivery; actions check
that budget again. Duplicate or older observations cannot renew it. Lifecycle
stops detach observation and clear displayed authority. A restart requires a new
interval and fresh phone approval from the domain.

Stop remains a request until durable closure is observed. A failed durable close
is described as capture disabled locally with closure unconfirmed. Retained
encrypted content is deleted separately, and submitted messages cannot be
recalled. Server composition, existing owner custody, root-signed manifests and
the phone's exact content-transfer approval remain required.

Closing or backgrounding the view closes its owned setup controller and rejects
late callbacks. Reopening creates a fresh controller and does not restore phone
approval. The initial setup file can be selected before activation. Reply
authority uses foreground manual input of the paired browser's exact canonical
base64 export, bounded to 21,900 characters and 16,423 decoded bytes. Nothing is
read automatically from the clipboard or saved. A separate verification action
is bound to the original active observation and its remaining lease; expiry,
changed observations, closing and backgrounding invalidate pending UI actions
and completions. Opening or cancelling the input does not remount the consent
pane or renew approval. An external file picker during an active interval still
closes that interval; returning cannot restore it. A failed close remains visible
and prevents another setup in that activity. Replies remain off by default.
After review opt-in, **Allow approved replies for this session** is a separate
deliberate choice, disclosed with carrier charges. Its value selects the existing
guarded execution composition for that setup only. It cannot grant content
consent, import reply authority, create an execution grant or bypass policy.
Candidate replacement, pause, stop, closing and recreation withdraw this choice;
the owned runtime closes before later callbacks can restore authority.
Each reply control belongs to its exact local choice generation. Earlier control
actions cannot re-enable a withdrawn choice or apply to a reselected candidate.

**Enroll conversation keys and compared root** opens a separate foreground
ceremony. It requires the current proof-authenticated host, an owner-approved
line, selected SIM continuity, SMS permissions and Android API 31 or later.
Creating a reader explicitly provisions a hardware ECDH key through the existing
enrollment lifecycle and initializes local journal protection when there is no
retained state needing recovery. The existing paired signing key is read without
creation or signing and must have StrongBox or TEE custody. Only public values
are exposed. The 223-byte `ZTPK01` packet binds account, device, line, paired
signing-point SHA256, big-endian binding generation, reader point and signing
point. Its independently compared fingerprint is SHA256 of
`ZTSE/phone-keys/v1` followed by a zero byte and the complete packet.
Software or unknown reader custody is refused. Lost protection with retained
conversation, inbound or suppression state is never silently recreated.

Root import accepts only the existing public genesis pin for the authenticated
account. The full fingerprint is independently entered and compared, never
autofilled from the downloaded candidate. Separate confirmation consumes the
existing comparison receipt and persists an unfresh root pin. Cancellation,
backgrounding, host/line/SIM or permission loss fence storage precommit.
Completed enrollment remains durable; closing does not delete keys or reset trust.
Enrollment never grants capture, content transfer or sending.

**Save public phone key export** explicitly selects a public binary-file
destination. Only the requested public packet survives that destination picker;
review, reply permission and pending enrollment still withdraw on pause.
Saving resumes in the foreground and rechecks the original authenticated host,
line, SIM, permissions and both existing hardware keys. Its elapsed lifetime is
five minutes and is checked again after binding validation, before opening the
selected destination; changed or lost keys are never replaced. Cancel, explicit close or
destruction discards pending export. Pause fences a write already in progress.
The completion presents the exact saved packet fingerprint for independent
comparison directly on the phone; a failed write may leave an incomplete public
file, which must be discarded. Files and fingerprints alone grant no authority;
the owner flow must match the export against current paired scope and keys.

First review accepts at most 64 public root-signed manifest predecessor links,
one canonical base64 manifest per line. Verification and every trust CAS use the
same negotiated authenticated socket clock as ordinary setup, without a separate
connection or phone wall-clock fallback. Genesis and each newly accepted link
must still be live; expired history and missing keys require separately supported
recovery and cannot be restored by this UI. The complete chain is preflighted
against the selected setup predecessor and hardware reader before its first CAS.
An interrupted import can resume from its exact persisted signed checkpoint;
replaying an accepted prefix cannot lower or duplicate the high-water mark.
Missing server root custody, initial archive/reader manifest publication or
validated SDK mounting still prevents ordinary production activation.
