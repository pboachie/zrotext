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

## Reference assets

- [ZROtext mark](assets/zrotext-mark.svg): editable SVG used in the README.
- [Android app concept](assets/android-app-concept.png): browser-rendered phone artwork with the planned gateway interface.
- [Fleet console concept](assets/fleet-console-concept.png): sample account, devices and message activity.
- [Two-location concept](assets/two-location-concept.png): sample routing and database-authority view.

These are design references with sample data, not Android hardware captures. When adding screenshots, remove personal numbers, email addresses, device identifiers, and tokens.
