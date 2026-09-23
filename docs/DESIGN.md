# ZROtext visual direction

## Brand

Display name: **ZROtext**, pronounced “zero text.” Wordmark: heavier `ZRO`, regular `text`, no separating underscore. Domain, repository, CLI and package identifiers remain lowercase `zrotext`. Tagline: **Your phone. Your number. Your SMS API.** Secondary message: **Run it yourself, or let us keep it running.** The slashed-Z mark is a simple original SVG built as an editable UI asset. It is a proposed identity, not a trademark clearance.

Keep the supplied plan's phosphor/terminal influence through dark green surfaces, monospace labels, connection states and lime accents. Use contemporary readable typography for prose and product controls. No CRT flicker, boot delay, scanline overlay on text, or sound on send. Avoid implying that retro visuals provide security.

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

Production font choice may use a self-hosted licensed family, with license files and measured performance. Never put essential status meaning in color alone. Buttons and inputs require keyboard focus, accessible names, adequate tap area, and reduced-motion behavior. Sample text sizes in a high-density mock must be revisited during production accessibility testing.

## Screens and behavior

| Screen | Concept supplied | Production requirements |
|---|---|---|
| Landing | Hero art, proposition, how it works, privacy boundary, proposed pricing | Real signup/self-host/docs URLs; no unearned trust badges |
| Fleet console | Sample metrics, device picker, offline details, pause/resume, message filters, simulated queue | Real events, empty onboarding state, low-power/permission/SIM diagnostics, per-device timeline |
| Android gateway | Phone-shaped browser concept with pause/resume | Compose UI, real permissions/service notification, pair/revoke and recovery states |
| Two-location topology | Interactive failure/routing sketch | Internal architecture tool; not a guarantee of deployed HA |
| Self-host direction | Honest pre-implementation guide | Working Compose, verified versions, backup and upgrade documentation |

Additional production screens: account login/MFA, recovery kit confirmation, pairing compare-code, key creation (one-time token reveal; locally generated crypto private keys), message detail timeline, local vault unlock, webhook delivery history/replay, usage/reset times, Stripe portal handoff, account export/delete and support. Document loading/empty/error/stale states for each. Never represent offline or unknown as delivered.

Sealed dashboard rules: fetch metadata and ciphertext; decrypt locally; render messages as plain text; never send decrypted content through HTMX forms or analytics; server search only metadata. Keep a clear vault-locked state, local-search limit, and explicit export sensitivity prompt.

## Deliverable assets

Application design requirements are documented here; marketing prototypes are maintained separately.

- `marketing/preview/assets/mark.svg`: original editable UI logo mark.
- `marketing/preview/assets/android-app-phone.png`: browser-rendered phone artwork using the actual Android concept UI and ZROtext wordmark. This is the selected hero.
- Use an Android app screen on the phone graphic rather than an abstract relay illustration.
- `marketing/preview/index.html`, `style.css`, `app.js`: interactive visual reference with sample data and no dependencies.
- `marketing/preview/architecture.html`: interactive two-location concept and failure behavior.
- `marketing/preview/screenshots/`: browser captures of the locally running reference. These are not Android hardware screenshots or production evidence.

Actual implementation screenshots at M5: public landing desktop/mobile; onboarding with a consented test phone; fleet healthy/offline; successful submitted and unknown timelines; real received test reply; masked API-key creation; webhook success/failure; quota limit; billing test mode; recovery warning; Android connected/paused/permission-error; dual-site origin drain with evidence. Remove personal numbers, email addresses, device identifiers, tokens and hidden overlays before publishing.

## Copy discipline

Do say: “Open-source Android SMS gateway,” “Bring your own phone and SIM,” “No automatic overage charges,” and “Submitted is different from delivered.” Use “planned” until built. Exact sealed-content claims wait for review.

Do not say: “zero-cost SMS,” “unlimited sends,” “guaranteed delivery,” “end-to-end encrypted SMS,” “audited” before review, “no third parties,” or “carrier restrictions solved.” No fake user counts, audit badges, reviews, graphs or uptime percentages.
