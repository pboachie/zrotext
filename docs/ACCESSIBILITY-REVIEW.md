# Owner web pages accessibility review

This is the first slice of the roadmap item "Accessibility review of owner pages and the Android app" (see `docs/ROADMAP.md`). It covers the owner web pages only; the Android app review remains open.

## Scope and method

Reviewed every page under `web/owner/` at commit `9310d8b`, together with the CSS and JavaScript each page loads:

| Page | Assets reviewed |
|---|---|
| `web/owner/devices.html` | `devices.css`, `devices.js` |
| `web/owner/account.html` | `devices.css`, `account.js` |
| `web/owner/sms-lines.html` | `devices.css`, `sms-line-signing.js`, `sms-lines.js` |
| `web/owner/receptionist-demo.html` | `receptionist-demo.css`, `receptionist-demo.js` |

This was a static review of those files against a WCAG 2.1 AA checklist: document language, page titles, heading structure, label association, focus indicators, keyboard operability, accessible names, image alternatives, contrast, `aria-*` usage, table headers, status and error messaging, meta viewport, reduced-motion handling, and touch target sizes. Contrast ratios were computed from the color values in the two stylesheets using the WCAG 2.1 relative-luminance formula; the computed values are cited below. No browser, screen reader, or automated-tool session was run, so findings are limited to what the source files show.

## Overall verdict

The pages are in good shape for hand-authored HTML. All text contrast pairs measured pass AA with wide margins, every form control has a real `<label>` (including controls built dynamically in JavaScript), all interactivity uses native links, buttons, inputs, selects, `details` and form submits, so everything is keyboard operable by construction, and status and error text is consistently routed through `role="status" aria-live="polite"` regions. One AA failure was found in the receptionist demo's non-text contrast, plus a handful of minor and advisory items. No blockers were found.

## Checklist summary by page

| Check | devices | account | sms-lines | receptionist-demo |
|---|---|---|---|---|
| `html lang` | Pass (`en`) | Pass | Pass | Pass |
| Descriptive `<title>` | Pass | Pass | Pass | Pass |
| Single `h1`, ordered headings | Pass | Pass | Pass | Pass |
| Labels associated with controls | Pass | Pass | Pass | Pass |
| Visible focus indicator | Pass | Pass | Pass | Pass |
| Keyboard operability | Pass | Pass | Pass | Pass |
| Accessible names for links/buttons | Pass | Pass | Minor (A4) | Pass |
| Image `alt` text | N/A (no images) | N/A | N/A | N/A |
| Text contrast (1.4.3) | Pass | Pass | Pass | Pass |
| Non-text contrast (1.4.11) | Pass (thin margin, see A6) | Pass | Pass | Fail (M1) |
| `aria-*` usage | Minor (A2) | Pass | Pass | Pass |
| Table headers | N/A (no tables; `dl`/`ul`/`ol` used) | N/A | N/A | N/A |
| Status/error messaging announced | Pass (A2, A5 caveats) | Pass | Pass | Pass |
| Meta viewport | Pass | Pass | Pass | Pass |
| Reduced motion | Pass (no motion defined) | Pass | Pass | Pass |
| Touch target size | Pass (checkbox caveat, A5) | Pass | Pass | Pass |

## Findings

Severity definitions used here: a blocker prevents users with disabilities from completing a task; a major fails a WCAG 2.1 AA success criterion; a minor is an advisory improvement or a robustness concern.

### Blockers

None found.

### Major

**M1. Secondary control boundaries in the demo fall below the 3:1 non-text minimum.**

- Files: `web/owner/receptionist-demo.css` lines 28 to 29 (border `#465541`, button fill `#161e17`, panel fill `#111712`), line 31 (hover border).
- Criterion: 1.4.11 Non-text Contrast (AA).
- What fails: every non-primary `button`, `select` and `textarea` on `receptionist-demo.html` is drawn as a `#161e17` fill on a `#111712` panel with a `#465541` border. Computed ratios: border against the panel 2.28:1, border against the control's own fill 2.14:1, fill against the panel 1.07:1. None reaches 3:1, so the control boundary is effectively invisible at rest. The only passing boundary state is hover (`border-color: #b6f36a`, 13.0:1), which keyboard and touch users never receive; the `:focus-visible` outline (`#edbe70`, 10.56:1) shows where focus is but not the control's extent beforehand. The primary button (`#0b0f0c` on `#b6f36a`, 14.72:1) is not affected.
- Remediation: give the at-rest border a color that reaches 3:1 against both `#111712` and `#161e17`. The palette already contains passing candidates, for example the accent `#b6f36a` (13.0:1 against the button fill) or the caution tone `#edbe70` (9.9:1 against the button fill), which also match the `docs/DESIGN.md` token table.

### Minor

**A1. Focus is dropped to `body` when the devices page switches views.**

- Files: `web/owner/devices.js` lines 149 to 153 (`showSignedIn`), used at line 1004 from the login handler and line 1024 from the MFA handler; `clearOwnerState` (lines 234 to 283) called on success from the change-password handler at line 1112.
- Criterion: 2.4.3 Focus Order (AA), applied to focus continuity.
- What fails: after a successful sign-in the focused submit button sits inside `#sign-in`, which `showSignedIn(true)` then hides, and after a successful password change the focused submit sits inside `#owner-content`, which `clearOwnerState()` hides. In both flows focus falls back to the `body` element, so keyboard and screen reader users lose their place and must tab from the top of the document. The live region does announce "Signed in." and "Password changed...", so the outcome is heard, but the reading position is still lost. The MFA step does this correctly by calling `byId("mfa-code").focus()` at line 1002.
- Remediation: after revealing `#owner-content`, move focus to the "Devices" heading (`#devices-title` or the `h1`) with `tabindex="-1"` plus `.focus()`; after `clearOwnerState()` from the change-password flow, focus the sign-in section heading.

**A2. The device-capacity live region is filled while hidden, then revealed.**

- Files: `web/owner/devices.js` lines 573 to 596 (`loadDeviceCapacity`); `web/owner/devices.html` line 138 (`#device-cap-prompt` starts `hidden`).
- Criterion: 4.1.3 Status Messages (AA), reliability risk.
- What fails: `#device-cap-prompt` is a `role="status"` region that ships with the `hidden` attribute. The script sets `prompt.textContent` while the element is still `display: none` and only then removes `hidden`. Live-region mutation announcements are unreliable when the change happens while the region is hidden; depending on the browser and assistive technology, the plan-limit warning may not be announced when it appears.
- Remediation: remove `hidden` first, then set the text, or keep the region permanently in the accessibility tree and swap text in a child node, as the other status regions on the page effectively do.

**A3. Disabled buttons lose nearly all affordance, and the cursor suggests activity that is not happening.**

- Files: `web/owner/devices.css` line 19 (`button:disabled { cursor: wait; opacity: .6; }`); `web/owner/receptionist-demo.css` line 33 (`opacity: .42`).
- Criterion: none; inactive controls are exempt from 1.4.3. Recorded as an advisory, not a WCAG failure.
- What fails: at `opacity: .42` the demo's disabled buttons render well under 3:1 and are easy to mistake for plain text. On the devices page `cursor: wait` on every disabled button implies a pending operation even for a permanently disabled "Load more" with nothing left to load.
- Remediation: keep disabled buttons near their normal contrast and distinguish them by a state cue other than transparency; use `cursor: wait` only while a request the button triggered is actually running, and `cursor: default` otherwise.

**A4. Repeated "Use this line" buttons share one accessible name.**

- File: `web/owner/sms-lines.js` lines 185 to 187 (button text `"Use this line"` inside each `#line-list` item).
- Criterion: 4.1.2 Name, Role, Value (AA), advisory; a name exists, so this is not a strict failure.
- What fails: every line row renders an identical "Use this line" button. The distinguishing information (line ID prefix and state) is in an adjacent span, so screen reader users stepping through the forms list hear the same name repeatedly with no way to tell the rows apart without backtracking. `devices.js` already solves this pattern correctly with `setAttribute("aria-label", ...)` for its repeated Revoke buttons (lines 549 and 652).
- Remediation: mirror the devices pattern, for example `use.setAttribute("aria-label", "Use line ${line.line_id.slice(0, 8)}…")`.

**A5. Validation feedback is generic and not linked to the field it concerns.**

- Files: `web/owner/devices.js` lines 37 to 45 (`statusDescriptions`), used for example at line 1220 ("Enter a valid message UUID."); `web/owner/account.js` lines 47 to 54; `web/owner/sms-lines.js` lines 33 to 40.
- Criterion: 3.3.1 Error Identification (AA), minimum met but weak; advisory.
- What fails: every error is announced as text through a polite status region, so 3.3.1 is met, but most messages are generic ("Check the entered values and try again.") and appear in a status paragraph that may sit far from the offending control, with no `aria-describedby` link between field and message. On the long devices page the message can be several sections away from the input.
- Remediation: name the failing field in the message and add `aria-describedby` pointing from the input to its status region (or move each message next to its form).

**A6. Checkbox rows are the only controls under 44 pixels.**

- Files: `web/owner/devices.html` line 129 (pairing confirmation) and lines 189 to 190 (API key scopes); `web/owner/devices.css` lines 28 to 29.
- Criterion: 2.5.5 Target Size (AAA in WCAG 2.1; the 24-pixel minimum of 2.5.8 in WCAG 2.2 is met). Advisory for this AA review.
- What fails: the checkbox input itself is browser-default size (about 13 by 13 CSS pixels). The wrapping `label.check` makes the whole row a toggle target, which rescues it to roughly 24 pixels of effective height, but it remains the smallest target on an otherwise generous page: text inputs and buttons measure about 45 pixels (`padding: .65rem`/`.6rem` at a 16-px base font).
- Remediation: add vertical padding or `min-height` to `.check` so the row meets the same ~44-pixel target as the other controls.

**A7. Light-theme input borders pass 3:1 with almost no margin.**

- File: `web/owner/devices.css` line 16 (border `#8198a2` on `#fff`).
- Criterion: 1.4.11 Non-text Contrast (AA). Currently a pass at 3.02:1.
- What fails: nothing today, but the computed ratio is 3.02:1 against the 3:1 minimum, so any background or border tweak can silently break it. The dark-theme equivalent (`#879ea7` on `#14232c`, 5.72:1) is comfortable.
- Remediation: darken the light-theme input border a step (the adjacent `button` border `#154b5d` passes at 9.56:1 for reference) so the pass does not depend on rounding.

### Passes worth keeping

These were verified and should be preserved in future changes:

- Every form control, including the decision select built per row in `devices.js` (`appendReviewDecision`, with `label.htmlFor` set), has an associated label; the checkboxes use wrapping `label.check` elements.
- Sensible `autocomplete` tokens throughout (`username`, `current-password`, `new-password`, `one-time-code`, `email`, `tel`), which also satisfies 1.3.5 Identify Input Purpose.
- Focus indicators are explicit and thick on both themes: `outline: 3px solid #b56516` with offset (`devices.css` line 20; 4.34:1 on white, 3.41:1 on the dark section) and `outline: 3px solid #edbe70` (`receptionist-demo.css` line 34; 9.9:1 and above everywhere measured). `summary` is included in the focus rule.
- No click-only interactivity: all handlers attach to native elements (`submit`, `click` on buttons, `change`, `input`), and there are no `tabindex`, `title` or `placeholder` attributes anywhere in the four pages.
- Status meaning is never color-only: connection states, warnings (`message-uncertain` carries its own sentence) and "(not connected)" select suffixes are all text, matching the rule in `docs/DESIGN.md`.
- No `<img>` elements exist, so there is no alternative-text debt; the wordmark is a text link.
- No `transition`, `animation` or `@keyframes` appear in either stylesheet and no JavaScript moves elements over time, so `prefers-reduced-motion` has nothing to gate; recording this so a future animation addition remembers the design rule.
- One-time values (pairing token, API key, MFA secret, recovery codes) use `user-select: all` so a single click selects the whole value (`devices.css` line 27).
- `aria-labelledby` on every section and `aria-label="Synthetic conversation"` on the demo message list are correct; no suspicious or redundant `aria-*` was found.

## Prioritized remediation shortlist

1. Raise the at-rest border contrast of non-primary controls in `receptionist-demo.css` to at least 3:1 against `#111712` and `#161e17` (M1; the only AA failure).
2. Preserve focus across view switches in `devices.js`: focus the revealed section after sign-in and after the password-change sign-out (A1).
3. Set `#device-cap-prompt` text after revealing the region so the plan-limit warning is reliably announced (A2), and disambiguate the repeated "Use this line" buttons in `sms-lines.js` with the `aria-label` pattern already used for Revoke buttons (A4).
4. Tighten validation messaging and link it to fields with `aria-describedby` (A5).
5. Give `.check` rows a ~44-pixel target and darken the light-theme input border below 3:1 margin territory (A6, A7); reconsider `opacity`/`cursor: wait` on disabled buttons (A3).

A follow-up pass with a real screen reader and keyboard-only session over the sign-in, pairing, MFA and line-activation flows would confirm the announcement and focus behavior that a static review can only infer, and the Android app half of the roadmap item is still to be scheduled.
