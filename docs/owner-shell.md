# Owner workspace

The owner workspace keeps the dark-green palette, typography and SVG mark from
[the design system](DESIGN.md). Its layout and recovery behavior follow the
[approved workspace contract](design/owner-workspace.md).

## Destinations

`/owner/devices` is the compact overview: authoritative writer summary, a bounded
phone list with a contextual inspector, recent outbound metadata and a permanent
Continue setup entry. The six primary destinations are Overview, Phones & lines
(`/owner/phones`), Activity, Integrations, Team and Settings. The fleet destination
keeps line tools beside phones. Account and security tools are nested in Settings;
their advanced URLs remain available. Add phone (`/owner/setup`) is the prominent
focused action. Billing is a capability-gated utility.

The main destinations reuse an embedded shell and existing control identifiers.
Inactive tasks are hidden from layout and accessibility navigation. Sign-in loads
the selected destination's data; security and integrations do not start fleet or
message polling. Navigation supports ordinary Back, Forward and bookmarks.
At compact widths navigation is an expandable Workspace navigation menu. A phone
inspector opens in an accessible modal with a Back to list action; the desktop
inspector remains beside the fleet list in a bounded, independently scrolling
panel, so selecting a phone does not push summary or activity down. Native modal focus returns to the
selected row. Controls retain visible focus, 44-pixel targets, 200-percent text
support and reduced-motion behavior.

Owner navigation appears only after the session endpoint confirms an owner role.
Observer sessions receive the observer destination. Server authorization remains
authoritative. The billing destination is exposed only for the existing TEST
billing capability; unavailable billing never becomes a live purchase claim.

## Add phone

The setup page presents Scan, Compare, Connect and Approve line as one focused
journey. The name is optional. QR credentials are transient; an explicit manual
alternative remains available. Read-only proof checks update the comparison view.
The owner checks the code and full fingerprint, then chooses Values match -
approve phone or These do not match. There is no comparison retyping or duplicate
confirmation checkbox. The same exact server proof values are submitted only by
the explicit approval action. The gateway app obtains its approved identity using
its distinct device-key binding protocol; the browser does not ask owners to copy
a device UUID or stream address.

`GET /v1/account/setup` supplies current account/session-bound progress. Protected
progress and fleet reads send the captured CSRF cookie proof in the required
header; session observations remain cookie-only. Missing or rotated proof clears
progress and blocks creation or approval until a fresh check succeeds. A public
pairing locator can appear in the setup URL; no ticket token or comparison value
is saved there. `new=1` expresses an intentional additional phone, but cannot
bypass an unresolved pairing or an unavailable/incomplete progress read. A
conservative `approval=checking` locator keeps a departed uncertain approval in
read-only recovery until the server confirms its result or the owner explicitly
cancels it. The original expired pairing is checked before retirement/replacement.

An observed phone connection advances to line review. Missing authenticator
setup, recovery-code saving and the browser approval key remain inside the wizard.
An authenticated current phone capability can select v2 and open its declaration
using server-projected deterministic line/opening locators. Existing pending
ceremonies resume instead of opening another. Unknown capability or a truncated
progress inventory cannot invent a new ceremony. Legacy mode keeps an explicit
supported setup selection. The exact SIM declaration is rebuilt before the owner
chooses Approve this phone and SIM. Current key/session checks remain authoritative;
changed session or phone connection repeats the affected declaration step.

Phone connected and Line approval recorded are separate server observations.
Neither establishes carrier service, dispatch readiness, delivery or recipient
consent. Real SMS tests remain separately deliberate.

## Verification

`node --test web/owner/*.test.js` exercises the actual controllers with synthetic
HTTP fixtures. `npm run test:rendered` in `web/owner` loads the real HTML, CSS and
scripts in Chromium. `browser/workspace-setup.test.js` binds authenticated
navigation, comparison, unknown approval/reload, session replacement, inline
security, line signing/reload and hosted return behavior to the shared requirement
IDs. Existing fleet, summary and activity tests preserve historical/unknown
semantics and keyboard focus.

Optional `ZT_OWNER_SCREENSHOTS=1` captures synthetic review images in a fresh OS
temporary directory. Screenshots and fixture passes do not prove a deployed
service, payment-provider acceptance, a physical phone or carrier delivery.
