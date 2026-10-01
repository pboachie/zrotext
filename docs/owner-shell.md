# Owner console shell

The owner pages use the dark-green canvas, lime accent, typography and existing
SVG mark from [the design system](DESIGN.md). The fleet page opens with approved
devices and message activity, followed by the existing security, pairing and
administration controls. Connection details and security links target the actual
sections without changing their forms or identifiers.

The desktop navigation rail becomes a wrapping two-column navigation above the
content on compact screens. Each page identifies its current destination. A skip
link moves keyboard focus directly to the main content. Controls retain visible
focus, text can grow to 200%, and reduced-motion preferences are respected.

Owner destinations are revealed only after the session endpoint confirms an
owner role. Observer sessions receive the read-only observer destination instead.
This navigation is presentation only: server authorization remains authoritative.
The billing link targets `/billing` and appears only when the existing billing
status endpoint reports test mode. It explicitly identifies that mode; disabled
or unavailable billing is not advertised. Navigation stores no credentials and
generation fences prevent delayed responses from restoring links after sign-out.

The fleet-console concept is a visual reference, not a source of synthetic live
metrics. Its marketing header and sample fleet metrics are intentionally omitted
from authenticated pages. Current controls and truthful empty/error states remain
visible; device-card and activity refinements can build on this shared shell.

`web/owner/browser/shell.test.js` renders the real HTML, CSS and controllers in
Chromium with synthetic, intercepted API responses. CI runs these tests alongside
the existing owner-controller tests. They cover compact and wide layouts, doubled
text, keyboard focus, real anchor navigation, role fences, disabled billing,
CSRF pairing requests, cancellation and credential-field cleanup. Screenshots
are optional temporary output via `ZT_OWNER_SCREENSHOTS=1`, in a freshly created
OS temporary directory; they are not public
repository artifacts. These tests do not establish carrier delivery or production
billing readiness.
