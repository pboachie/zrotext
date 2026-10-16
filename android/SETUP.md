# Android setup and recovery

The app implements the Android portion of the [owner workspace design](../docs/design/owner-workspace.md)
and [setup journey contract](../protocol/v1/setup-journey-contract.json).
Those contracts govern later UI changes as well as the initial implementation.
The app keeps the existing dark green palette and 48 dp minimum action targets.

## Navigation and setup

`UX-NAV-02`, `UX-LAYOUT-01`, `UX-A11Y-01`, `SETUP-ACCESS-01` and
`SETUP-CONNECT-01` apply to the visible Home, Activity and Setup navigation.
The header and primary navigation stay outside the scrollable task content.
Connection and Tools remain explicitly named advanced destinations. Navigation
never requests Android permissions, starts a service or authorizes messaging.
Activity displays actual connection observations; it does not invent a message
history when no authorized reader is connected.

Setup presents scan, comparison, SIM/access and connection as focused tasks.
SMS access and a SIM are not needed to pair. A SIM must be selected explicitly
before starting the current connection controls. Permission requests remain
purpose-specific, request only missing access, and retain the separate receiving
choice and its local-processing disclosure. SIM removal or permission loss uses
the existing continuity withdrawal path; another SIM is never silently chosen.

The guided **Start connection** starts the existing heartbeat-only session. Its
reboot-resume option begins unchecked and is not restored as presentation
state. Carrier testing, inbound pilots, content access, line approval and SMS
sending retain their separate controls and gates. Connection proof is not a
claim of carrier delivery or SMS readiness.

## Trusted service and hosted builds

`SETUP-TRUST-01`, `HOSTED-SELF-01` and `HOSTED-APP-01` require selecting the
canonical HTTPS service independently of the QR. Self-hosted users enter their
operator's origin once. A dedicated build may set
`-PzrotextHostedOrigin=https://gateway.example.test`; the default is blank.
The build and runtime both validate the configured origin. This build option
only removes service-address typing; it does not enable hosted availability.

The chosen public origin is retained. A QR from a different origin is refused
before any claim. One explicit, named confirmation sends the phone-key proof;
the owner still compares the entire code and fingerprint and approves on the
website. Manual pairing is an optional same-origin fallback. The Android app
has no account registration, card form or purchase-leading link.

## Authenticated resumption

`SETUP-BIND-01`, `SETUP-RESUME-01`, `SETUP-UNKNOWN-01` and `SETUP-FRESH-01`
require current authenticated observations. Before sending a pairing claim, the
app saves only the public canonical origin, original pairing UUID and expected
key fingerprint. It never saves the pairing token, comparison code, owner
credentials, line approval, permission consent or active binding authority.

On a visible foreground Setup screen, a distinct binding challenge proves
possession of the existing original signing key. A missing or different key is
refused before network access and is never replaced by recovery. The approved
device ID comes from the binding response; the stream URL is derived locally
from the independently trusted origin and `/v1/device-stream`. No response URL
can replace that origin. Exact response fields, UUIDs, fingerprint, domain,
nonce and a monotonic 60-second operation bound are checked. The shared server
transcript fixture is covered by the Android binding tests.

The only exception before a key was attached is a closed challenge-route
`409` object containing `pairing_expired` or `pairing_cancelled`. The server
limits it to an actual unclaimed, unapproved terminal ticket. It permits an
explicit replacement of that attempt and carries no device identity or
approval. Missing rows, mismatched claimed keys, `404`, extra fields and
malformed errors remain unknown and retain the saved locator.

Leaving Setup or backgrounding invalidates the current binding observation.
Returning rechecks it before the guided start can be used. Late responses from
an old screen/operation are discarded. Status failures preserve the locator
and show recovery instructions. Automatic failure checks stop after six
attempts; **Check saved pairing** explicitly starts another bounded check.
Neither status checks nor restored navigation replay claim/proof, owner
approval, permission grants, connection starts or radio actions.

| Observation | Next task |
|---|---|
| Verified proof, approval pending | Show the exact comparison values and wait for owner approval |
| Current approved mapping | Continue to the selected SIM/access and explicit connection start |
| Expired or cancelled ticket | Explicitly replace only the pairing through the dashboard |
| Proof not completed or rejected | Retire the old ticket on the dashboard and explicitly replace it |
| Existing key unavailable or replaced | Explain old-phone revocation and new pairing; never silently create a key |
| Status unavailable | Retain progress, offer status check and a content-free support reference |
| Legacy unknown marker without locator | Recover the original public ticket ID with the existing key; no new claim |

Tests distinguish public UI progress from key possession, service start,
Android permissions, physical SIM continuity, line approval and carrier
acceptance. Robolectric/native rendering does not establish physical-device,
provider, deployment or real-SMS acceptance.
