# Design preview verification

Verified locally on 2026-09-22. These results cover the sample-data design prototype, not an implemented gateway or native Android application.

## Browser checks

| Area | Observed result |
|---|---|
| Landing and pricing | Correct ZROtext wordmark; Android interface shown on the phone; proposed prices and preview status visible |
| Navigation | Overview, fleet console, Android concept, pricing, self-hosting direction and topology screens open |
| Sample message | Queue increased from 4 to 5 and a new queued row appeared; confirmation explicitly says no SMS was sent |
| Message filters | Inbound filter shows the inbound sample; All restores the list |
| Device controls | Backup device shows offline recovery guidance; desk device pauses and resumes |
| Android concept | Gateway pause/resume updates its state and button text |
| Two-location topology | Healthy traffic split, Site A loss, writer-site loss and network partition each display their designed routing/recovery state |
| Single-location failure | Loss of its only site pauses service |
| Narrow layout | Landing and console checked in a 390px-wide browser iframe; document width equals viewport width, with no page-level horizontal overflow. The message table retains its own horizontal scrolling |
| Browser diagnostics | No warning/error entries returned for the final landing preview |

A narrow-layout check found a grid minimum-width issue in the fleet console. The layout now allows the main grid children to shrink, constrains the table container, and wraps statistics and panel headers appropriately.

## Saved captures

Screenshots live in the separate private `zrotext-ops` working folder under `marketing/preview/screenshots/`:

- `landing-desktop.png` and `landing-full.png`
- `fleet-console.png`
- `android-concept.png`
- `two-location-topology.png`
- `landing-mobile.png` and `fleet-mobile.png` — browser captures of the 390px responsive frame, including its surrounding canvas; not native-phone screenshots

The selected hero asset, `marketing/preview/assets/android-app-phone.png`, is a browser-rendered phone mockup of the Android concept. The earlier generated relay illustration is retained only as unused design exploration. All selected product screenshots and branding depict the ZROtext design concept.

## Static checks and limits

Both preview JavaScript files pass Node syntax checks. Relative Markdown links in the public planning package resolve. Final text scans of both working folders found no retained operator-specific customer threshold or private infrastructure path. The public gateway build is specified to remain independent of private marketing source.

This was a visual and interaction review, not a comprehensive accessibility audit, cross-browser certification, performance benchmark, cryptographic review, or SMS delivery test. All device names, message counts and connection states in the preview are sample data. Implementation and hardware evidence must be recorded separately in [implementation-status.md](implementation-status.md).
