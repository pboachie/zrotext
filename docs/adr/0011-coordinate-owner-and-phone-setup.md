# Coordinate owner and phone setup through current authority

Status: accepted design; implementation acceptance is separate.

## Context

The owner workspace combines unrelated tasks in a long document. The phone
requires repeated technical entry after enrollment. Reloads, expired login and
uncertain responses leave users to infer which actions succeeded. Adding hosted
registration and checkout to that structure would increase manual work and
could encourage duplicate approvals or subscriptions.

## Decision

Use the [owner workspace specification](../design/owner-workspace.md) and
[versioned setup journey contract](../../protocol/v1/setup-journey-contract.json)
as the common product contract. Provide real workspace destinations, contextual
phone details, visible Android primary navigation and one focused setup task.
Keep account/plan setup on the web and phone pairing/permissions on Android.

Derive resumable progress from current authenticated facts. Public locators may
help recover a ceremony, but a completed-step flag cannot grant authority. A
distinct existing-key-authenticated proof lets a phone discover its approved
binding. The independently selected service origin determines the stream host.

Owner comparison, permission disclosure, SIM selection, connection start and
applicable line/content decisions remain explicit. Reading status and changing
pages are side-effect free. An unknown mutation result is reconciled before
retry or replacement. A fresh login cannot inherit a session-bound line choice.

Capability-driven service availability and authoritative plan terms control
hosted actions. TEST fixtures never stand in for LIVE billing. Self-hosted
operation does not acquire a subscription dependency.

## Consequences

The UI may reuse existing controller IDs while separating destinations, but its
inactive tasks must not remain in the document's layout or accessibility order.
Shared requirement IDs and scenarios bind future UI changes to behavioral
browser/Android tests. Cross-platform acceptance still requires actual rendered
and authenticated runtime evidence; schema conformance alone is insufficient.

Some interruptions require a new decision rather than transparent continuation:
changed SIM, lost device key, replaced session and unknown provider outcomes.
The user repeats that affected decision, with the account and unrelated valid
progress retained. This decision neither enables dispatch nor authorizes live
service activation, external purchases or deployment.
