# Text receptionist simulation

Open [the interactive demo](../web/owner/receptionist-demo.html) in a browser from a local static server:

```sh
python -m http.server 8088 --bind localhost
```

Visit `http://localhost:8088/web/owner/receptionist-demo.html`. This is a standalone development example, not a route in the application server.

## What to try

Choose a service inquiry, wedding RSVP, or personal assistant request. Review the captured details, edit the scripted reply, approve that exact draft, and queue a simulated message. Editing a draft invalidates approval. Advance phone submission and the delivery receipt separately; a missing receipt remains unknown and never automatically resends.

Try an opt-out or handoff before submission to cancel the queued reply. After submission, an opt-out blocks future replies but cannot recall a message. A late receipt may still arrive. Start again or switch scenarios to discard the current state.

The example uses fictional participants and scripted drafts. It makes no network requests, uses no analytics or browser storage, and sends no SMS. Its content security policy blocks connections and form submission. Use synthetic text only; page state disappears on refresh.

## Implementation boundary

This example validates an interaction design. It does not provide an AI agent, a general sending endpoint, calendar integration, persistent contacts, RSVP storage, scheduled jobs, or consent evidence. It is not a bulk invitation sender. Submission and receipt buttons are synthetic events, not phone or carrier evidence.

Turning this into a production workflow requires:

- Verified line activation and general-send readiness, including carrier/device evidence and recipient suppression.
- Durable intake and conversation storage with scoped access and explicit retention.
- An AI adapter with bounded tools, provider permissions, and approval tied to the exact recipient, draft, and action.
- Durable job scheduling, idempotency, pacing, cancellation, and human handoff.
- Purpose-specific consent records and opt-out handling before any invitations or follow-ups.

The current runtime limits remain documented in [SMS compliance](SMS-COMPLIANCE.md) and the [roadmap](ROADMAP.md). A working simulation does not change a capability's release stage.

## Verification

`node --test web/owner/*.test.js` includes the simulation tests through the existing owner UI test discovery. Tests cover approval invalidation, duplicate queue actions, cancellation, human handoff, late receipts, unknown outcomes, scenario reset, and safe text rendering.
