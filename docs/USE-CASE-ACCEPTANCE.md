# Use-case acceptance evidence

This page defines what evidence closes a customer application journey in [USE-CASES.md](USE-CASES.md) and the [application catalog](https://github.com/pboachie/zrotext/issues/759). Each application's behavioral acceptance criteria stay in USE-CASES.md; this page states the composed capabilities, the recorded evidence a journey needs before its issue closes, and what evidence never claims. It supports issue #759 and does not itself advance any roadmap stage.

## Shared evidence rules

- A journey closes only through a merged pull request that states `Fixes #NNN` for its child issue, with the evidence below linked from the pull request or a follow-up note in the repository. Synthetic recipes, closed shared-service issues and generated documents alone do not close a journey.
- Every journey records, at minimum: the exact commit or release it ran on, the harness used, and the observed outcome for each criterion. Evidence lives in the repository or its linked CI runs, not on private disks.
- **Valid harnesses** are the repository's existing repeatable ones: the conversation simulator contracts job, the isolated conversation emulator job, the owner browser job, the sealed cross-client tests, and guided connector verification. A new journey may add a harness if it lands in CI in the same pull request.
- **No carrier or physical-device claim.** Emulator and simulator runs never prove carrier delivery, RCS behavior, or a supported device. Physical evidence follows the device compatibility process and is tracked separately.
- **No authority shortcuts.** A delivery receipt, silence, a phone number match, or a model interpretation is never acceptance, consent, RSVP or task completion. Every journey reuses the shared consent, suppression, owner-session and exact-action approval checks; none may fabricate routine, conversation, calendar or provider authority.
- Journeys that allocate a bounded resource (a slot, a shift, an item, an assignment) compose the shared single-opening capacity foundation (#772): separately typed opening and allocation identities, single-winner capacity under concurrency, replay returning the committed result, pending reservations held until owner confirmation or expiry, and authority re-checked before commit.

## First

### Text receptionist

Composes [contacts and conversations](ROADMAP.md#cap-contacts), [templates and scheduling](ROADMAP.md#cap-scheduling), [approvals and reply tracking](ROADMAP.md#cap-approvals) and the [customer-controlled assistant](ROADMAP.md#cap-assistant).

Evidence required:

- An owner-browser recorded journey: inquiry arrival, intake answers, an approved response, one owner edit invalidating a prior approval, and one scheduled follow-up.
- A conversation-simulator recipe covering duplicate inbound events and opt-out mid-journey, showing no duplicate reply and stopped automation.
- A replayed submit showing no second send, from the simulator or sealed cross-client vectors.

### Personal AI by SMS

Composes the assistant, contacts and consent, and sealed conversation capture.

Evidence required:

- A simulator recipe where a note flows to an owner-approved routine, one sensitive action waits for authenticated approval, and a reminder expires unused after its deadline.
- A sealed cross-client run demonstrating note and reply bodies are absent from relay logs and server storage for the journey's messages.
- An unauthenticated-claim probe: an incoming number attempting permission change or cross-conversation disclosure is refused and recorded.

### Agent task notifications and replies

Composes the [MCP tools](ROADMAP.md#cap-mcp), [agent adapters](ROADMAP.md#cap-agenttools), [guided setup](ROADMAP.md#cap-agentsetup) and workflow services.

Evidence required:

- A guided connector verification run showing setup preserves an existing client configuration and ends with authenticated readiness for the same context.
- One MCP and one SDK notification/reply exchange sharing one permission set, with honest delivery states surfaced in both.
- A replayed and an ambiguous submission producing no duplicate message, from the simulator vectors.

## Next

### Repair and project updates

Composes templates and scheduling, approvals, and reply correlation.

Evidence required:

- A simulator recipe pairing an exact job and request version with an approval, where a generic reply cannot approve unrelated work.
- A changed-work case invalidating a pending request, and a replayed status event sending no duplicate update.
- An unanswered-request case landing in the owner's exceptions view, with silence recorded as no approval.

### Cancellation-slot recovery

Composes the shared single-opening capacity (#772), scheduling and approvals.

Evidence required:

- A concurrency proof for the last capacity unit: parallel accepts produce exactly one winner in a durable store; the loser sees the committed result on replay.
- An expiry proof: an offer past its deadline cannot claim or reopen capacity, including when the phone was offline at expiry.
- An owner-cancellation proof: cancelled openings release pending reservations and stop unsent invitations.

### Wedding and event concierge

Composes contacts, templates and scheduling.

Evidence required:

- A multi-recipient simulator run where each message is individual and guest numbers are not disclosed to one another.
- A review case: a duplicate contact and an ambiguous name reply held for owner review before guest-count changes.
- An RSVP/opt-out interaction cancelling the relevant unsent reminders, with batch progress reporting queued, submitted, delivered and unknown separately.

### Volunteer and shift coordination

Composes the shared single-opening capacity (#772), contacts and suppression.

Evidence required:

- A concurrency proof: replies cannot exceed opening capacity and one response cannot claim two openings.
- A late-reply proof: expired or cancelled openings are refused atomically.
- A withdrawal proof: participant withdrawal plus suppression removes the participant from further reminders and updates the assignment state.

## Later

### Household coordinator

Composes contacts, scheduling and conversation isolation.

Evidence required:

- A cross-member probe: one member cannot read another private conversation or change owner settings by SMS.
- A recurring-reminder recipe honoring timezone change, expiry, completion and withdrawal in one recorded run.
- An acknowledgment recorded from an authenticated reply, with a delivery receipt explicitly not counted as completion.

### Community lending desk

Composes the shared single-opening capacity (#772) for bounded reservations, contacts and scheduling.

Evidence required:

- An overlap proof: concurrent requests cannot reserve the same item for overlapping periods; the second requester sees a refusal, not a silent failure.
- An availability-inquiry proof: questions never create reservations.
- A lifecycle proof: cancellation, opt-out or confirmed return removes the relevant scheduled messages.

### Operational acknowledgment

Composes the shared single-opening capacity (#772) for single-assignee acknowledgment, contacts and templates.

Evidence required:

- A duplicate-event proof: repeated issue events create one request and one assignment.
- A stale-reply proof: replies after closure cannot reopen the issue or reassign it.
- An acknowledgment recorded only from an authenticated reply, with the workflow documented as routine coordination and no emergency-delivery guarantee.

## Closure checklist (per child issue)

1. The journey's USE-CASES.md criteria are demonstrated by recorded evidence from a valid harness, at a named commit.
2. The composed capabilities exist at Build or later on the roadmap, or the pull request advances them together with the journey.
3. The pull request states `Fixes #NNN`, passes review, and merges green under the standing process.
4. USE-CASES.md availability for the application is updated in the same pull request or an immediate follow-up.
