# Use cases

ZROtext's proposed direction is **your number, connected to your business, your automations, and your AI**. The first experiences focus on local service operators and individuals who want to reach their own assistant by SMS. A dashboard and integrations should use the same messaging foundation.

**Every experience below is proposed and unavailable today.** The current gateway supports restricted synthetic or controlled tests. Neither a working template nor a connected phone establishes readiness for customer traffic. See the [roadmap](ROADMAP.md), [product implementation plan](PRODUCT-PLAN.md), and [current sending limits](SMS-COMPLIANCE.md).

Priority describes delivery order, not a release date. Capabilities are counted in the technical roadmap; these use cases are customer outcomes and do not add completed capabilities. All examples describe hypothetical users and synthetic workflows.

<!-- Generated regions come from docs/roadmap.json. Edit that file, then run `python3 scripts/roadmap.py`. -->

<!-- roadmap:usecases -->
| Priority | Experience | Example | Availability |
|---|---|---|---|
| First | [Text receptionist](USE-CASES.md#receptionist) | Gather job details by text, draft a reply, and ask the owner to approve a quote. | Proposed; unavailable |
| First | [Personal AI by SMS](USE-CASES.md#personalai) | Text your assistant a note or reminder; let approved routines communicate with selected contacts. | Proposed; unavailable |
| Next | [Repair and project updates](USE-CASES.md#repairs) | Send a repair update and request approval before extra work. | Proposed; unavailable |
| Next | [Cancellation-slot recovery](USE-CASES.md#waitlist) | Offer an open slot in sequence and stop when one booking is confirmed. | Proposed; unavailable |
| Next | [Wedding and event concierge](USE-CASES.md#events) | Send personalized invitations, collect RSVPs, and remind only unanswered guests. | Proposed; unavailable |
| Next | [Volunteer and shift coordination](USE-CASES.md#volunteers) | Fill an open shift by text and stop requests once it is covered. | Proposed; unavailable |
| Later | [Household coordinator](USE-CASES.md#household) | Coordinate pickups, errands and recurring responsibilities through opt-in reminders and replies. | Proposed; unavailable |
| Later | [Community lending desk](USE-CASES.md#lending) | Request equipment by text, confirm availability, and receive return reminders. | Proposed; unavailable |
| Later | [Operational acknowledgment](USE-CASES.md#acknowledgment) | Notify a small team about a maintenance issue and record who will handle it. | Proposed; unavailable |
<!-- /roadmap:usecases -->

## Shared expectations

- Start with one owner, a dedicated Android phone/SIM and small, paced contact lists. Supported capacity depends on measured device behavior and the permitted sending route; there is no advertised throughput yet.
- Recipients use ordinary SMS. A dashboard operator needs a browser, and an assistant needs an authorized connector. The recipient does not need to install ZROtext.
- Automatic messages must fit owner-approved routines, recipient permissions, timing and budgets. Human review handles commitments, unusual requests and ambiguous replies.
- Customer-controlled AI runs in an authorized customer process that can read selected content and pass it to the chosen model. Optional ZROtext-managed AI is a later, explicitly enabled content reader. The sealed relay boundary does not mean the chosen AI, carrier or recipient cannot read the message.
- A received SMS is conversation input, not authority to change permissions or access other conversations. Delivery receipts are not RSVPs, consent or task completion.
- Larger campaigns require a separately evaluated provider route. Phone-based workflows retain the existing suppression, expiry and unknown-outcome rules.

<!-- roadmap:cases -->
<a id="receptionist"></a>

## Text receptionist

**First · Proposed; unavailable**

**For:** Cleaners, tutors, repair shops and other local service operators.

Owners lose time collecting the same details and tracking unanswered inquiries while doing their main work.

**Example:** Gather job details by text, draft a reply, and ask the owner to approve a quote.

### Intended journey

1. The owner connects a dedicated line and configures service facts, intake questions, hours and escalation rules.
2. A customer texts an inquiry; approved intake questions collect the minimum details needed for a job summary.
3. The assistant answers approved FAQs and drafts a response; prices, bookings and commitments go to the owner.
4. The owner approves or edits the exact action, takes over the conversation, or schedules an allowed follow-up.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Customer-controlled AI assistant](ROADMAP.md#cap-assistant) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- A nontechnical owner completes inquiry, intake, approved response and follow-up from the dashboard.
- No unapproved quote or booking is sent; edits invalidate approval of the previous action.
- An opt-out or human takeover stops pending automation, and duplicate inbound events do not duplicate replies.

### Success signals to measure

- Setup completion and time to first completed inquiry.
- Owner interventions and time spent per resolved inquiry.

<a id="personalai"></a>

## Personal AI by SMS

**First · Proposed; unavailable**

**For:** Individuals who want to reach their chosen assistant through ordinary SMS.

Capturing a thought or delegating a small task should not require opening another app.

**Example:** Text your assistant a note or reminder; let approved routines communicate with selected contacts.

### Intended journey

1. The owner connects an assistant, pairs an owner channel, and chooses allowed contacts and routines in the authenticated dashboard.
2. The owner texts a note, question or reminder; the connector decrypts the selected conversation and uses the chosen AI.
3. The assistant answers the owner or proposes an action for another person; automatic sending stays within configured routines.
4. The owner reviews exceptions and can pause or revoke the connector.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Customer-controlled AI assistant](ROADMAP.md#cap-assistant) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Notes, owner replies and reminders work without exposing bodies to relay logs or storage.
- An incoming phone number alone cannot change permissions, disclose other conversations or approve sensitive actions.
- Messages outside approved routines wait for authenticated approval; reminders expire instead of arriving after their useful time.

### Success signals to measure

- Tasks completed by SMS without opening the dashboard.
- Corrections, unexpected messages and repeat use by the owner.

<a id="repairs"></a>

## Repair and project updates

**Next · Proposed; unavailable**

**For:** Repair shops, makers and small project-based businesses.

Customers need progress updates, and owners need a clear record of approval before additional work.

**Example:** Send a repair update and request approval before extra work.

### Intended journey

1. The owner records a job and selects update templates.
2. A job milestone triggers an approved status update to the customer.
3. Additional work creates an owner-approved request for the exact scope and amount.
4. A matching customer response is recorded; ambiguous replies or conflicting changes return to the owner.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Approval is tied to the correct job and request version; a generic reply cannot approve unrelated work.
- Replayed status events send no duplicate update, and changed work invalidates an earlier pending request.
- Unanswered requests appear in the exceptions inbox; silence never counts as approval.

### Success signals to measure

- Status inquiries avoided and time to customer response.
- Additional-work requests resolved without manual follow-up.

<a id="waitlist"></a>

## Cancellation-slot recovery

**Next · Proposed; unavailable**

**For:** Appointment-based local businesses with a small opt-in waiting list.

A cancelled appointment leaves unused time while several customers may want the same slot.

**Example:** Offer an open slot in sequence and stop when one booking is confirmed.

### Intended journey

1. The owner enters an available slot and eligible waiting contacts.
2. The workflow offers it to one contact with an expiry before moving to the next.
3. An acceptance reserves the slot for owner confirmation; later responses cannot allocate it again.
4. Confirmation closes outstanding offers and cancels remaining reminders.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Concurrent acceptances cannot allocate the same slot twice; expired offers cannot claim it.
- No external calendar booking is implied: the first version uses owner-entered availability and owner confirmation.
- The owner can cancel the offer, and an offline phone does not send expired invitations.

### Success signals to measure

- Cancelled slots filled and time to confirmation.
- Expired offers, conflicting replies and owner corrections.

<a id="events"></a>

## Wedding and event concierge

**Next · Proposed; unavailable**

**For:** Couples, community organizers and hosts of small events.

Hosts need to reach guests personally and follow up without repeatedly messaging people who already answered.

**Example:** Send personalized invitations, collect RSVPs, and remind only unanswered guests.

### Intended journey

1. The host imports or enters a guest list with permission records, reviews duplicate contacts and previews invitations.
2. The host approves a paced batch with event details, recipient timing and expiry.
3. Replies update the correct guest record; ambiguous answers go to the host.
4. Reminders target unanswered guests only, and the host exports the final RSVP list.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)
- [Data export and account deletion](ROADMAP.md#cap-export) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Each recipient receives an individual message without disclosure of other guest numbers.
- Duplicate contacts, household replies and ambiguous names are reviewed before changing guest counts.
- RSVPs and opt-outs cancel relevant unsent reminders; batch progress separates queued, submitted, delivered and unknown.

### Success signals to measure

- RSVP completion and host follow-up effort.
- Duplicate contacts resolved and unnecessary reminders prevented.

<a id="volunteers"></a>

## Volunteer and shift coordination

**Next · Proposed; unavailable**

**For:** Clubs, volunteer organizers and small teams.

Coordinators need to fill an opening without continuing to contact people after enough volunteers accept.

**Example:** Fill an open shift by text and stop requests once it is covered.

### Intended journey

1. The coordinator defines an opening, capacity, expiry and opt-in contact group.
2. An approved workflow sends paced requests and records replies.
3. The coordinator confirms volunteers within capacity; excess acceptances receive a reviewed response.
4. The workflow closes the opening and cancels remaining requests.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Concurrent replies cannot exceed the opening capacity or assign one response to two shifts.
- Expired or cancelled openings cannot be filled by late replies.
- Participants can withdraw; reminders honor suppression and the latest assignment.

### Success signals to measure

- Openings filled and coordinator messages per assignment.
- Overbooking prevented and withdrawals handled.

<a id="household"></a>

## Household coordinator

**Later · Proposed; unavailable**

**For:** Households coordinating routine errands and responsibilities.

Small recurring responsibilities are easy to forget or duplicate when coordination is scattered.

**Example:** Coordinate pickups, errands and recurring responsibilities through opt-in reminders and replies.

### Intended journey

1. An owner creates an opt-in household contact group and recurring reminders.
2. A member receives a task and replies to accept, decline or report completion.
3. The owner sees unanswered tasks and decides whether to reassign them.
4. Members can pause their reminders; completing a task cancels its pending follow-ups.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- One member cannot read another private conversation or change the owner settings by SMS.
- Recurring reminders respect timezone changes, expiry, completion and withdrawal.
- The workflow records acknowledgments without treating delivery receipts as task completion.

### Success signals to measure

- Tasks acknowledged and completed.
- Unwanted reminders and manual coordination effort.

<a id="lending"></a>

## Community lending desk

**Later · Proposed; unavailable**

**For:** Community groups sharing equipment or other reusable items.

Small lending programs need a simple way to accept requests and track availability and returns.

**Example:** Request equipment by text, confirm availability, and receive return reminders.

### Intended journey

1. The owner records items, availability and borrowing rules.
2. A member requests an item by text; the request enters the owner queue.
3. The owner approves a reservation and pickup details within available capacity.
4. Return reminders stop when the owner records the return.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Concurrent requests cannot reserve the same item for overlapping periods.
- Availability questions do not themselves create reservations.
- Cancellation, opt-out and confirmed return remove the relevant scheduled messages.

### Success signals to measure

- Completed loans and response time to requests.
- Reservation conflicts and overdue follow-up effort.

<a id="acknowledgment"></a>

## Operational acknowledgment

**Later · Proposed; unavailable**

**For:** Small teams coordinating routine maintenance and service issues.

An alert is useful only when someone accepts responsibility and others can see that response.

**Example:** Notify a small team about a maintenance issue and record who will handle it.

### Intended journey

1. A configured integration creates a routine issue with an expiry and eligible contacts.
2. An approved workflow notifies the group and collects acknowledgments.
3. The owner confirms responsibility, or a configured single-assignee rule records the first valid acceptance.
4. Closing the issue cancels remaining reminders and records the outcome.

### Required capabilities

- [Contacts, consent and conversations](ROADMAP.md#cap-contacts) (Planned)
- [Templates and scheduled follow-ups](ROADMAP.md#cap-scheduling) (Planned)
- [Approvals and reply tracking](ROADMAP.md#cap-approvals) (Planned)
- [Workflow connector and integrations](ROADMAP.md#cap-integrations) (Planned)

These also inherit their upstream roadmap dependencies and the [general sending gates](ROADMAP.md#path-to-general-sending).

### Acceptance criteria

- Duplicate issue events do not create duplicate requests or assignments.
- Delivery or silence is never recorded as acknowledgment; stale replies cannot reopen closed issues.
- The workflow is described as routine coordination, with no emergency-delivery guarantee.

### Success signals to measure

- Issues acknowledged and time to accepted responsibility.
- Unanswered issues, duplicate alerts and assignment corrections.
<!-- /roadmap:cases -->

## Choosing what to build next

Start with the text receptionist and personal assistant. Validate the shared contact, conversation, scheduling and approval capabilities before adding new templates. Record setup completion, completed tasks, owner effort, errors and repeat use from consenting pilots; the success signals above are measurements to collect, not claims of demonstrated demand.

Propose additions with an audience, a specific task, required capabilities and a testable completion condition. Keep customer identities, private transcripts and commercial research outside the public repository. See the [product plan](PRODUCT-PLAN.md#validation-and-release-evidence) for release evidence.
