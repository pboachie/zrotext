# Customer-local exact template authoring

`sdk/typescript/src/owner-template-authoring.ts` composes the existing bounded
template contract, preview, maintained encrypted-template HPKE sealing and
dormant owner persistence client. It is an explicitly enabled SDK controller,
without a mounted page, relay plaintext, scheduling or sending authority.

The host supplies the same explicit authenticated selected-owner inputs as
`OwnerEncryptedTemplateClient`, plus `readDraftState()` and
`consumeDraftReview()`. The constructor creates and exclusively owns its
persistence client. Do not share that lifetime with another authoring or
opening controller. `readDraftState()` observes a positive draft revision,
owner/presentation epoch and current selected custody liveness. These are
trusted customer-host observations, not public flags that grant permission.
The independently current binding, owner session, consent, active phase, CSRF
and opaque SDK-verified manifest still govern every operation.

`prepare({requestId,expectedRevision,scope,template,values,epoch,draftRevision})`
acquires operation ownership before inspecting caller-controlled input.
It refuses accessors and captures scope bytes, draft strings and plain bounded
substitution data before awaiting anything. The existing canonical contract
and bounded SMS composition estimate reject malformed placeholders, missing
values, Unicode errors and more than six parts. Actual selected Android
subscription segmentation remains a separate pre-dispatch check.

The host consumes an explicit local review containing the copied template,
substitutions, rendered preview, estimate, selected scope and revision.
Only the boolean `true` accepts. Review receives separate scope byte copies
and frozen copied values; mutating caller input or review metadata cannot
change the content subsequently sealed. Declining prepares no ciphertext
persistence ticket and sends no POST. This is a local authoring decision,
not message dispatch approval or a grant to an agent.

After review, the controller checks currentness again, uses the existing
`sealEncryptedTemplate` implementation, rechecks, invokes the real
private-branded persistence client's `prepareSave`, and rechecks before
returning its opaque ticket. The original ciphertext metadata review remains
mandatory. No private key is needed or exported for sealing to the verified
selected reader. The controller does not alter the crypto implementation.

There is one absolute monotonic budget of at most ten seconds, including
currentness reads, manifest verification, plaintext review, sealing and child
preparation. Authenticated validity, manifest/reader/active phone-key expiry
and template expiry can only shorten it. A persistent lifetime timer also
closes the owned client when that original budget expires after a ticket
returns. Child preparation cannot restart the budget. Every awaited result
is fenced against closure and deadline; the full selected binding, draft
revision/epoch/custody, CSRF, branded manifest/root/generation/version/digest
and authenticated monotonic time are checked again around the composition.

The caller may explicitly invoke `authoring.client.commit(ticket)` later
within that lifetime. Preparation never commits, retries, schedules or sends.
Only one prepared draft is allowed per controller. An unresolved POST retains
the existing client's safe pending identity; authoring closure never converts
it to acknowledged or destroys that metadata. It does close retry authority
and the client's owned request bytes. Crash recovery is not introduced.

The host must call `invalidate()` or `close()` on input replacement, hiding,
navigation, owner/session loss or custody replacement and clear any local
review it already owns. Both methods close the entire lifetime. New input
requires a new controller and explicit owner selection. Host callbacks remain
trusted integrations: timeout fencing cannot stop arbitrary callback work.
The controller clears only its owned envelope/canonical byte copies. JavaScript
strings, cryptographic-library temporaries, browser memory and callback-owned
copies cannot be securely erased; this is no secure-memory guarantee.

Existing SDK wildcard tests discover the authoring regressions. Existing
rendered owner wildcard tests execute the actual compiled module in Chromium
against a synthetic HTTPS owner-cookie/CSRF persistence host. The actual HPKE
round trip checks that the reviewed copied content is what was sealed and
that only a later explicit commit transmits opaque ciphertext. That fixture
is not mounted Rust/PostgreSQL or full customer-application acceptance.
Source/synthetic results do not establish physical custody, carrier delivery,
supported application onboarding or availability of the full template roadmap.
