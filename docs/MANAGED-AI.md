# Optional managed AI: data-handling proposal

> [!IMPORTANT]
> **Proposal only.** Nothing on this page is implemented, and ZROtext has no
> managed AI service. It records the properties such a service must have
> before any runtime work starts, following the
> [product plan](PRODUCT-PLAN.md#managed-ai-and-larger-campaigns). No model
> provider, region, retention period, price or budget amount has been chosen;
> each is listed under [open decisions](#open-decisions).

The first assistant experience is **customer-controlled**: the customer's own
process decrypts selected content and calls the model it chooses
([use cases](USE-CASES.md)). A managed service would be a later option for
customers who want ZROtext to run that process. It is not a prerequisite for
anything else, and phone-based workflows must stay usable without it.

A managed service is a new **content reader**. Under the
[sealed-content design](SECURITY-DESIGN.md#claims-and-trust-boundaries), the
relay routes ciphertext and visible metadata and cannot read bodies without
client keys. A managed service changes that only for content an owner
explicitly grants to it, and a model provider becomes a further processor of
that content.

## Invariants

These hold whatever provider, pricing or retention periods are chosen later.

1. **Off by default, per account.** No account, line or conversation is
   readable by the managed service until an owner creates a grant.
2. **No plaintext fallback.** The sealed API never gains a path that sends
   plaintext to the relay because a managed service exists. The service reads
   content only as an authorized recipient of sealed content, with its own
   keys.
3. **Separate identity and keys.** The service has its own decryption and
   signing keys, separate from relay, device, owner and webhook keys. Losing
   or rotating them does not affect other readers.
4. **Scope is enforced by the relay and the service.** The grant's lines,
   conversations and purposes limit what the relay encrypts to the service
   and what the service will process. A service bug should not widen the
   scope silently.
5. **Budgets fail closed.** When a budget is exhausted, or cannot be checked,
   no provider call is made.
6. **Revocation stops future access. It does not recall past access.** The
   product must say so wherever a grant is created or revoked.
7. **Sending stays under existing controls.** Anything the service proposes to
   send goes through the same admission, suppression, idempotency and approval
   rules as any other client. An ambiguous radio attempt stays `unknown` and
   is never resent automatically.

## Grant

A grant is an account-scoped record that an owner creates, changes and
revokes. Proposed contents:

| Field | Purpose |
|---|---|
| Scope | Selected lines, conversations or contact groups, and the permitted purposes (for example draft replies only, or replies within an approved routine) |
| Reader identity | The service key set that receives sealed content for this grant |
| Provider route | Which approved provider configuration may process the content (see [provider access](#provider-access)) |
| Budget | The per-account limits in [budgets](#per-account-budgets) |
| Lifetime | Creation time, creator, optional expiry, and revocation time and actor |

Creating or widening a grant would require an owner session with a fresh
password and MFA confirmation, the same strength as other owner credential
changes. It would also write an append-only audit record. Narrowing or
revoking a grant must never require more than the owner's current session.

## Provider access

The model provider receives only what one task needs:

- the message text in scope, and the owner-authored instructions for that
  routine;
- no phone numbers, account IDs, device IDs or other metadata unless a task
  cannot work without it. Recipients are referred to by per-task
  pseudonyms;
- no content outside the grant, including other conversations on the same
  line.

Before a provider configuration can be offered, the maintainer must record,
for that configuration, how the provider:

- uses customer content, including whether it is used for training;
- retains prompts and outputs, and whether zero or reduced retention is
  available;
- handles deletion requests;
- discloses its sub-processors;
- chooses its processing regions.

These are evidence requirements, not claims about any provider. The public
repository documents which provider configurations the code supports. It does
not hold contracts, account details or credentials.

## Retention

The service is stateless per task wherever possible. Proposed rule for each
record category, with periods left open:

| Record | Proposed rule | Period |
|---|---|---|
| Decrypted content, prompts and provider responses in the service | Held in memory for the task only; never written to logs, traces, crash reports or queues in plaintext | None beyond the task |
| Drafts and proposals the service produces | Stored only as sealed content readable by the owner and the grant's reader | Open decision |
| Grant records | Kept while the grant is active, then with the account's audit history | Open decision |
| Access records (which grant, which conversation, when, task outcome, budget units) | Content-free metadata for owner review and abuse investigation | Open decision |
| Provider-side copies | Governed by the chosen provider configuration; the shortest available option | Set by the provider configuration |

Synthetic canary content must be absent from relay and service logs, database
rows outside sealed columns, and webhook envelopes. This is the content
boundary test in the [product plan](PRODUCT-PLAN.md#validation-and-release-evidence).

## Export

The owner export (`GET /v1/owner/export`) would add, for each grant: its
scope, lifetime and revocation, its access records, and the sealed drafts it
produced. The export contains ciphertext for sealed items, like other sealed
content. This is the "assistant access records" part of the
[export and deletion roadmap item](ROADMAP.md#cap-export).

## Account erasure

Account erasure would:

1. revoke every grant and destroy the service's key material for that
   account;
2. delete grant records, access records and sealed drafts with the rest of the
   account's data, subject to the same retention exceptions as other account
   records;
3. ask each provider configuration used by the account to delete retained
   copies, where the configuration supports it, and record the outcome as
   content-free metadata.

Erasure cannot recall content a provider has already processed. The erasure
confirmation must say so.

## Revocation

When an owner revokes a grant, or it expires:

- the relay stops encrypting new content to the grant's reader, and the
  service refuses new tasks for it. The target is effect within one admission
  check, with no cache that outlives it;
- a task that has not yet called the provider is cancelled;
- a task already waiting on the provider is allowed to finish. Its output is
  discarded unless the owner has already approved it, and the discard is
  recorded;
- key material specific to the grant is destroyed;
- the access records remain, so the owner can review what was read.

## Per-account budgets

Budgets bound cost and blast radius. Each would be checked when a task is
admitted, before any provider call, in the same way as the existing
per-account admission budgets for outbound messages:

- tasks per period, and provider units (for example tokens) per period;
- messages the service may propose for sending per period, in addition to
  normal sending limits;
- a hard ceiling that no setting can exceed.

When a budget is exhausted, tasks stop. The owner is notified, nothing retries
automatically, and nothing tops up automatically. A budget that cannot be
read counts as exhausted.

## Threats and failure cases

| Case | Expected behavior |
|---|---|
| Prompt injection in an inbound SMS ("ignore previous instructions", requests for other conversations) | The service can reach only the grant's scope. Actions still need admission and, where the routine requires it, owner approval. Inbound text is never treated as instructions. |
| Cross-account or cross-conversation disclosure | Every task is keyed to one account and one grant. Tests use synthetic canaries in adjacent conversations. |
| Revocation during a task | See [revocation](#revocation). No output is sent after revocation. |
| Budget exhausted or budget store unavailable | Fail closed; no provider call. |
| Provider outage or timeout | The task fails visibly. No automatic switch to another provider configuration unless the grant allows it. |
| Provider returns content for the wrong task | Output bound to the task identity; a mismatch is discarded and recorded. |
| Service key compromise | Rotate the service keys and re-grant. Exposure is limited to content granted since the last rotation. |
| Plaintext in logs or crash reports | Blocked by design and tested with canaries. |
| Loops (the service replying to its own messages, or two routines replying to each other) | Per-conversation reply limits and the proposal-send budget. |

## Release gates

Before the roadmap item is marked done or any managed service is offered:

- every [open decision](#open-decisions) is made and recorded;
- the grant, revocation, export, erasure and budget behavior above is
  implemented and tested with synthetic data, including the failure cases;
- hosted-service operations, and the export and deletion capability, meet the
  [product plan's](PRODUCT-PLAN.md#managed-ai-and-larger-campaigns)
  requirements;
- this page is rewritten from a proposal into a description of the behavior
  that exists.

## Open decisions

These are for the maintainer. They are business or operational choices, so
this proposal deliberately leaves them open:

1. Which provider configurations, if any, to support first, and in which
   processing regions.
2. The retention periods marked open above.
3. Whether a recipient's phone number is ever sent to a provider, and for
   which purposes.
4. Default and maximum budgets, and how managed AI usage is priced.
5. The support process for deletion and access requests that involve a
   provider.
6. Whether a grant may allow a fallback provider configuration.
