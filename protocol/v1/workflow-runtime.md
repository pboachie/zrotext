# Dormant shared workflow service contracts

This is a client-neutral library candidate for #641 with an independently
opted-in HTTP transport for #616; it is not a production sending capability.
Its eight methods share the existing
workflow context, exact-action decision and recipient-local scheduling stores.
It adds no queue, approval ledger, crypto implementation or background worker.
The executable DTOs are `workflow_runtime::contracts`; the library dispatcher
`workflow_runtime::call` invokes the eight actual checked service
functions and preserves typed authorization errors. Transport wrappers must
authenticate the separate workflow credential and call the checked service;
parsing a DTO or reading the catalog never grants authority.

## Request envelope and method catalog

Requests contain exactly `method` and `params`. Unknown methods and fields are
rejected, including caller-selected actors, permission bits, approval flags,
owner identities and message/dispatch markers. Every request ID is a nonzero
UUID. An exact semantic replay retains its identity; reuse for a different
operation or payload conflicts. Current authority is checked again on replay.
Grant, context, interval, session and connector deadlines are checked against a
fresh database clock after the final potentially blocking authority query.
An earlier successful check cannot keep a grant live through a later query wait;
expired issuance rolls back the credential records and MFA consumption.
Credentials belong to transport authentication, never request bodies, responses
or audit payloads. No owner-cookie/API-key/agent-key fallback is implied.

| Method | Independent permission | Parameters | Candidate result |
|---|---|---|---|
| `workflow.contact.read` | `ContactRead` | `request_id`, `context_id` | Bound contact UUID, purpose, peer digest |
| `workflow.context.metadata` | `ContextMetadata` | `request_id`, `context_id` | Public context lifecycle metadata |
| `workflow.context.content` | `ContextContent` | `request_id`, `context_id` | Separate checked role-3 encrypted projection |
| `workflow.action.propose` | `Propose` | `request_id`, existing exact `descriptor` | Durable `ActionState`; no approval/message |
| `workflow.action.status` | `Status` | `request_id`, `context_id`, `action_id` | Latest durable action key, record version, phase and exact bound delivery snapshot |
| `workflow.action.schedule` | `Schedule` | `request_id`, exact `key`, `policy`, `series_id`, `ordinal` | Existing scheduler occurrence through the checked integration permit |
| `workflow.action.send` | `Send` | `request_id`, exact `key`, optional `occurrence_id` | Durable typed `SendOutcome` through the checked integration permit |
| `workflow.action.cancel` | `Send` | `request_id`, exact `key` | Withdraw this same grant's prepared message before its irreversible grant; preserve the historical owner decision |

All eight library operations exist with checked transaction-bound service
permits; their catalog state is `library_candidate`. The transport is disabled
by default and no activation or noninteractive background worker is implied. The dispatcher
requires a real authenticated `IntegrationPrincipal`; it does not authenticate
caller fields or serialize raw database/provider diagnostics.
No approve, edit, bind, reply-correlation or takeover method is exposed
to an integration. Those remain independently authenticated owner operations.

## Opt-in authenticated HTTP transport

`WORKFLOW_TOOLS_ENABLED=true` mounts `GET` and `POST /v1/workflow/tools`
when server authentication is enabled. With the flag off the route is absent.
This flag does not enable sealed sending, device dispatch, or a background worker.
Both methods require exactly one `Authorization: Bearer` header containing the
dedicated workflow credential. Cookies, Origin headers, duplicate credentials,
owner sessions and ordinary API/device/agent keys are refused. Credentials never
appear in the DTO or caller-selected actor fields.

Issuance remains the existing owner/MFA-checked library operation; this mount
does not provide a self-service grant-management HTTP endpoint or UI. It consumes
an actual issued workflow grant rather than translating an ordinary API key.

GET rechecks the authenticated grant's current context scope and returns exactly
`available`, `methods`, `scope`, and `send_semantics`. `available` is true for a
successful response; scope contains `context_id`, `device_id`, and `line_id`.
The eight method entries retain the catalog fields and add `permission_granted`;
`transport_mounted` is true. Permission hints do not replace each operation's
fresh checks. `send_semantics` is `owner_bound_prepared_only`.

POST accepts the closed request above and returns the existing `{kind,result}`
response. Requests are limited to 65,536 bytes, responses to 131,072 bytes, and
transport handling to ten seconds. Responses carry `Cache-Control: no-store`.
Errors contain only `{error:{code}}`: `invalid_request` (400), `unauthorized`
(401), `forbidden` (403), `conflict` (409), `rate_limited` (429), or
`unavailable` (503). Raw database
and provider diagnostics are excluded. A timeout or unavailable response after a
mutation is ambiguous: it does not prove rollback and must not trigger an
automatic new-identity retry. Reconcile or explicitly replay the exact request.

Catalog hints describe domain behavior only. Reads may still consume bounded
access/audit records. An idempotent hint means exact semantic request replay,
not permission to retry an uncertain radio effect. The send destructive hint
warns of the eventual irreversible effect; it does not enable that effect.
The hints neither widen a grant nor substitute for current authorization.

## Exact identities and recipient timing

Proposal descriptors reuse every normative field and canonical digest from
[workflow-action-01](workflow-action-contract.md). No subset, caller approval proof or
additional plaintext is accepted. The service checks account, line, contact,
purpose, context revision/digest, routine generation and timing against live
authority; their presence in a descriptor is not evidence of consent.

An action key contains `account_id`, `action_id`, `revision` and the exact
`binding_digest` as 64 lowercase hexadecimal characters. Account identity is
verified against the authenticated principal; it is not chosen by the caller.
Action revisions are positive and within the existing decision-store bound.

Schedule policies reuse all `WindowPolicy` fields: explicit recipient timezone
or null, first local date, opening/closing minutes, optional local-day recurrence,
maximum occurrences and pacing. The approved descriptor's window ID must equal
the actual immutable `window-v1-<64 lowercase hex>` policy identity. Each ordinal
requires its own exact approved action. A valid shape or a computed identity
does not resolve a missing timezone, nonexistent/ambiguous civil time, or missed
window. Such cases wait for owner review or refuse; they never choose an
arbitrary execution time. Descriptor `not_before`/`expires_at` use UTC epoch
**seconds**. Occurrence fields ending `_ms` use UTC epoch **milliseconds**.

Schedule and send remain independent grants. The initial supported executor
must be the same exact workflow grant UUID recorded on the occurrence and must
explicitly possess each permission required for the requested operation. A
different grant on the same connector cannot adopt that actor. A later reviewed
cross-grant link would need its own exact account/action/occurrence proof;
connector membership or a caller-supplied grant ID is insufficient.

Send accepts no raw message, recipient number, plaintext, ciphertext, message ID
or dispatch ID. The checked wrapper discovers the existing immutable
owner-confirmed rendered-message link for the exact approved action, retains the
shared routine/context/action/schedule transaction fences, and rechecks current
authority through commit and the existing phone grant/intent boundary. Missing
owner binding produces durable `waiting_owner_binding`; an unopened or pacing-
blocked scheduled occurrence produces durable `waiting_window`. Omitting or
setting `occurrence_id` to null requests immediate independent Send. It requires
the exact owner-approved descriptor to name `immediate-v1` and refuses if the
action already has an occurrence. A canonical scheduled policy cannot become
immediate by omitting its occurrence, even before scheduling. A nonnull occurrence must be nonzero
and the exact occurrence owned by the same authenticated workflow grant, which
must also possess Schedule. Caller-selected occurrences do not grant authority.

Exact replay retains the first waiting or prepared outcome after current
authority is rechecked. A waiting result needs a new request identity after the
prerequisite changes. `prepared` contains the exact server-discovered message
and dispatch UUIDs as metadata only: the wrapper creates no queue message,
invokes no provider/radio and proves no carrier submission or delivery. The
shared scheduler checks timing, lease expiry and pacing again after blocking
writes and through deferred commit guards; expired leases cannot be revived
by a successful earlier check. Unknown submission stays unknown;
it is not success, delivery, approval, or permission for an automatic resend.

## Response boundaries

Responses contain `kind` and `result`. The candidate kinds are `contact`,
`context_metadata`, `context_content`, `action`, `occurrence`, `send`, and
`unavailable`. The `send` result reuses the strict `SendOutcome` states
`waiting_owner_binding`, `waiting_window` and `prepared`.
These are serialization shapes, not tokens a caller can replay as authority.

Contact metadata contains no phone numbers or decrypted notes. `peer_digest` is
lowercase SHA-256 hex of the exact approved peer identity. Public context metadata
contains context UUID, revision, numeric kind, expiry, binding/trust/manifest
generations and explicitly named `source_content_digest`: lowercase SHA-256 hex
of the exact locked archive-source envelope. This field binds
`Descriptor.content_digest` to the same stored source revision; it is not the
hash of the separately encrypted role-3 projection. It proves neither plaintext
meaning, decryption access nor equivalence between two encrypted representations.
It omits the source archive reader and content-proof claims. It must not relabel the source role-2 header as a role-3
projection.

Content returns the separately owner-declared role-3 ZTWC envelope as canonical
unpadded base64url, never archive-reader bytes as a fallback. The client verifies
the actual envelope header, selected reader, manifest and authenticated binding
before decryption. For proposal construction the client uses metadata
`source_content_digest` with the exact context UUID/revision; it must not
substitute a digest computed from the role-3 envelope. Metadata alone does not prove successful encryption, content
meaning, reader access or authority. The server stores/forwards opaque bytes.

Action status retains the exact `key`, `record_version` and closed action phase,
and adds `delivery`. Its availability is `not_bound`, `unavailable`, or `available`.
Available metadata comes from the canonical delivery store for the immutable
message/dispatch link matching this exact action revision and binding digest,
under the current tenant, device and line scope. It reports message/dispatch
UUIDs, delivery state/version, acceptance time and update time; no content or
recipient is returned. Unavailable metadata never becomes a guessed delivery
state. Approval and Prepared are not submission or delivery evidence. Looking up
the current head reveals revision changes; a prior approved key never authorizes
its replacement. Occurrence responses
expose occurrence/series UUIDs, ordinal, lifecycle phase, nullable opening/closing
times and expiry. Internal lease/message/dispatch markers are omitted.

The reserved transport unavailable reason is `transport_not_mounted`; the
library dispatcher does not fabricate unavailable schedule/send results.
Unknown credentials,
foreign tenant/resource IDs and revoked/expired authority must be refused by the
service, without exposing private foreign-resource detail. Transport error
mapping remains a wrapper responsibility; no raw database/provider errors or
credentials should appear in client responses.

## Synthetic acceptance example

This request is synthetic and grants no access:

```json
{
  "method": "workflow.contact.read",
  "params": {
    "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "context_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
  }
}
```

The executable contract tests check the closed method/permission mapping, denial
of unknown authority fields and owner operations, exact digest spelling, zero
identity/revision rejection, schedule ordinal bounds, and omission of reader/
content claims from metadata. They run through normal Rust test discovery after
the module is declared. End-to-end transport,
radio execution, physical-device delivery and real provider calls are not proved
by these DTO tests. Production configuration and activation remain explicit and
outside this candidate contract.

Send permission explicitly includes withdrawal of this same grant’s own prepared output through `workflow.action.cancel`. The closed input is `request_id` and exact `key`; callers cannot nominate a queue or message identifier. Cancellation discovers the immutable owner binding and verifies the actual preparing grant, then uses the existing job/message grant boundary and refund-once transaction. Status, Propose and another Send grant confer no withdrawal authority. Cancellation changes the bound message only; the historical owner decision and scheduling series are not cancelled or reapproved. Already granted, expired or uncertain work is refused; transport ambiguity stays unknown and never triggers resend. Exact retries still require live scope, credentials and authority. The UUID-only legacy cancellation tool remains unavailable.
