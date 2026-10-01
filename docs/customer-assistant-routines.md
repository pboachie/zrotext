# Customer assistant routine candidate

**Draft customer-side runtime; live workflow services and selected-reader
integration are unavailable.** This does not activate customer AI, hosted AI,
messaging, provider access or a sending policy. Related prerequisites are #641,
#634, #635, #636, #638, #639, #617 and independent #615 send authority.

`sdk/assistant/runtime.mjs` implements a callable Node 22 candidate for configured
FAQ, intake, note, reminder and owner-conversation proposals. The deterministic
SDK tests execute all five through encrypted synthetic fixtures. No network,
real provider, payment, SMS or radio call occurs. The fixture encryption is a
test boundary, not the selected workflow-content wire profile.

## Adapters and authority

Build the TypeScript SDK first. `AssistantRunner` requires explicit
`enabled: true`, an absolute customer-owned journal path, an immutable policy,
and these trusted adapters:

| Adapter | Contract |
| --- | --- |
| `service.current(event, {signal})` | Authenticated shared service validates the original event, current account/connector/line/contact/purpose/context/routine/reader/provider identities and generations, consent, selected capabilities, takeover, suppression and resolved sending window. |
| `service.reserveProvider(authority, request, {signal})` | Atomically charges the exact request identity and bounded units under current independent provider authority; returns only a fresh reservation or refuses. |
| `reader.readSelected(authority, event, {signal})` | Customer-selected reader verifies exact context/reference/digest, authenticated ciphertext and current reader authority before returning UTF-8 instruction/content buffers. |
| `provider.generate(input, {signal, maximumUnits})` | Customer-controlled approved provider receives only routine kind, instructions and selected content; returns a bounded UTF-8 proposal buffer. It must enforce the maximum units and stop on cancellation. |
| `renderer.prepare(authority, {actionId, text}, {signal})` | Customer-side selected crypto renderer creates the exact encrypted context revision, returning reference/version/ciphertext. It cannot approve or dispatch. |
| `service.propose(action, ciphertext, {requestId, signal})` | Authenticated shared service rechecks exact current authority and persists the complete #635 descriptor and ciphertext binding as a proposal. Returns that exact identity and `proposed` only. |

These are injection contracts for trusted application adapters, not HTTP request
fields. A caller's `active`, `consent`, `canRead` or `canPropose` boolean is never
authority. Implementations must obtain fresh server-validated capabilities and
recheck them atomically with their effects. No live adapter is provided here;
`assistantReadiness()` always reports `workflow_services_unavailable`. Role-2
archive access from the current workflow-content candidate does not imply a
role-3 connector reader. The #641 selected-reader integration must close that
boundary before any live configuration.

Verified event delivery and resumable checkpoints belong to #617. Raw webhook
or SMS payloads must not invoke this API directly. The runner snapshots a strict
metadata-only event, rejects extra fields, and checks its original issuance and
expiry. SMS sender identity, embedded instructions and model text cannot change
the selected recipient, context, provider, reader, purpose or routine. Owner
conversation routines accept only independently verified owner-direction events;
that direction marker by itself does not authenticate an owner.

The configured consent purpose must be `transactional`, `operational` or
`marketing`, paired respectively with stable descriptor ID
`00000000-0000-0000-0000-000000000001`,
`00000000-0000-0000-0000-000000000002` or
`00000000-0000-0000-0000-000000000003`. Unknown IDs and mismatched pairs refuse.
The shared service must verify the actual latest #634 account/contact purpose
grant, expiry, STOP and human hold. This mapping identifies a purpose; it does
not create consent or a new consent ledger. Synthetic generic #635 codec IDs
are conformance data, never consent authority.

All model text is classified `sensitive`. The complete canonical action binds
the tenant, exact encrypted object digest/version, line, recipient, purpose,
routine generation, UTC timing and resolved window. A quote, booking, payment
or other commitment needs separate live authenticated owner confirmation of that
exact decrypted action through #638. The runner has no approve, send, dispatch,
schedule or tool-execution method. Historical approvals are metadata. Scheduling
belongs to #639; actual sending needs independent #615 authority and final fresh
effect checks. A model claiming its reply is informational cannot lower this
ceiling.

## Durable limits and uncertain outcomes

Policies select one conversation scope and expire within one day. Widening a
policy under the same scope/generation is refused. Configured maximums are 100
provider calls per UTC day, one million reserved units per UTC day, three turns
per selected conversation while its retained records exist, and a 30-second
provider timeout. Lower policy limits apply across the whole customer journal;
changing routine generation does not reset retained daily or conversation
charges. Use one private journal per customer budget domain. An external shared
service must independently enforce budgets across journals and processes; a
customer who replaces a local file cannot gain server authority.

SQLite uses immediate write transactions, WAL and full synchronization. Charges
and replay identity commit before provider invocation. An `unknown` checkpoint
commits before entering the provider, so a process crash, timeout, ambiguous
proposal response or late withdrawal cannot repeat a call automatically.
Duplicate input returns its stored opaque outcome after fresh scope checks.
Changed input under the same identity conflicts. Budget storage failure or an
unavailable external reservation stops before a provider call. Unknown outcomes
consume their charge; reconciliation requires a separate authenticated service
flow and cannot infer owner approval.

Local clock rollback refuses work. Expiry, current authority and withdrawal are
rechecked after adapter waits. Unknown timezone/window resolution holds for
owner review. The scheduling candidate uses an exact `window-v1-` plus SHA-256
policy identity and UTC epoch seconds; UUID windows are synthetic fixture
identities. No authenticated live `open` window endpoint exists yet. STOP or human takeover persists withdrawal and aborts outstanding
calls. A provider ignoring cancellation may still incur its already reserved
cost; its late result cannot create a proposal. Shared services must enforce
withdrawal transactionally, including changes racing the final proposal call.

## Reader, export and erasure boundaries

The journal contains only hashes, budget units, lifecycle states, expiry and
opaque proposal references. It contains no message body, instruction text,
provider response, ciphertext, credential, key or phone number. Export is a
bounded 100-record page with an explicit continuation cursor. File and WAL tests
check plaintext canaries are absent. Keep the journal in a private directory
with appropriate platform ACLs; creation mode alone is not a Windows ACL.

The runner zeroizes owned mutable instruction, selected-content, model-output
and renderer buffers on completion, refusal or timeout, including late provider
output. This cannot erase a provider's retained copies, JavaScript strings,
network service records or OS memory. Adapters must avoid retaining plaintext,
logging it or sharing it with adjacent conversations.

Pruning preserves charged records until both their budget day and policy expire;
event expiry never replenishes a live allowance. Expired original input cannot
be resurrected after pruning. `eraseMetadata()` deletes records and permanently
disables that journal. It does not claim forensic deletion of SQLite pages,
backups or provider data, and does not erase the server's exact action, context,
decision or schedule ledgers. Account export/erasure and provider retention are
independent shared-service responsibilities.

## Verification boundary

Run `npm test` from `sdk/typescript` after installing the locked dependencies.
The existing CI test glob discovers `test/assistant-runtime.test.mjs`, including
actual SQLite transactions and a subprocess killed immediately after the
durable pre-call checkpoint. Tests exercise prompt injection, adjacent scopes,
consent/reader/provider revocation, takeover, loop and unit limits, storage
failure, timeout, restart/replay, budget retention and plaintext-free exports.

No real model/provider, production workflow service, physical device, radio
delivery or end-to-end owner approval is verified by these fixtures. Live
activation remains unavailable until the shared service and selected-reader
contracts are integrated and independently checked.
