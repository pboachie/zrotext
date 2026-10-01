# Managed AI selected-reader and task lifecycle contract

**Proposal prerequisite; unavailable.** This contract selects generic authority
and lifecycle boundaries for #644. It does not enroll a managed reader, mount a
route, make a provider call or enable a worker. Customer-controlled assistants
remain independent. Provider/account/region choices, retention periods,
commercial terms and budget amounts stay private policy decisions. Runtime
implementation must satisfy the [managed AI release gates](../../docs/MANAGED-AI.md#release-gates).

## Grant and client-created wraps

A grant names one account, one managed reader identity and key generation,
selected line/conversation/content identities, permitted purpose, one provider
configuration identity, expiry, revocation generation and bounded budget policy
identity. There is no wildcard, contact-group expansion, adjacent conversation
inheritance or automatic future-content enrollment. Future scope expansion
requires a new owner-confirmed grant version. Reader and send grants are
separate; neither content access nor a provider response approves an action.

Grant creation, widening and key-generation replacement require fresh owner
password/MFA confirmation and audit; revocation/narrowing require the current
owner session. Root keys, device signing authority and account administration
are never delegated. The authenticated reader must independently prove its
pinned identity and current key generation. A caller-provided reader string
alone is not authentication. The conformance oracle assumes that proof and
fresh owner authorization have already been verified by trusted boundaries.

An existing authorized content client decrypts the owner-selected encrypted
objects and creates per-object wraps for the managed reader's independently
verified public key. Only that client has plaintext/key access. The relay may
store and route opaque wraps and binding metadata; it cannot invent another
reader wrap, decrypt/re-encrypt content or grant access to an object by changing
metadata. Key comparison and owner selection precede wrap creation. The wrap's
protected binding includes account, line, conversation, object/version/digest,
grant/version, reader/key generation, purpose and task identity. Wrong bindings
fail closed at both retrieval and client unwrapping. Never serve an unrestricted
conversation transcript to a selected-content task.

Granting content reveals it to the managed service and the chosen provider.
Revocation cannot recall plaintext already read or stop a compromised reader
using a retained old wrap. The controlled service must destroy grant-scoped key
material and caches when revoked. This is a future-access control, not remote
cryptographic erasure. Reader rotation invalidates old tasks and grants; the
owner confirms a new grant and an authorized client supplies new wraps only
for explicitly selected content. Old wraps are never automatically copied or
rewrapped by the relay. Other readers' keys and old-ciphertext access remain
unchanged by this managed-reader rotation.

## Task binding and checkpoints

A task binds immutable task/account/grant IDs, grant version and revocation
generation, reader/key generation, provider configuration, line, conversation,
selected object IDs with versions/digests, purpose, expiry, maximum provider
units and routine authority generation. Bind owner instructions as selected
objects too; prompts cannot request adjacent content or expand tool authority.
Use per-task recipient pseudonyms; no raw phone, customer/account/device IDs
or unnecessary metadata enter provider requests. No provider fallback is
selected by this contract. Changing the bound task requires a new task and
explicit grant/access checks; it cannot inherit an earlier provider response.

| Checkpoint | Atomic requirements | Failure outcome |
| --- | --- | --- |
| Queue/admit | Live grant/account, exact selected content/wrap bindings, current reader/grant/routine generations, purpose and expiry, available bounded task/provider budget | reject; no provider request |
| Begin provider call | Repeat all current authority/content checks; reserve worst-case units and one task slot durably; CAS queued task to provider-inflight with stable call identity | cancel or block; no call |
| Accept provider output | Same call/task/reader/provider binding, live grant/generations, unexpired task, all selected content still present | discard output; content-free reason |
| Propose draft | Fresh content-reader authority; encrypt draft for owner and explicitly permitted reader only | discard; never store plaintext draft |
| Begin send | Exact approved action digest/version and separate send grant; repeat live reader/grant/routine/content/expiry checks plus suppression, device/line eligibility and send budgets | reject send, invalidate derived pending work |

Every authoritative snapshot and checkpoint update must serialize with
revocation, expiry, rotation, deletion and budget changes. No cached permit,
queued task, prior approval, earlier reservation or successful model response
survives a failed current checkpoint. A budget lookup failure is exhausted;
never silently top up, change provider, repeat the call or widen a grant. Amounts
are integers within a configured hard ceiling; booleans/negative/unbounded
amounts are invalid. Reserve worst-case cost before the call; settle actual
bounded usage once by call identity. Unknown provider acceptance keeps the
reservation consumed until authoritative reconciliation. Retries that may
repeat a paid call need a separately selected policy; this contract permits
none. Suppression and sending authority are independently enforced by the
existing send lane, not inferred from successful provider admission.

## Revocation and irreversible effects

Queued work is cancelled before a provider call when a grant is revoked,
expired, rotated or narrowed, or selected content is deleted. If a call has
already begun, request best-effort cancellation, record the attempt and discard
any later output. Already-approved pending work is blocked at the send
checkpoint too; owner approval is never an exception to revocation. Cancelling
a remote request does not prove the provider did not read the prompt.

A call that is already in flight may complete outside the service's control;
there is no new content fetch, tool action or send allowed as a consequence.
Once send dispatch has durably committed, revocation prevents subsequent work
but cannot claim cancellation/recall of that already committed effect. Preserve
its honest status; uncertain dispatch remains unknown and cannot auto-resend.
Provider outages and mismatched/late responses produce a visible metadata
outcome with no automatic retry. Duplicate outputs/callbacks cannot create a
second draft/send. Use one stable call identity and one stable dispatch identity
with durable CAS and replay fences. Exact-action approvals follow the shared
workflow contract (#635); managed AI must not define another approval model.

## Retention, export and deletion

| Category | Retention boundary | Export / deletion propagation |
| --- | --- | --- |
| Plaintext prompts, selected content, responses, transient keys | Memory only during authorized task; no logs/traces/crash reports/queues | Never export plaintext; destroy controlled memory/cache on completion or revocation |
| Selected encrypted objects and managed-reader wraps | Existing content retention plus grant lifetime; no independent immortal copy | Authorized ciphertext export; delete wraps/objects through owner erasure and content deletion |
| Encrypted drafts | Bounded selected policy; generation/grant binding remains explicit | Ciphertext export; revoke future managed-reader access and delete on account erasure |
| Grant versions, reader public identities, scope, lifetime and revocation | Bounded account audit policy | Owner export includes history; erasure removes grants and controlled grant-scoped keys |
| Task/call metadata, authority checks, budget ledger, decision/outcome links | Content-free, bounded audit/replay policy | Export all account records; delete or retain only policy-required minimal tombstones with explicit expiry |
| Provider copies already read | Selected provider policy; local erasure cannot prove remote deletion | Request deletion where supported; record attempted/acknowledged/unsupported/failed/unknown separately |

No numeric retention period or legal exception is selected here. Runtime cannot
launch until explicit bounded policies exist for each category. Export includes
revoked/expired grants, selected ciphertext, wraps, task and budget records,
encrypted drafts, failed calls and deletion propagation status. It must not
export service private keys or raw prompts. Account erasure first makes the
account/grants unavailable to all checkpoints, then removes controlled records
and keys. Outstanding remote deletion requests contain only the minimum opaque
provider reference and have a bounded reconciliation lifetime.

Report local deletion independently from provider deletion. Acknowledged means
the provider acknowledged its deletion protocol, not that previously consumed
content became unread or all backups vanished. Unsupported, failed and unknown
remain visible; never convert best-effort cancellation into successful erasure.
No claim of recall of retained data, model use or already dispatched messages
is permitted. Real evidence, provider accounts and operations remain private.

## Conformance and rollout

Synthetic grant/task vectors cover adjacent-conversation canaries, foreign
accounts, wrong reader/task/provider, scope narrowing, expiry, deleted content,
rotation, revoked grants before call/send, exhausted/unavailable budgets and
already-approved/in-flight work. The executable reference is test-only; it
models fresh trusted snapshots rather than HTTP authority, encrypted wrapping,
provider SDKs or actual storage. Runtime slices must additionally prove pinned
key enrollment, protected wrap binding, worker isolation, transactional races,
canary absence in logs/storage, export/erasure and provider propagation.

The managed service remains unavailable until scoped grant, authorized-client
wrapping, reader access, worker, budget and lifecycle slices and private policy
decisions all complete. This contract creates no hidden reader, provider
transport, automatic content fanout, sending authority or production activation.
