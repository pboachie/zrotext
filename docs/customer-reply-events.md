# Customer-local scoped reply event adapter

**Experimental candidate implementation; production agent reply delivery remains
unavailable.** `sdk/replies/reply-events.mjs` provides a runnable signed-webhook
receiver, a resumable customer-local HTTP interface and a durable SQLite
metadata/checkpoint/action ledger for #617. It has no SMS submission, owner
approval, radio grant, second message queue or model-provider connector. #615
server-side grants, trusted conversation services and sealed-content readiness
remain activation dependencies. The server's existing ingress/delivery gates
are unchanged and default off.

Use Node.js 22.16 or later; the built-in
[`node:sqlite`](https://nodejs.org/download/release/v22.16.0/docs/api/sqlite.html)
API is experimental. No additional dependency is introduced. From
`sdk/typescript`, run `npm ci --ignore-scripts`, `npm run build`, and
`node --test test/reply-events.test.mjs`. The normal `npm test` discovers the
same tests in CI. They use temporary on-disk databases, an independent process
that exits after committing a reservation, and an actual local HTTP listener.
They never contact a hosted service or send SMS.

The candidate response schema is
[`agent-reply-events-01.schema.json`](../protocol/drafts/agent-reply-events-01.schema.json).
The shared [public test vector](../protocol/v1/vectors/agent-reply-events-01.json)
contains only synthetic known bytes and an exact webhook HMAC transcript;
Python independently recomputes the HMAC and validates bounded response shapes.
Its illustrative cursor is shape-only, not a grant or a runnable resume token.
Runtime tests separately authenticate real generated cursors. UTF-8 text limits
are enforced in encoded bytes at runtime, beyond the schema's character bound.

## Independent scope and reader boundary

Construct `ReplyEventAdapter` with a customer-managed database path, exact
account/line IDs, separate 32-byte webhook/cursor secrets, a trusted clock and
an independently authenticated `authority(event, now)` lookup. Secrets come
from the customer secret store, stay in adapter memory, and are never accepted
in agent requests or written to SQLite. Do not place the database, its WAL,
secrets or private deployment configuration in the public repository. Missing
authority denies every operation. The database format is version 1 and is
bound to one account/line plus a random instance identity; reopening it under
another scope fails closed.

Authority must independently validate the current grant, account, line,
device/source-attempt mapping and expiry, then return `active`, `accountId`,
`lineId`, `deviceId`, `revision` and `expiresAtMs`. A revision changes on any
grant/identity change; old events and cursors do not migrate into the new grant.
The webhook has no line ID, so scope must come from authoritative source-attempt
metadata rather than SMS text, sender inference or a model instruction. The
lookup must be synchronous and current, not a cached login or historical
receipt. This callback is a customer integration seam, not an implemented #615
server grant service.

Selected content additionally requires the configured `readerId` to match the
current grant's reader ID and `canReadContent === true`. The customer-local
`reader(event, AbortSignal)` loads only that event from the existing selected
content service/queue. It has a five-second bound. Content access is checked
again after decryption and before an automatic notification. Revoking just the
reader preserves metadata access and returns content `unavailable`.

`sdk/replies/selected-draft-reader.mjs` is a testable profile-01 reader seam. It
delegates origin verification and HPKE/body decryption to the existing SDK
`openDraftEnvelope`, and checks exact inbound event/account/device/line/time
binding. Its trusted `authorize` callback must independently authorize the
current manifest, recipient and reader before and after loading. It implements
no alternate crypto. It is **not** a production profile-02 reader or a root
enrollment service. The shared public envelope corpus proves the delegation;
production reader approval remains unavailable.

The current `opaque_pilot` webhook format is never treated as customer sealed
content and is never passed to the reader. Ordinary events without an
independently available selected reader report `{kind:"unavailable"}`.
Recognized `opt_out` and `opt_out_review` report `{kind:"metadata_stop"}` without
decrypting a body. A permitted selected read returns `decrypted`, the text and
the exact reader identity. Plaintext is returned only to the authenticated local
client, never persisted or logged by the adapter. No model provider receives it
automatically; forwarding by a customer client is a separate disclosure the
customer must authorize. Revocation cannot retract content already returned.

## Webhook and resumable interface

`createReplyEventServer(adapter, authenticate)` returns an **unstarted** Node
HTTP server. The customer supplies listener/TLS/reverse-proxy and network
controls; tests bind only `localhost`. The reverse proxy must preserve raw
webhook bytes and the signed headers. `authenticate` independently returns the
configured consumer identity for a scoped local client; absence denies access.
It must not infer authority from received content. Four in-flight requests,
bounded request bodies and five-second receive/reader deadlines limit resources.
All responses are `no-store`; exception text and secrets are not returned.

| Method and path | Behavior |
| --- | --- |
| `POST /webhook` | Verify the existing exact raw-body HMAC and signed event schema; return 202 only after the metadata transaction commits. |
| `GET /events?cursor=...&limit=...` | Authenticate the local consumer; return up to 20 events in local ingress order with a scoped cursor and explicit content state. |
| `POST /consume` with `eventId`, `actionId` | Authenticate the local consumer; atomically reserve one action identity, consume the next event and advance its durable checkpoint. |

No HTTP route registers correlation requests, changes grants, clears STOP,
approves actions, executes effects, exports data or takes owner control. These
are separate trusted customer-local operations. Unknown fields and duplicate
query parameters are refused. Consumer identity comes from authentication,
never a request body or cursor's unverified fields.

Webhook verification reuses
[the existing signing contract](../protocol/v1/inbound-foundation.md):
HMAC-SHA256 of ASCII Unix-second timestamp, a dot and the exact raw JSON bytes,
with canonical lowercase `v1=` hex and a five-minute transport window. The
server already verifies device signatures and writer/source-attempt identity
before enqueueing this webhook. This receiver verifies the authenticated server
transport; it does not claim independent device-signature verification because
the public webhook lacks the device sequence needed for that transcript.
Changing the delivery ID on replay is permitted; changing any original inbound
field under the same event ID is an identity conflict. No event ID is minted
as a replacement for the server identity.

Cursors authenticate database instance, account, line, consumer, grant revision,
sequence and expiry under a separate secret. A cursor is a read position, not
proof of action consumption. Restart the same consumer from its persisted
checkpoint to recover unconsumed events. A foreign/tampered/revised/expired
cursor fails explicitly. Retention gaps never silently skip into automatic
processing: a trusted local owner must review the gap and call `resynchronize`;
the skipped floor and gap count persist, and no skipped effects are run.

## Action identity and correlation

Only a trusted customer owner/controller registers an active request with exact
outbound message/attempt/device IDs, start/expiry and a cap of one through eight
automatic turns. Registration is correlation metadata, not send permission.
The source-attempt lookup must validate these IDs independently. Received text,
including "yes", can never register requests, change scopes or approve work.

A decrypted `captured_local` reply can produce only `reply_notice` for exactly
one active matching request within its time window. Reordered, future, late,
ambiguous, unrelated, unavailable and unverified replies produce `owner_review`.
Every result has `approval:false`. Turn counts and the last accepted observation
time persist; repeated agent-to-agent replies reach the cap without generating
new send authority. A local owner must separately authenticate any sensitive
action against #615's exact-action approval service.

`consume` commits a globally unique event/action identity and checkpoint in one
`BEGIN IMMEDIATE` transaction before effects. `runAction` invokes a trusted local
notification/review callback only for a new reservation and rechecks current
scope/reader/STOP immediately before invocation. The callback receives metadata
and the durable action ID, not message text or credentials. It must use that ID
for its own idempotency. A callback exception is `unknown`; replay or recovery
of an interrupted `reserved` action also reports `unknown` and never retries
the effect. A callback can have completed before a process dies, so this is not
a claim of exactly-once external side effects. Reconciliation is explicit owner
review; it never resubmits an uncertain action automatically.

## STOP, retention, takeover and erasure

STOP commits a conservative line-wide denial before any turn cap or content
read. It also commits denial when the event ledger is full, then returns
`retention_full` so webhook delivery can retry; pending automatic actions and
selected reads are already blocked. `opt_in` cannot clear this denial. There is
no agent-facing undo/reset operation. This is a safety overblock, not a claim
of recipient-specific server suppression or a carrier opt-out service.

The ledger defaults to a 24-hour ingress retention window, configurable from
one minute through seven days; actions require the original observed time to
remain within that window. It holds at most 1024 event references by default
(maximum 4096), 128 request windows and 16 durable consumer identities. Request
correlation metadata expires one retention interval after its window closes.
Retention cleanup runs on resume, consumption and export. The HTTP listener
also runs cleanup every minute while idle; standalone library consumers must
call `expire()` periodically. SQLite WAL with `synchronous=FULL`,
transactions and secure deletion protects committed state. Real power-loss and
customer filesystem durability are not verified by a process-exit test.

Trusted local `deny('revocation')` or `deny('takeover')` persists an irreversible
denial across reopen. `exportMetadata()` requires current scope and exports only
retained event/action/checkpoint references. Before local erasure, the owner can
perform that export. `deny('deletion')` purges pending references, requests,
actions and checkpoints and leaves the durable revoked scope tombstone. It
does not erase a customer's backups, logs, another server's queue or previously
returned plaintext. Operators must include those stores in account erasure and
must not reopen deleted/revoked scope by deleting the tombstone or changing an
agent's instructions. In-flight external effects cannot be retracted.

No production #615 grant integration, approved profile-02 selected-content
runtime, device/carrier reply flow, physical device, hosted ingress deployment
or release activation was verified. Report suspected vulnerabilities privately
as described in [SECURITY.md](../SECURITY.md).
