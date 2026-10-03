<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Customer-owned reply adapters

`original-reply-events.mjs` composes the original-event HTTPS reader with the
opaque sealed-event receiver and a separate customer-owned SQLite consumption
journal. It is a candidate library, not an enabled deployment. Configure the
independently selected account/device/line/interval/connector/read grant, pinned
root and locally accepted manifest history in `OriginalReplyClient`. The
original read credential and an optional independent Propose credential come
from trusted local configuration, never callback/model parameters. Read does
not authorize Propose, Approve or Send.

Call `createOriginalReplyReceiver` with that client, two distinct absolute
SQLite paths, webhook/cursor secrets and bounded capacity/retention settings.
The operator must provide a private, trusted directory and appropriate ACLs;
the library does not establish filesystem ownership or prevent a privileged
directory replacement. `ingest(bytes, headers)` authenticates the exact sealed
webhook body and stores only identities/digests. It does not decrypt, classify
STOP, invent outbound message/attempt identities or establish reader authority.

`page()` obtains current service metadata. Availability is not qualification.
`process(eventId, activeRequestId, callback)` reserves a durable identity before
reading the signed original ciphertext or invoking the bounded transient text
callback. With no associated request it does not read content and requests owner
review. A callback may return an exact shared action descriptor or `null`;
the service independently validates the registered request and separate Propose
grant, resolving ambiguity to owner review. The callback receives an AbortSignal;
local erasure or current withdrawal before a new submission stops it. JavaScript
cannot retract text already disclosed to a callback.

An uncertain read/callback/submission never runs again automatically. Restart
uses the same durable identity through `status` only; if no remote consumption
exists, it remains unresolved for owner review rather than issuing another
effect. Completed retries likewise query current service status. Per-request
automatic turns and checkpoint/tombstone counts are capped. `consume` supports
explicit descriptor submission using the same checkpoint rules.

`exportMetadata` pages local checkpoint/turn metadata, including unknowns, without
content or credentials. `exportOpaqueMetadata` exports capture metadata under a
fresh original-reader grant, bounded by receiver capacity. `retain` retires old
completed outcome metadata but preserves bounded identities and all unknowns.
`erase` durably denies future use and logically removes both ledgers; it does
not promise forensic erasure of WAL files/backups or retract remote effects.
Close the adapter to release handles and the receiver's secret copies.

The legacy adapter and opaque receiver remain separate. New original events are
not converted into `inbound.message`. Metadata STOP continues through its
existing authenticated source; this adapter never infers it from body text.
