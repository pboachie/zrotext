# Expired unaccepted profile03 election recovery

This additive candidate transport composes with the Android profile03 setup
consumer. It changes no E500 or signed-bundle bytes. Source integration and
structural vectors do not establish server transaction, Android provider,
reconnect or carrier acceptance.

Every `payload_profile_challenge03` frame requires a `closed_unaccepted` array,
including the empty array for an initial opening. The corresponding owner
challenge response carries the same array. Only this root field admits an array
in Android's strict bounded JSON parser. It contains at most sixteen closed
objects, each with exactly these fields:

| Field | Representation |
| --- | --- |
| `opening_id` | Canonical nonzero UUID of the original server reservation |
| `challenge_id` | Canonical nonzero UUID, equal to the original E500 challenge |
| `new_binding_id` | Original immutable server-reserved new binding UUID |
| `core` | Exact canonical unpadded base64url original 500-byte E500 |
| `closed_unaccepted_ms` | Positive canonical decimal-string timestamp |
| `superseded_by_challenge_id` | Exact next challenge UUID in the retained chain |

The [closed projection schema](../v1/profile03-closed-unaccepted.schema.json)
validates this array's shape independently of the full authenticated challenge.
It cannot prove the server transaction or resolve a released phone signature.

The server may close only an expired, never-accepted reservation in the same
exclusive transaction that verifies genuine current02 selection epoch zero,
current owner authentication with a fresh factor, and reserves a higher burned
generation. A closed reservation remains ineligible for acceptance even if a
clock regresses. Passive status, a transport failure, local retirement, an expiry
alone or a `not_accepted` reply cannot perform that transition.

The array retains the entire linked ancestor chain in increasing burned
generation order. Generations may have gaps. Each original expiry is at or before
its closure; each closure timestamp equals the successor E500's exact issued
timestamp. The last entry links to the new live challenge. Every E500 shares the
same account, device, line, original binding/generation/proof, root, vault,
original02 manifest, successor version, selected reader, enrolled device key,
original SEALED approval key and canonical origin. New nonces, owner/device
sessions, burned generation, time window and signed03 candidate digest may differ.
Every new candidate still needs the full original proof and signed-manifest
verification performed by the ordinary setup consumer.

A predecessor may never have reached the phone. Android retains such an entry
only as authenticated server reservation/closure provenance. It does not invent
a local election row, device signature or acceptance. Every locally retained
active or ever-signed predecessor must match its exact core and reserved binding
and be covered. Any locally accepted election contradicts current02 and refuses.

Room schema17 adds a separate immutable closure journal. All closure entries and
the fresh reserved election commit under one writer before hardware signing.
Post-write authority loss rolls back that entire new transaction. Existing rows,
signatures, unknown radio attempts and permanent legacy02 fallback fences remain.
Closed challenges cannot later acquire a local signature or installation, while
current-status polling selects only the unresolved fresh signed opening.
An explicitly verified fresh opening may resume bounded status reads, preserving
the socket's existing rate and total-request limits.

Missing or overlong chains, changed historical entries, wrong local records,
accepted predecessors, unresolved effects and stale physical/socket authority
refuse without deleting history or selecting another profile. Exact passive
proof resume requires its already retained closure history and cannot import a
new history or sign again. Fresh same-phone observation refresh is a separate
protocol and cannot reuse these election closure entries.
