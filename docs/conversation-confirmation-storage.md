# Conversation confirmation storage

Migration 072 prepares durable signed conversation confirmation records. It
does not install a confirmation producer, queue admission route, execution
grant or radio path. Those integrations must independently verify the original
confirmation, signature and sealed envelope under current authority before
committing a message and its proof in one transaction.

Each record retains an immutable account/message identity, interval, initiating
owner session, device/line binding, manifest and key identities, expiry, and
digests of the original confirmation, signature and complete signed envelope.
Foreign keys bind the record to its existing message, interval, session and
line binding. Updates cannot alter this identity or extend expiry. Original
confirmation and signature bytes can only be erased together, permanently.

The bounded retention worker erases proof bytes after expiry, interval closure,
owner-session revocation or loss of owner authority, or message-content erasure.
Replay metadata remains. A retained proof prevents interval identity deletion;
the existing content-retention window still erases the peer-bearing interval
statement. Missing optional proof storage does not hide failures of mandatory
retention steps.

Owner export adds a metadata-only `confirmation_inventory`, with at most 100
records per page and a `confirmation_before` cursor. It returns no original
proof, signature, peer or envelope bytes. Owner authorization is fenced inside
the inventory transaction. Account erasure validates installed proof columns
and types and deletes proof records before their referenced parents in the
existing authenticated erasure transaction. An installed malformed table fails
erasure closed; existing erasure blockers remain in force.
