# Original profile03 conversation consent storage

Migration113 adds a distinct `conversation_profile03_intervals` ledger. It does
not mount a route, authenticate a browser or phone, verify signatures, reconstruct
private custody, or authorize a message from a phase label. The production
adapter must compose all of those independent checks before using its narrow
storage methods. Legacy conversation01/02 permissions remain unchanged.

An ordinary authenticated owner may reserve a bounded unsigned statement. A
separate owner request requires the actual selected browser role5 signature and
fresh password/MFA in the same transaction. Phone approval and installation use
the independently selected manifest role4 custody and authenticated full device
connection. The server retains all three exact original signatures and their
original acceptance times. Content permission begins only after the installed
acknowledgement commits and the phone independently recognizes its matching
durable local preparation. The storage schema cannot supply that local handle.

The exact ZTCA03 statement retains the original account, owner user/session,
device, line, accepted election/binding, manifest, reader and signer identities,
peer, disclosure, physical receipt, full connection and bounded time windows.
Actual current records independently bound every transition. A later manifest,
owner session, reader, signer or connection does not translate an old interval.
Original activation evidence or an installed same-phone refresh remains pinned
to its historical signed checkpoint and accepted ancestry; its digest is not a
cryptographic credential or proof of hardware custody.

The six runtime methods are reserve, owner request, phone approve, install,
owner stop and device stop. Owner stop permits the same original user through a
current owner session. Device stop records the actual current socket actor
separately from the immutable original connection; it requires no fabricated
owner session. Both withdraw new permission and retain historical proofs and
content. Neither deletes ciphertext or cancels an already admitted liability.

The ledger retains every reservation and terminal original. It bounds live work
to16 per binding, full connection and peer, and genuinely new allocations to16
per rolling24hours per account, line, binding and peer across connections. A
reconnect cannot reset that budget. Future-issued originals still count after
clock regression. A new explicit opening may permanently close a predecessor
only after its signed setup deadline, or its signed interval end after active
installation. It records the later opening and elapsed checkpoint; passive
status and exact retries never close, allocate, debit or extend anything.
Unusable but unexpired owner permission requires explicit authorized withdrawal
before another request in that scope. Outstanding messages and attempts retain
their original intervals and are never relabelled to clear a slot.

Actual mutations lock authority, account fence and retained stable anchor in
that order. Every new state transition versions the anchor tuple at unchanged
selection epoch1. Exact historical retries return their original receipt
without touching that tuple or refreshing any deadline. Deferred checks repeat
actual structural scope and primary time after waits before commit.

The ordinary non-owning runtime receives SELECT and the six narrow methods.
It cannot edit rows, columns, phases, actor history, internal scope helpers or
selection epochs. Closed body/declaration, ownership, schema, trigger and ACL
checks reject altered or partial installations. The Rust capability module is
`conversation_profile03_storage::{optional,require}`; it verifies storage
availability and runtime privilege boundaries, never authentication or consent.

Reviewed-send admission, quota reservation, grant, fetch and effect records are
separate follow-on behaviors. An installed interval alone does not make those
paths available or establish current permission for an effect.
