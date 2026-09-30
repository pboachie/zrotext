# Dormant single-message confirmation contract

Only the explicit synthetic conversation simulator consumes this contract.
There is no production route, credential creation, dispatch grant or radio call.
The browser page is unmounted and has no default transport. Its adapter is an
explicit dependency; pairing and SMS permissions never substitute for content
transfer consent or an active conversation interval.

Review snapshots the exact account, originating session, interval, selected
device/line generation, peer, current reader/manifest and strict UTF-8 body.
Editing, expiry, account change, hiding the page, navigation and closure discard
the review. Merely reviewing prepares an encrypted envelope; only the separate
confirmation action signs the confirmation transcript. Confirmation is consumed
before awaiting transport. An uncertain result never triggers automatic retry.

Canonical confirmation starts with ASCII `ZTCS` and byte `01`. Fields follow:

1. Account, device, line, interval, originating session and message UUIDs,
   each 16 network-order bytes.
2. Line generation, trust generation, manifest version and expiry in Unix
   milliseconds, each positive signed-range eight-byte big-endian integer.
3. One-byte peer length and 3–16 canonical E.164 ASCII peer bytes.
4. Exact 32-byte browser signer ID, archive reader ID, manifest digest,
   SHA-256 of the entire encrypted envelope and SHA-256 of the strict UTF-8 body.

The proof is 297–310 bytes, with no trailing bytes. P-256 low-S P1363 confirmation
signatures cover `zrotext/conversation/confirm-send/v1`, NUL, the four-byte
big-endian proof length, and the complete proof. The signer must be an already
authorized current role-5 browser signer for the exact line; the simulator's
fresh fixture signer models that custody without creating a production key.
The envelope itself retains the existing profile-02 signature and exactly one
selected phone and archive reader. The confirmation expires within 30 seconds
of the envelope observation. Server authorization checks the current owner
session, exact active interval and origin, phone lease, line generation, current
reader/phone signer and manifest before and after relevant waits. Authority
locks precede account locks. A verified confirmation is not an execution grant.

The independent synthetic phone consumer verifies both signatures, all scope
and envelope fields, strict mode/time bounds and expiry after decryption. It
decrypts with the distinct fixture phone KEM key and compares the actual body
digest. The shared phone admission monitor gates recording simulated acceptance
after decryption. Closing the interval during decryption prevents acceptance.

The simulator's one-shot message map is process-local test state. It is not
durable execution fencing, an exactly-once carrier guarantee, a production
outbox or delivery evidence. Production requires persisted confirmed intent and
phone execution/replay state, reconciliation of uncertain transport outcomes,
current authority immediately before radio submission, existing suppression
and billing/queue gates, owner signer custody, shared receiver/Pause wiring,
published consent/policy and physical-device tests. None is enabled here.

The canonical cross-language example is
[conversation-send.json](vectors/conversation-send.json).
