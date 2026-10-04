# Conversation capture journal

The Android conversation journal is a separate Room database opened by the explicit
conversation installation. The selected runtime connects receipt admission, protected
storage and capture upload to the authenticated phone channel. Construction alone
grants no capture authority. Synthetic Room and isolated emulator probes exercise
this source path; physical phone and release gates remain separate.

An affirmative phone approval prepares an encrypted exact scope: account, device,
line and binding generation, selected peer, interval and receipt identities,
originating browser session, disclosure digest, exact reader key, trust generation,
original activation version / digest and activation transcript digest. Preparation
alone cannot capture. The authenticated activation adapter validates approved manifest
provenance, exact ACK identity and server-installed state before accepting an active
response. The current permission, session, reader and root checks remain mandatory.

Recovery uses a fresh challenge. A verified response grants at most 60 seconds of
local admission, measured from the request's monotonic start, including response
delay. Exact authenticated duplicate responses are idempotent without extending
that deadline. Persistent `installed` state never restores a lease after process
restart. Clock regression closes admission; recovery requires a new domain instance
or the monotonic clock catching up. Current permission, device lease, line continuity,
originating session and exact reader / root authority checks are mandatory adapter
responsibilities, checked again after storage waits.

At first receipt, a separate transaction commits a content-free HMAC receipt fence
before encryption begins. Only that same call can upgrade the fence to an encrypted
capture in a second transaction. Pending, unselected, oversized, expired and discarded
receipts remain fenced. Encryption or admission failure commits only the fence;
process death during the upgrade rolls back the body while retaining the fence.
Failed storage before the initial fence commits cannot prove that a receipt was seen.
Receiver integration must stop admission and avoid redispatching uncertain backlog
after such a failure.

Captured records retain their original interval, activation provenance, durable event
identity and first receipt times. Retries decrypt that exact record and require the
same currently authorized interval. They do not reassign an interval, refresh capture
time, rewrite provenance or reseal old content. Local close synchronously clears
admission and pending recovery before persisting an irreversible closure fence.
It clears pending wire ciphertext while retaining body ciphertext and identity fences;
withdrawal and content deletion are separate operations.

Upload uses the persisted envelope and sequence. The transport authenticates the
current session and verifies the response challenge, event and full envelope digest.
An exact durable upload ACK is finalized in one Room transaction: recheck current
scope and consent, bind the receipt token, event, interval, sequence and original
receipt time, record the ACK digest, and clear both protected body and envelope.
The final authority check occurs after both writes; failure rolls back the entire
transaction. Wrong, malformed, late or missing ACKs cannot finalize a capture.
This ACK records server upload custody, not customer delivery or reading.
An authenticated `created=false` retry also requires retained protected content and
the exact interval / manifest provenance in the server's conversation ingest
transaction; erased or provenance-less replays receive no capture ACK. The server's
replay identity covers signed protected content and excludes the ECDSA signature;
re-signing cannot replace its original stored envelope. The ACK's full digest still
binds the exact packet persisted locally and submitted on this connection.

An acknowledged capture keeps its permanent receipt and sequence tombstones. Exact
duplicate finalization is idempotent under current authority; it cannot reseal,
recapture, allocate another event or restore a lease. Room migration adds a nullable
ACK digest without acknowledging or clearing any older pending bytes. Database
reopen does not restore admission or bypass the runtime's fresh phone review policy.

Scope and body use the existing inbound vault with distinct AAD domains binding
scope to interval / receipt and body to receipt token / capture identity. No new key
alias, browser root credential or network credential is introduced. Record string
representations redact the peer, body and protected contents.

The queue has a maximum of 128 pending protected bodies and 1024 permanent receipt fences.
Durably acknowledged uploads release body capacity without evicting receipt fences.
Content purge clears ciphertext and nonce while preserving event / receipt identity.
Full queues discard new bodies. Full receipt or closure-fence capacity fails closed;
it must not be repaired by evicting fences and replaying old SMS. Preparation reserves
closure capacity. Releasing body capacity does not remove the finite permanent fence
limit or establish a complete long-running retention product.

Source integration still requires the following release and operational gates:

- Physical-device verification of canonical installation, receipt, replay, cancellation
  and lifecycle behavior through the selected authenticated connection.
- Maintained content-crypto provider and actual signer / browser reader-key custody.
  Fixture crypto does not establish production custody.
- A single shared admission authority for pause, permission changes, line continuity,
  device lease, origin-session logout / expiry and authority rotation / revocation.
- Receipt HMAC key continuity: the existing vault's automatic key recreation must
  not let restored or replayed PDUs acquire new identities after key loss.
- Coordinated account export, retention worker, guarded deletion and backup handling
  for this separate local database. Its purge method is not a scheduled worker.
- Separate factual body-transfer disclosure and policy update before any content sync.

The legacy conversation router remains unmounted. This journal change does not
enable unrestricted history, general sending or hosted availability. JVM / Room tests
and APK compilation do not establish physical phone behavior, carrier delivery,
customer delivery, or Google Play exception approval.
