# Dormant conversation capture journal

The Android conversation journal is a separately defined Room database and domain
component. No production code opens it, receives SMS into it, or sends its records.
It is tested with synthetic signed activation responses and an ephemeral AES-GCM
fixture vault. It does not implement the server activation / phone ACK transport.

An affirmative phone approval prepares an encrypted exact scope: account, device,
line and binding generation, selected peer, interval and receipt identities,
originating browser session, disclosure digest, exact reader key, trust generation,
original activation version / digest and activation transcript digest. Preparation
alone cannot capture. The verifier interface has no production implementation and
must validate approved manifest provenance, exact ACK identity and server-installed
state before accepting an active response.

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
The future receiver integration must stop admission and avoid redispatching uncertain
backlog after such a failure.

Captured records retain their original interval, activation provenance, durable event
identity and first receipt times. Retries decrypt that exact record and require the
same currently authorized interval. They do not reassign an interval, refresh capture
time, rewrite provenance or reseal old content. Local close synchronously clears
admission and pending recovery before persisting an irreversible closure fence.
It retains ciphertext; withdrawal and content deletion are separate operations.

Scope and body use the existing inbound vault with distinct AAD domains binding
scope to interval / receipt and body to receipt token / capture identity. No new key
alias, browser root credential or network credential is introduced. Record string
representations redact the peer, body and protected contents.

The queue has a maximum of 128 retained bodies and 1024 permanent receipt fences.
Content purge clears ciphertext and nonce while preserving event / receipt identity.
Full queues discard new bodies. Full receipt or closure-fence capacity fails closed;
it must not be repaired by evicting fences and replaying old SMS. Preparation reserves
closure capacity. These bounds describe a simulator primitive, not a complete
long-running retention product.

Before integrating with the existing Android receiver, service or shared database,
coordinate file ownership and complete the following gates:

- Canonical server acceptance / phone installation ACKs, signed authority validation,
  exact replay / cancellation semantics, and authenticated active-state recovery.
- Existing owner-controlled signer adapter and actual browser reader-key possession.
  Fixture signers do not establish production custody.
- A single shared admission authority for pause, permission changes, line continuity,
  device lease, origin-session logout / expiry and authority rotation / revocation.
- Receipt HMAC key continuity: the existing vault's automatic key recreation must
  not let restored or replayed PDUs acquire new identities after key loss.
- Coordinated account export, retention worker, guarded deletion and backup handling
  for this separate local database. Its purge method is not a scheduled worker.
- Separate factual body-transfer disclosure and policy update before any content sync.

The legacy conversation router remains unmounted. Continuous-history authority,
server provenance persistence, browser rendering and exact user-confirmed sending
remain separate work. JVM / Room tests and APK compilation do not establish physical
phone behavior, carrier delivery, or Google Play exception approval.
