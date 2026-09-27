# Sealed inbound identity and line-binding prerequisite

**Storage foundation only.** Migration 018 and `sealed_inbound::line_binding_ready`
do not enable sealed content, line enrollment, a customer API, a device frame, or
webhook delivery. They accept no HTTP or WebSocket body. The `ZTSE` profile-01
kind-02 byte prefix and length constraint is a storage guard, not a parser or
cryptographic verification. No production sealed-content claim follows.

## Dormant candidate-02 manifest persistence

Migration 042 adds an initially empty `sealed_manifest_authorities` table and
`sealed_manifest_store::admit` composes the candidate-02 manifest verifier with
the existing sealed line/session preflight. Neither has a production caller.
There is no root provisioning, reset, rotation or content-ingest API. A future
independently authenticated owner ceremony must establish the exact RootPin02,
fingerprint, generation and transition anchor; request bytes and the separate
SMS/line-approval keys are not a trust source. An absent or revoked authority
fails closed. This assumes trusted database storage and administrative access;
the verifier cannot authenticate an administrator's choice of initial pin.

The caller supplies a database transaction. Admission locks its account's
authority row first, then retains the preflight's account, device, enrolled key,
site, deployment authority, session, line and binding locks through transaction
completion. Revocation and rebinding writers serialize against those locks.
Database wall time is sampled after lock waits. A transaction may advance only
one linked version or replay the same current unsigned semantic digest; a fork,
gap, rollback, expired manifest, wrong tenant or regressing database time fails.
Replay preserves the originally stored signed bytes and original acceptance
time. A fresh next version may follow an expired predecessor, whose signature
is reverified at its recorded acceptance time. The monotonic database-time
high-water is retained through restarts. It detects clock rollback, not a
malicious or incorrectly advanced database clock.

The returned non-cloneable `Admission` borrows the transaction. Its `context`
method requires inbound kind and the same account/device/line, checks the live
session, current authority and manifest/key freshness again, and constructs the
exact expected envelope context. It exposes no unfenced manifest getter. A
future caller must verify the exact signed envelope, enforce event/sequence
identity and perform all effects in this transaction, calling `context`
immediately before those effects and commit. The caller must roll back on any
error. This does not guarantee a lease remains valid through arbitrary caller
delays; it is not a substitute for future ingest's final atomic acceptance
contract. The table permits account-erasure cascades and has no delete trigger;
deleting authority cannot bootstrap replacement trust through this API.

This layer does not change the existing profile-01 sealed-event storage guard,
resolve the candidate inbound segment-count contract, journal phone events,
insert ciphertext or mount a route. Candidate-02 remains a proposal, and no
sealed release gate is closed by this persistence prerequisite.

## Dormant candidate-02 ingest transaction

`sealed_inbound::ingest::ingest_candidate02` composes that authority admission
with exact candidate-02 envelope verification and durable insertion. It owns
its transaction through commit; an error rolls back a staged manifest advance
as well as any event insertion. No HTTP/WSS route calls it, and it performs no
webhook, outbound dispatch, grant or SMS operation.

The bounded parser supplies untrusted event, peer and reader selectors. The
authenticated session and current database binding supply account, device and
line authority; the independently pinned manifest authorizes the signer and
readers, and exact signature verification binds the selectors to the received
bytes. Only then can the transaction store the original envelope and its
unsigned semantic digest. Observed time must be positive, at most seven days
old and no more than five minutes ahead of database wall time. There is no
device-clock-offset rewriting. It accepts out-of-order sequences within that
window, but never reuses an accepted device sequence for a different event.

Every replay passes these same current authority, signature, session and age
checks. An expired or superseded original manifest, revoked signer or session,
or event older than the window is rejected even if its tombstone exists. A
fresh manifest cannot authorize an envelope naming an old version/digest. A
valid identical unsigned replay returns `created=false`, preserving the first
signature, original binding generation and timestamps. It never restores
ciphertext removed by retention. Conflicting event IDs, profile changes and
reused sequences fail; no foreign account's content is read. The transaction
rechecks event age and manifest/session authority after insertion or replay-row
lock waits, immediately before commit.

Migration 043 retains an immutable `envelope_profile` beside each tombstone.
Existing profile-01 constraints remain unchanged. Candidate-02 rows use
`part_count=NULL`, explicitly unknown: the signed format has no segment-count
field, and the relay cannot infer it from ciphertext. The existing purge-only
update guard still permits only removal of the envelope, preserving all replay
identity and profile metadata. Content pruning does not delete tombstones.

Production use still requires independently authenticated root provisioning,
an explicit device-authenticated transport adapter, bounded ingress/storage
budgets, and Android production manifest trust, event/sequence journaling,
multipart and ambiguous-SIM handling, signing and upload. Existing Android
test-only vectors and dormant recipient primitives do not establish those
properties or physical-phone interoperability. No sealed runtime gate is enabled.

## Distinct source identity

The current [M1 inbound pilot](inbound-foundation.md) signs an outbound
`message_id` and `attempt_id` and requires positive sent-callback evidence from
the same device. That contract correlates metadata to a known outgoing SMS.
It cannot represent an unsolicited received SMS, and it cannot accept the
candidate sealed kind-02 envelope's `message_id = event_id` rule.

The candidate sealed inbound identity has one stable `event_id` allocated and
journaled on the phone before encryption. Its protected `message_id` copies
those same 16 bytes, and `local_sequence` is a positive, durable counter for
that device's sealed inbound stream. Retries preserve the exact event ID,
sequence, signed envelope bytes,
and unsigned digest. The separate `sealed_inbound_events` table uses the event
ID as its primary key and `(device_id, device_sequence)` as a replay fence. It
has no foreign key to `messages`, `message_attempts`, or M1
`webhook_deliveries`. A future ingest must compare the saved unsigned digest
on event-ID replay, return a no-op only for identical signed content, and
reject changed content or a reused sequence. No future implementation should
route kind-02 bytes through the M1 inbound pilot to satisfy its source check.
Retention must keep an ID/sequence replay tombstone for the full accepted
upload window after any ciphertext purge. The current schema permits deletion
of sealed events for future retention work; deleting a row without a separate
durable event-ID and device-sequence high-water fence would permit a replay.

## Stable line identity

`phone_lines.id` is an owner-assigned UUID within an account. It is not a
mutable Android `subscription_id`, SIM slot, phone number, ICCID or IMSI.
`device_line_bindings` connects one line to one device and a monotonically
increasing binding generation. New rows start `pending`; no activation API
exists. The database permits at most one active device binding per line,
rejects generation rollback and revoked-row resurrection, and refuses sealed
event inserts unless the line and binding are active at the current generation.
Line and binding rows cannot be deleted and recreated to reuse an old
generation; a future account-erasure procedure needs an explicit migration.
The server preflight also requires a current writer session, live lease,
unrevoked enrolled key/device, enabled account/site and matching deployment
epoch. The insert trigger locks the active line and binding, so a revocation
cannot race past storage after the preflight query returns.
The trigger does not check the writer session. A future ingest must run its
session preflight and insert in the **same database transaction**, retaining
the session row lock until commit, or recheck the session under lock inside the
insert transaction. Calling the current helper in autocommit mode and then
inserting later is insufficient against session fencing.

The approval and device-confirmation digest columns are audit anchors. Their
presence alone does **not** prove that the physical SIM was identified or that
either party signed a valid statement; SQL fixtures can populate them. A
future enrollment flow must source a trusted owner key, show the owner the
selected line and device, and reject ambiguous or changed multi-SIM
observations. A phone must block sealed send/reply if it cannot unambiguously map
its selected local subscription to the currently approved `line_id` and
generation. A different local subscription index must not silently inherit
the binding. The founder's sealed-mode device floor is Android API 31+; the M1
gateway keeps its existing API range.

[Migration 019 and the internal activation transaction](line-activation-contract.md)
add exact signed proof bytes, a one-use challenge, and atomic generation
activation. They have no HTTP/WSS caller and no trusted owner-key bootstrap or
Android observation implementation. Their single-active-subscription rule is
an interim fail-closed rule for virtual contract testing, not proof of which
physical SIM is present. The original digest columns remain audit anchors;
direct SQL fixtures can still bypass application verification. No sealed
content route or product claim follows.

Migration 019 tracks the last **issued** generation separately from the
currently active generation. A missing pending device can be superseded and
its generation burned without interrupting the old active binding. A late
proof for the superseded generation is rejected.

## Dormant envelope verification prerequisite

The server library's [sealed envelope module](../../crates/server/src/sealed_envelope/mod.rs)
provides bounded candidate parsing and exact-byte P-256 signature verification.
It requires explicit proof-only draft-01 or candidate-02 selection, and checks
caller-supplied account, message, device, line, keyset version, manifest digest,
peer, signer and exact ordered recipient set. Its result includes the SHA-256
unsigned-envelope digest; its constructor is private, and debug output omits
identifiers and envelope bytes. Draft-01 interoperability keeps the pinned
high-`s` fixture valid with its `ZTSE/sign/v1` transcript; candidate 02 uses
the distinct `ZTSE/sign/v2` transcript and rejects high-`s` signatures. The
[pinned Web Crypto signature-only vectors](vectors/ztse-draft-02-signatures.json)
cover both envelope kinds and reject the old signature domain. Their opaque
ciphertext is structural test data, not a decryptable candidate-02 vector.

No route calls this module. The expected context must come from independently
verified owner-pinned manifest authority, not the received envelope or an
untrusted relay directory. A successful signature does not prove manifest
freshness, active line generation, session/grant validity, replay safety, HPKE
or body authentication, or permission to store, decrypt or send. The live
transactional checks and the remaining Q1-Q11 evidence are still required.

## Dormant manifest authority prerequisite

The Rust [`sealed_manifest`](../../crates/server/src/sealed_manifest/mod.rs)
module verifies bounded, exact RootPin02 and Manifest02 bytes against an
independently authenticated account/root fingerprint and explicit chain position.
It checks the owner signature, low-`s` canonicality, complete role/scope/subject
matrix, key IDs and unique points, root/archive cardinality, and signed freshness
window. The immutable result can derive a candidate-02 envelope context for an
active line-bound outbound signer or device-and-line-bound inbound signer, plus
exactly the selected authorized readers. No reader is added implicitly. Key
validity and manifest freshness are checked again at context construction.

The caller must supply trusted time and a chain position derived from durable
owner-authenticated state: initial generation genesis requires a zero anchor;
later generations require a nonzero, independently verified transition anchor.
Advancement requires the next version and previous semantic digest, and reuse requires the
exact current semantic digest. This API does not bootstrap trust, accept root
transitions, persist a high-water mark, detect clock rollback, or perform an
atomic compare-and-set. Persisting trust advances and rechecking current authority
before effects remain mandatory. Constructing a context is not live admission;
callers must immediately verify the exact envelope signature and enforce the
transactional checks below. No HTTP/WSS route uses this module.

Existing independent Python-generated genesis/rotation manifest vectors exercise
the reusable verifier; rotation-signature verification remains a test-only proof.
Signed authority tests cover both envelope kinds, revoked/expired/future keys,
wrong subjects and scopes, missing/duplicate/unapproved readers, changed bytes,
wrong pins, stale manifests, rollback, chain gaps and same-version forks.

## Required next ingest gate

Before any sealed route can write `sealed_inbound_events`, it must bound and
parse the complete exact binary profile, verify the owner-pinned manifest
chain and allowed device signing key/scope, verify the device signature over
the exact unsigned bytes, and compare protected account/device/line/event,
sequence, timestamps and manifest digest with the authenticated session and
database state. It must reject plaintext JSON, unknown profile or kind,
missing line proof, altered bytes, stale/revoked keys, duplicate conflicts,
and any fallback to the synthetic alpha or M1 metadata pilot. The client must
durably journal the normalized multipart SMS, event ID and sequence before
upload, and must keep local body content out of relay logs and errors.
Webhook fanout needs a distinct event/delivery contract and ciphertext-only
payload; the existing M1 webhook table references only `inbound_events`.

The current migration constrains candidate envelope size and the six-byte
`ZTSE`/profile/kind prefix only. An internal SQL writer with database access
can insert a forged binary fixture after synthetically activating a line; the
schema does not establish encryption or device signature validity. No
application route writes this table today.
