# Profile03 conversation consent

This additive source contract separates conversation content consent from phone pairing,
SEALED line approval, profile election, physical SIM refresh and reader readiness. None of
those earlier steps grants conversation sending, capture or transfer permission. Existing
ZTCA01/02 statements, domains and journals retain their meaning.

The Android shipping03 consumer requires the closed frames in
`conversation-interval03.schema.json`, a genuine current device selection, and the original
request accepted by the server with fresh owner authentication. A current manifest must
select the actual phone role4 and browser role5 content signers independently. The original
SEALED approval key and enrolled device signer do not substitute for those roles. When an
existing hardware alias actually matches the root-selected role4, it remains usable; the
consumer does not replace a missing or different key.

## Exact public statement

The header is `ZTCA || 03 || 03 || 03 || 00`. It is followed by:

1. Nine raw UUIDs: account, device, line, current binding, interval, receipt, owner user,
   original owner session and opening.
2. Eight positive big-endian u64 values: binding generation, vault generation, current
   manifest version, selection epoch, issue time, setup expiry, interval start and end.
3. Thirteen nonzero 32-byte values: physical reader, archive reader, phone signer, browser
   signer, root fingerprint, manifest digest, election commitment, election bundle digest,
   owner session digest, configured origin digest, full device session digest, independently
   verified physical-selection commitment and challenge nonce.
4. A one-byte length and exact ASCII `conversation-content03-v1`, the SHA256 of the disclosure
   below, a one-byte peer length and exact E.164 peer, then a one-byte integration count.
5. Zero to six mappings, each connector UUID, read-grant UUID and role3 key ID. They are sorted
   strictly by key ID, with each connector, grant and key independently unique.

Length is `692 + peer bytes + 64 * mappings`, between 695 and 1092. The signed start equals
the issue time. Setup lasts at most five minutes and the interval at most one day. The actual
owner session, device lease, manifest and selected key lifetimes further bound these times.
Setup expiry does not by itself end an already installed interval. A later manifest,
owner session, physical receipt or device lease requires another explicit ceremony.

The exact UTF8 disclosure is:

> With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately.

## Separate original signatures

All three use strict low-S raw64 P256/SHA256. `L(label,payload)` is ASCII label, a single NUL,
big-endian u32 payload length and exact payload. Received bytes are never normalized.

- Browser role5 request: `L(zrotext/conversation/request03/v1, statement)`.
- Phone role4 approval: `L(zrotext/conversation/approve03/v1, statement || SHA256(owner signature))`.
- Phone role4 installation: `L(zrotext/conversation/install03/v1, statement || SHA256(owner signature) || SHA256(phone approval))`.

The phone displays the peer, line, content signers, archive, deadline and disclosure. Each
additional reader is listed with its full key fingerprint, connector ID and read grant ID,
derived from the exact verified signed selection. An affirmative foreground action reserves the one-use approval phase before
hardware signing. A matching service approval commits its original time before a separate
one-use installation reservation and signature. Only the original matching install ACK can
issue the active RAM handle. Foreground loss, callback loss, missing custody or expired
authority refuses further setup. Every pause or display disposal permanently invalidates that
action's foreground ticket; resuming enables a fresh affirmative action without reviving a
blocked signing operation. A cold journal and a passive active status cannot issue a
handle. Explicit Retry sends only already durable original bytes, within the same live
pending ceremony and original setup window. Retry does not renew consent for unused hardware
signing. A lost signing outcome is never regenerated.
If the original approval ACK was committed locally but installation was never reserved, another
affirmative foreground approval can continue that unused installation phase. It cannot revisit
an installation reservation or replace an unknown signing result.

The separate interval Room journal uses the existing enrollment-provisioned AES-GCM key and
nonempty interval/statement AAD. It never creates or replaces that key. Peers and exact
statements/signatures are protected. Keyed scope commitments bind account, line, binding and
an existing-key sender MAC; the live scope additionally binds the full actual device session.
Every original row and receipt/nonce fence survives Stop and expiry, with no lifetime history
cap. Indexed counts bound live/unknown work to sixteen per exact live scope and genuinely new
allocations to sixteen per rolling day across connections for the same account/line/binding/
peer. The writer captures the original allocation time; exact retries never allocate or renew
it. This phone supports one outstanding signed/unknown/active ceremony per peer. A signed
setup timeout cannot free an interval that may already have been installed remotely; only
actual interval expiry or explicit local Stop permits another local reservation. The server
independently enforces its admission, management budgets and Stop transactions.

Stop withdraws the RAM handle before storage/network waits, durably retains a local stopped
row, and requests the distinct authenticated device Stop acknowledgement. It does not claim
that the service has acknowledged Stop until that exact response arrives. Retained encrypted
content has a separate deletion lifecycle.

## Current permission and effects

Every challenge, passive status and signed fetch includes a closed `interval_permission`.
Its request ID is the signed receipt for a challenge, the actual pending nonce for status,
or the signed grant attempt ID for fetch. Fetch requires all three original signatures and
times, exact active local journal evidence and the same live RAM installation. Original message
admission must be at or after the original installation time and no later than actual now. The selected
peer, owner session, signers, interval bounds and complete outbound recipient set must match
the reviewed intent. The after-wait maintained-recipient guard also checks an interval-specific
RAM withdrawal/deadline guard, without Room, framework or key access under custody.

Connector mappings require both direction bits12 in the actual current registry grant and
manifest role3. The closed sidecar carries actual mapping points, generations and row bounds.
A signed ID or manifest entry cannot supply the mutable server-record grant predicate.
Missing mappings or missing sidecars refuse, including an empty-reader interval's missing
sidecar. Status uses fresh correlation, at least 25 seconds between requests and at most64
requests per actual socket. It neither re-signs nor activates.

The synthetic vector includes separate enrollment, original SEALED, phone role4 and browser
role5 keys, original high-S v2 proof bytes, and both empty and mapped reader selections. It
proves public bytes/signatures only. Genuine browser role5 enrollment and current03 manifest
ancestry/renewal, actual server/SQL permission adapters, and profile03 inbound capture remain
separate integration prerequisites. This source contract and fixtures do not establish a
deployed service, Android hardware/provider acceptance, carrier delivery or release readiness.

## Ordinary enrollment storage observation

Enrollment uses public own-UID AppOps callbacks for SEND_SMS, RECEIVE_SMS and READ_PHONE_STATE,
actual subscription callbacks, and explicit selected-subscription preference invalidation.
Registration alone supplies no observation. Complete permissions/SIM/key checks run outside
Room and protected root storage, with an immutable captured callback epoch rechecked after
waits. Callback entry withdraws RAM tickets; restoring a mode cannot renew an old registration.

Raw app-operation modes are checked alongside actual runtime permission before and after each
read. ALLOWED and DEFAULT require a granted permission; DEFAULT delegates that normal check.
Raw foreground-only modes refuse because this enrollment observation does not establish a
continuing foreground-service/app-state entitlement. Unknown, ignored and errored modes refuse.
The public watcher is an invalidation source, not an atomic permission snapshot or a positive
permission grant. Runtime permission revocation process death is additional defense. Complete
outside validation and post-wait RAM fences remain mandatory. JVM framework callbacks and
synthetic proof tests do not establish a physical phone's permission or hardware behavior.
