<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ADR 0007: Outbound MMS and attachment support decision

Status: proposed and unapproved. This is a decision proposal for review. It
approves no activation, no radio attempt, no product capability, no roadmap
stage and no release exposure, and it changes no code or settings.

## Decision proposal

Keep the merged outbound MMS spike as a controlled debug probe. Do not promote
MMS or attachments to a product capability now, and do not drop the probe.
Revisit promotion through a separately reviewed proposal only after every
condition in [Conditions before any promotion](#conditions-before-any-promotion)
is met. The README and roadmap remain unchanged: MMS is not a capability, and
this decision does not make it one.

## What the spike proved

The stage-one probe merged as a debug-only device tool with a founder-gated
server grant, and the [device testing guide](../ANDROID-TESTING.md) documents
its boundary. The work that did land is real:

- **Gating chain.** Debug build only; a default-empty build-time recipient
  allowlist; an in-memory operator confirmation armed for five minutes; a
  solicited server grant bound to the device, connection epoch and recipient
  digest with a 30-second server TTL
  ([`mms_spike_policy.rs`](../../crates/server/src/device_socket/mms_spike_policy.rs))
  and a 35-second client ceiling; a keyed STOP lookup before the gate is spent
  and again at the radio boundary; and a durable one-use client gate committed
  before any possible radio call
  ([`MmsSpikeSend.kt`](../../android/app/src/debug/java/org/zrotext/gateway/MmsSpikeSend.kt)).
  The server issues at most one grant per device and recipient per 90 days and
  withholds it while the recipient is suppressed or under an unreleased owner
  hold ([`device_socket/mod.rs`](../../crates/server/src/device_socket/mod.rs),
  `mms_spike_grant_if_due`).
- **PDU privacy hygiene.** The plaintext recipient and subject exist in a
  temporary PDU file only while the platform may read it; it is deleted on the
  sent callback, the timeout, a throw and every pre-radio exit, with an orphan
  sweep for a dead process. The journal stores fixed result codes only, and a
  test scans the whole app data directory for recipient or subject leakage.
- **A minimal, vector-pinned composer.** The `m-send.req` byte layout mirrors
  AOSP's composer with a golden-vector test, and the attachment is a synthetic
  1x1 PNG built in code, so no pasted binaries
  ([`MmsSendComposer.kt`](../../android/app/src/main/java/org/zrotext/gateway/MmsSendComposer.kt)).
- **Honest local states.** A recorded platform-call return is `submitting`; a
  successful sent callback is `submitted`; an error callback is `failed`;
  a timeout, throw or conflicting terminal evidence is `unknown` and is never
  retried automatically
  ([`MmsSpikeJournal.kt`](../../android/app/src/main/java/org/zrotext/gateway/MmsSpikeJournal.kt)).

## What the spike did not prove

- **No physical device and no carrier.** Whether the platform MMS service can
  read the FileProvider URI, and whether any carrier MMSC accepts the PDU, are
  explicitly recorded as open device findings
  ([ANDROID-TESTING.md](../ANDROID-TESTING.md), "Outbound MMS spike"); the
  merging pull requests state "no physical device, no emulator, no radio" and
  "no real SMS/MMS sent".
- **The journey is inert today.** The server issues a grant only in answer to
  the solicited `mms_spike_ready` frame
  ([device-stream.md](../../protocol/v1/device-stream.md)), and the merged
  Android client never sends that frame — no producer exists in the Android
  tree. Arming alone therefore cannot complete a send, in debug or release.
- **No attachment path of any kind.** The content is a fixed synthetic image;
  owner-authored media has no protocol envelope, storage, metering or delivery
  contract anywhere in the stack.
- **No size or carrier limits measured.** The composer's 300,000-byte image
  cap and 64-character subject bound are probe-local validation
  ([`MmsSendComposer.kt`](../../android/app/src/main/java/org/zrotext/gateway/MmsSendComposer.kt)),
  not carrier ceilings.
- **No delivery-report behavior.** The probe requests no MMS delivery report,
  and this platform send path exposes only a sent callback whose reliability
  depends on the MMSC transaction.

## The content-sealing boundary is the blocking gap

The sealed-content design is text-only end to end:

- The relay admits opaque ciphertext and binds each grant to the SHA-256 of
  the exact admitted bytes; the grant frame carries no body or recipient
  ([sealed-dispatch.md](../../protocol/v1/sealed-dispatch.md)).
- On the phone, the envelope is opened only under a one-use grant through a
  non-exportable Keystore HPKE key
  ([`SealedDispatchExecutor.kt`](../../android/app/src/main/java/org/zrotext/gateway/SealedDispatchExecutor.kt)),
  and the opened plaintext must be strict UTF-8 text of 1..32,768 bytes with
  no BOM or NUL
  ([`SealedPlaintextRules.kt`](../../android/app/src/main/java/org/zrotext/gateway/SealedPlaintextRules.kt)),
  reproduced as one through six SMS segments via `divideMessage`
  ([`Draft02OutboundPreparation.kt`](../../android/app/src/main/java/org/zrotext/gateway/Draft02OutboundPreparation.kt),
  [candidate preparation notes](../ANDROID-SEALED-PREPARATION.md)).
- Binary media has no representation in that contract: protocol v1 defines no
  attachment envelope at all.

The MMS probe sits outside all of it. The PDU is composed on the phone with a
plaintext recipient, subject and image — the raw image bytes are written
directly into the `m-send.req` body — and handed to the carrier MMSC, which
reads it in clear ([`MmsSendComposer.kt`](../../android/app/src/main/java/org/zrotext/gateway/MmsSendComposer.kt)).
Nothing seals an attachment today, and sealing stored or relayed media would
still not encrypt the carrier leg.

Promoting owner-authored MMS attachments now would force one of two
unacceptable choices: route attachment bytes through the hub and storage
unsealed, defeating the sealing invariant that keeps message content away from
the relay, or keep content synthetic-only, which is a probe, not a capability.
An attachment envelope with its own sealing design — bound content type and
size, key and reader scope, chunking, and the MMSC size interplay — is
therefore a hard prerequisite for any promotion. This is the main reason the
recommendation is not "promote".

## Size and carrier limits are open validation items

The probe's bounds are probe-local; they are not policy. Real MMS size
ceilings are carrier-specific and were never measured, and PDU overhead
(headers, subject encoding, multipart framing) consumes the budget before the
media does. MMSC and APN resolution behavior is likewise unmeasured: the probe
passes a null location URL, so the carrier default MMSC is used, and whether
that resolves on real networks is an open device finding. A future promotion
proposal must present per-carrier measured ceilings and error codes from
controlled devices as evidence; it must not assume a universal number.

## Compliance wording required before any promotion

If a future proposal promotes MMS, [SMS-COMPLIANCE.md](../SMS-COMPLIANCE.md)
must gain, at minimum, wording along these lines. The file itself is unchanged
by this ADR; this is the proposed text, to be applied in the same change as
any promoted behavior:

- "MMS messages are subject to the same consent, withdrawal and sender
  identification duties as SMS. An attachment is part of the message for
  consent purposes: permission to text a number is not permission to send it
  media."
- "Sending media raises content-lawfulness duties beyond text. You need an
  appropriate basis for the media itself, and you, not ZROtext, are
  responsible for it."
- "Check your carrier's MMS terms, size limits and registration requirements
  for your route separately from your SMS plan; consumer-plan and A2P
  restrictions can differ between SMS and MMS."
- "The restricted pilot offers no general send API of any kind. Do not connect
  MMS sending to a marketing or bulk messaging workflow."

## Honest delivery-state mapping for MMS

Any promoted MMS path must map onto the existing states in
[DELIVERY-STATES.md](../DELIVERY-STATES.md) without inventing new ones:

The probe's `pending` journal value records incomplete local evidence; it is
not a new product delivery state.

- Grant accepted and the durable one-use gate spent: the journal remains
  `pending` while its only recorded event is `composed`. Spending the gate
  does not establish that the platform call returned.
- A platform-call return recorded as `call_returned`, without terminal
  evidence: `submitting`. Missing return evidence does not prove that no
  radio action occurred and never authorizes an automatic retry.
- Sent callback OK: `submitted`. For MMS this means at most that the MMSC
  transaction reported success, which is weaker evidence than the SMS sent
  callback; it must never be displayed as delivered.
- Sent callback error: `failed`. Absent callback, a throw after a possible
  radio action, or conflicting terminal evidence: `unknown`, never retried
  automatically.
- `delivered` must remain unreachable for MMS on this send path. The platform
  exposes no delivery callback for `sendMultimediaMessage` and the probe
  requests none, so the honest ceiling today is `delivery_unknown`, unless a
  separately designed, carrier-dependent delivery-report mechanism is itself
  proven on controlled devices.

## Conditions before any promotion

1. Controlled physical-device evidence: the platform reads the FileProvider
   URI, at least one carrier MMSC accepts the composed PDU, and measured size
   ceilings and error codes are recorded as findings.
2. A reviewed attachment envelope design with sealing — bound content type and
   size, key and reader scope, opaque storage, export and erasure — and its
   device-stream, API and webhook contracts.
3. Attachment retention, reachable encrypted object storage and replication
   checks satisfying the
   [multi-location prerequisites](../MULTI-LOCATION.md), before any MMS
   high-availability claim.
4. The compliance wording above (or better) applied in the same change as the
   promoted behavior.
5. A delivery-evidence design that states plainly which MMS outcomes can and
   cannot claim `delivered`, per the mapping above.
6. The solicited ready-frame producer, if the probe itself is to function as a
   test instrument.
7. Metering, reservation and refund semantics, and the inbound-MMS receiving
   role and its default-SMS-app constraints, decided separately.

## Rejected alternatives

- **Promote now.** No carrier acceptance evidence, no attachment sealing path,
  no delivery honesty and no compliance wording exist. Rejected.
- **Drop the probe.** It would discard an audited, default-off, currently
  inert harness whose gating, STOP and PDU-hygiene properties any future
  attachment work would have to rebuild. Its residual risk is contained by the
  debug-only source split, default-empty allowlists and the missing
  ready-frame producer. Rejected.
- **Promote the probe while keeping content synthetic.** A synthetic-only
  sender is not a capability, and documenting it as one would make the README
  untruthful. Rejected.
