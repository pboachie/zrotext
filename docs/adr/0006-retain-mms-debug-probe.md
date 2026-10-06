<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Retain MMS as a controlled debug probe

Status: Proposed

## Proposed decision

Retain the existing outbound MMS probe in the debug source set. Do not promote
it to a product attachment API or remove it as part of this decision. This
proposal does not approve activation, a radio attempt, release exposure, carrier
support, group messaging or inbound MMS.

The [device testing guide](../ANDROID-TESTING.md) describes the existing probe
and its limits. Closing the original tool issue establishes neither physical
carrier acceptance nor a product delivery guarantee.

## Current boundary

The [debug sender](../../android/app/src/debug/java/org/zrotext/gateway/MmsSpikeSend.kt)
composes a synthetic PNG into a plaintext MMS PDU for Android's platform service.
The recipient and subject are plaintext in that temporary PDU; it is not a
sealed attachment envelope. The local journal records identities and fixed
result codes, without recipient, subject or media. Callback, timeout and
pre-radio cleanup paths attempt to remove the PDU, with orphan sweeping after
process loss. This is not a new content-retention guarantee.

The [composer](../../android/app/src/main/java/org/zrotext/gateway/MmsSendComposer.kt)
currently bounds image data to 300,000 bytes and subject length to 64 Kotlin
string units. These are probe validation bounds, not a total-PDU size limit,
carrier acceptance measurement or approved product attachment policy.

The probe checks debug mode, selected SIM, build allowlist, exact local recipient
confirmation, a current device/epoch-bound grant and local STOP suppression.
The server's [spike policy](../../crates/server/src/device_socket/mms_spike_policy.rs)
is default-off and restricts grants to one configured device and allowlisted
recipients. The authenticated stream checks suppressions and unreleased owner
holds and uses the existing server-side one-use budget. The phone commits its
per-installation attempt gate before a possible radio call.

The [spike stream contract](../../protocol/v1/synthetic-alpha-stream.md) requires
a solicited `mms_spike_ready` before a grant. The maintained Android probe has an
arm and grant consumer, but does not yet produce that ready frame; arming alone
therefore does not provide a working end-to-end send journey. Completing that
controlled probe prerequisite requires separately scoped implementation and
verification. It does not authorize product promotion.

Release entry points reject the grant and draw no MMS section. The receiver,
file provider and platform MMS call are debug-only. This proposal preserves
those boundaries and the current default-off settings.

## Honest outcomes and carrier evidence

The [journal](../../android/app/src/main/java/org/zrotext/gateway/MmsSpikeJournal.kt)
maps `SENT_OK` to `submitted`, not delivered. A returned platform call alone is
`submitting`; timeout, a throw after possible radio action and conflicting
terminal evidence remain `unknown`. Unknown does not authorize automatic
resend, including after reconnect or process recovery.

Composition, JVM/Robolectric boundary checks and server socket tests cannot
prove that a physical platform service can read the FileProvider URI, that a
carrier MMSC accepts the PDU, or that the recipient receives it. Per-carrier
physical findings remain prerequisites. Carrier/APN behavior, subject handling,
size limits and result interpretation need explicit controlled-device evidence;
no universal carrier limit or delivery-receipt reliability is inferred here.

## Conditions before a product proposal

A separate product design must define an attachment envelope and device-stream,
API and webhook contracts, authenticated content/type/size bindings, key and
reader scope, opaque storage, access control, export and erasure. Sealing stored
or relayed content does not make the eventual carrier MMS payload end-to-end
encrypted. The existing sealed-text profile is not attachment authorization.

Attachment retention, reachable encrypted object storage and replication checks
must satisfy the [multi-location prerequisites](../MULTI-LOCATION.md) before
MMS high availability is claimed. Metering, reservation/refund and unknown
outcomes require explicit contracts rather than reuse of SMS counts by assumption.

Apply the existing [compliance boundary](../SMS-COMPLIANCE.md): appropriate
purpose-specific consent, withdrawal, recipient holds and current send fences
remain necessary. General activation and media-specific content handling need
review; this proposal adds no consent rule, carrier permission or release gate.

Inbound MMS needs a separate design and role decision. Android restricts
[`WAP_PUSH_DELIVER_ACTION`](https://developer.android.com/reference/android/provider/Telephony.Sms.Intents#WAP_PUSH_DELIVER_ACTION)
to the default SMS app; the distinct `WAP_PUSH_RECEIVED_ACTION` notification
can reach registered receivers. These are different receiving boundaries, not
proof that every inbound path requires the default role. The current passive
SMS capture and outbound probe approve neither a changed messaging role nor its
user experience.

Future product verification should cover malformed or substituted attachment
bindings, cross-account retrieval, revoked keys/consent, expiry, missing or stale
replicas, export/erasure, dropped acknowledgments and conflicting outcomes
without resend. Release exclusion and controlled physical carrier acceptance
remain separate checks. These are proposed cases, not executed results.
