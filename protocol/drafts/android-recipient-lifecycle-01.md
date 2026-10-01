# Android recipient custody lifecycle (candidate)

**Implemented local fence, unresolved production receiver decision.** This
change strengthens the dormant `DevicePayloadKeyStore`; it enables no sealed
route, provider, grant or radio operation. Q5 remains open.

## Required profile and provider gate

Issue #625 requires the exact P-256/HKDF-SHA256/AES-128-GCM wrap profile with
distinct, nonempty HPKE `info` and AAD and a non-exportable API 31+ Keystore
recipient. That requirement is preserved. The existing profile-02 public-JCA
candidate uses empty HPKE AAD, so its candidate support choice does **not**
satisfy this production gate. A known-answer pass, reported hardware level or
the lifecycle fence below cannot approve that receiver or change the profile.

No maintained receiver satisfying the complete requirement is selected by this
PR. The existing [provider study](zt-009-android-provider-study.md) evaluates
bounded implementation paths; the [profile-02 candidate](draft02-android-recipient-provider.md)
remains useful for isolated feasibility tests. A reviewed provider decision
meeting the required profile, or an explicit separately reviewed new-profile
decision with regenerated cross-client vectors, is still required. The live
sealed gate stays closed. No `info`/AAD, crypto transcript, suite or SDK floor is
changed here, and no software private-key fallback is introduced.

## Persisted state

`DevicePayloadKeyStore(context, alias)` now uses a bounded public lifecycle record
in the application's no-backup directory. The filename is a hash of the bounded
ASCII alias; the record contains only a version, state and, once enrolled, a
32-byte public key ID. Private keys, ECDH secrets, CEKs, roots, grants and message
content never enter this record. The existing Android Keystore origin, purpose,
size, non-exportability, point and reported security-level checks still run on
every load. A reported security level is not independent hardware attestation.

| State | Explicit enrollment | Existing lookup/ECDH |
| --- | --- | --- |
| Absent, no alias | Persist pending, generate once, validate, commit bound ID | Refuse |
| Absent, alias exists | Refuse unregistered identity; never silently adopt it | Refuse |
| Pending | Refuse interrupted enrollment; never retry generation automatically | Refuse |
| Bound | Reload and compare original ID; never generate | Require stored ID, current point and caller's pinned ID |
| Revoked | Refuse, even if the alias has been deleted | Refuse |

The pending record is committed **before** any generator call. Failure during
generation, validation or bound-record publication leaves that fence in place.
A successful repeated enrollment call returns the same validated identity. A
missing bound alias, changed public point, malformed/oversized/unknown metadata,
missing metadata alongside an existing alias or failed persistence stops the
operation. No receive, reboot/reload or reenrollment path creates a replacement
for an enrolled, pending or revoked identity.

Metadata writes sync a same-directory temporary file and require
[`Files.move`](https://developer.android.com/reference/java/nio/file/Files)
with atomic replacement, followed by bounded readback verification. An
unsupported atomic move fails closed; no non-atomic fallback is supplied.
An interrupted first write without a committed record also fails closed. Any
remaining replacement file refuses further use or enrollment, including an
interrupted revocation beside an older bound record. A shared
process mutex and an OS file lock cover the entire enrollment/private operation
and local revocation. Filesystem replacement alone supplies no locking.
This serializes separate key-store instances and processes using this adapter:
enrollment generates at most once, and local revocation linearizes before or
after a complete ECDH operation. It cannot retract a secret already derived
before revocation; the authorized caller must still enforce current grants,
freshness, replay and journal fences before using a CEK.

`revokeExisting(pinnedKeyId)` persists a local denial tombstone and is idempotent
for that exact ID. It grants no server/root permission, does not delete historical
authority or ciphertext, and does not claim to revoke a server manifest. No
production reset, adoption or tombstone deletion API is supplied. Recovery from
pending/lost/revoked state requires a separately authorized new enrollment/key
identity and current root-signed grant; it is not an automatic fallback.

## Identity and data loss

The key ID remains `SHA256("ZTSE/key/v1\0" || 0x0010 || uncompressed_P256_point)`.
Browser/SDK/server provisioning must use the same independently pinned root and
current manifest/device-role key ID. Local metadata is not RootPin02 enrollment,
root comparison, a grant, a freshness proof or an attestation. An independently
pinned manifest must reject a replacement after key loss or application reset.

The no-backup record and Keystore alias have different lifetimes. Deleting an
alias alone keeps the bound/revoked fence. Removing metadata alone cannot adopt
the remaining alias. Removing **both** the app data and key can erase local
historical knowledge; a fresh explicit enrollment may create a new identity,
but cannot inherit the old independently pinned identity or grants. Platform
data clearing, uninstall, device replacement and rollback protection still need
their separately authorized physical/client drills. This record is not a
tamper-proof or rollback-resistant history against an actor controlling app
storage/UID. Existing server/root authority remains necessary.

Retention is the local account/app lifetime; local key loss does not erase old
message ciphertext or make it decryptable. Exporting the public ID is not key
backup. Test-source cleanup removes only owned synthetic fixtures, never a live
identity's tombstone.

## Verification and remaining gates

JVM tests cover durable reload, corrupt/oversized/version/state metadata,
pending-before-generation, interrupted publish/generation, one-winner concurrent
enrollment, substitution/pin rejection, loss without regeneration, sticky local
revocation and operation/revocation ordering. Android instrumentation extends
the actual Keystore identity/non-exportability/key-loss tests with repeated
enrollment refusal and persisted revocation. Existing candidate known answers
and changed `info`/AAD/point/profile/key rejection corpora retain their original
profile; they are not acceptance evidence for a different profile.

No physical lifecycle, actual reboot/process-kill, independently attested
hardware, API-31 device matrix or maintained exact-profile production receiver
approval is claimed. The provider/profile decision, Android/SDK/server exact
receiver acceptance and independently controlled provisioning evidence remain
release gates. API 28–30 remain ineligible for sealed key operations.
