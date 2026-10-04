# Compared-root persistence

`Draft02RootComparison`, `Draft02TrustStore` and `Draft02AtomicRootStorage` are
candidate-02 building blocks used by explicit Android conversation enrollment.
`ConversationAndroidEnrollment` and the foreground setup screen bind enrollment
to the current selected account/device context. They accept only generation-one
root pins; comparison and persistence alone grant no sealed send or receive authority.

The comparison controller accepts an exact 94-byte root pin bound to a separately
selected account. It displays the full domain-separated SHA-256 fingerprint and
requires a separately supplied full fingerprint plus deliberate human confirmation.
The resulting receipt is single-use and cancellation invalidates it, including
before a pending atomic commit. The foreground enrollment session cancels on
backgrounding or selected-context loss and requires a separate comparison input.
Equal strings do **not** prove that a human compared independently obtained values.
This module provides no scanner, UI, owner-signing-key ceremony or trust bootstrap.

## Persistence and custody

The adapter stores one bounded AES-256-GCM record containing the exact public pin,
manifest bytes, local revision and last admission time. It stores no message body,
SIM identifier, private owner key or integration secret. Associated data binds a
versioned purpose, application package and local namespace. Its dedicated alias is
separate from existing device signing, recipient, inbound-vault and journal keys.

Key creation is available only during explicit fresh enrollment. Reads never
create or replace keys. API 31 or later and platform-reported TEE or StrongBox
custody are required, together with generated, nonexportable AES-256 key properties.
Software, unknown custody and incompatible keys return `Unsupported`; there is no
software or alternate-alias fallback. This policy is a local platform assertion,
not remote attestation or a solution to release signing-key custody.

The file lives in a dedicated `noBackupFilesDir` directory. A canonical-path monitor
and separate OS file lock serialize the whole read/verify/compare/write operation
across cooperating instances and processes. `AtomicFile` writes preserve an old or
new complete record; data is explicitly synced before the final cancellation or
freshness check and rename. An interrupted enrollment that already created its key
requires recovery rather than silently re-enrolling. A failed finalization can leave
either complete version and returns an error, requiring a fresh inspection.

Android excludes `noBackupFilesDir` from its backup system. `AtomicFile` itself does
not provide locking; the adapter supplies it. These are platform properties, not a
claim that privileged file copying or device rollback is impossible.
See [Android backup](https://developer.android.com/identity/data/autobackup),
[AtomicFile](https://developer.android.com/reference/android/util/AtomicFile) and
[Keystore custody](https://developer.android.com/privacy-and-security/keystore).

## Admission and failure states

Every successful load returns `NeedsFreshness`, including a cold start or reboot.
It does not return a usable message authority or grant. Genesis enrollment stores
version zero with no manifest and no inferred OS-clock checkpoint. Manifest admission
requires an exact snapshot comparison under the storage lock, the pinned root and
account, and a caller-supplied independently trusted current time. It verifies the
same semantic version or exact successor and rechecks freshness after blocking
writes, before commit. Invalid candidates leave the old complete record intact.

The API distinguishes unenrolled-needs-comparison, stale comparison-and-swap,
conflicting enrollment, unsupported custody, missing key, corrupt record,
interrupted enrollment/recovery required, rejected input and I/O failure. It never
automatically deletes, overwrites, migrates or repairs a trust identity. Loss of a
key, reinstall, root rotation and account changes require a separate reviewed
recovery or comparison ceremony; there is no reset API here.

The recorded admission time is a lower bound for later admissions, not a trusted
clock provider. No persisted receipt authorizes freshness. Encryption and a local
revision cannot detect restoration of an older authentic snapshot together with
its revision. Such a snapshot deliberately still loads as `NeedsFreshness`.
External freshness/checkpoints, rollback recovery, accepted root transitions,
owner-key custody, live session/line/grant fences and durable effect journals remain
unimplemented prerequisites. Android elapsed time alone cannot recover trusted
time across reboot; this store does not invent a substitute.

## Tests and limits

JVM tests use the existing pinned cross-client genesis fixture and deterministic
transaction faults to check comparisons, cancellation, immutable snapshots,
competing writers, signed manifest rejection, clock regression/expiry during a
write, missing keys, corrupt records and authentic older-snapshot restoration.
Their in-memory fixture is not a production cryptography provider.
Separate JVM codec tests use synthetic AES keys to check nonce randomization,
version/nonce/ciphertext/tag tampering, wrong keys, wrong associated data and bounds.
The codec does not choose custody; production always validates the existing
AndroidKeyStore key first and supplies it without a fallback.

Three narrowly selected no-radio device tests exercise actual atomic file rollback
and bounds, two adapter instances, and platform custody enforcement. The custody
test must explicitly pass either hardware-backed round trips with tampering and
associated-data rejection, or the `Unsupported` path on a software-only emulator.
It never skips or introduces a fallback. All test aliases and directories are new,
isolated synthetic namespaces. Existing aliases, app flows, physical devices and
SMS are untouched. These tests do not establish power-loss durability, cross-process
crash behavior, hardware availability on other devices, human provenance, recovery,
carrier delivery or roadmap capability completion.

## Composed synthetic provisioning check

The Windows sealed-setup consumer runs the compiled owner custody CLI, real server
and browser publication ceremony, verifies the actual signed export with the SDK,
and admits that exact public pin through Android `ConversationEnrollmentSession`
and `Draft02TrustStore`. The comparison checkpoint is retained independently of the
server export. Substitution, declined comparison and an actual creator-session
revocation refuse new phone enrollment. The stored root remains `NeedsFreshness`.

This JVM consumer encrypts its test record with the existing AES-GCM codec and a
synthetic software key. It proves protocol and storage composition, not Android
Keystore or physical-device custody, carrier delivery, independent human behavior,
backup decryption or authorization to transfer conversation content.
