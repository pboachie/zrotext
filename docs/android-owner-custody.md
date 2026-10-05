# Android owner custody

This is a local candidate implementation. The native bridge supports bounded
root enrollment/custody, line registration, separate archive creation/recovery,
conversation genesis, activation and role-5 refresh using existing codecs.
Ordinary app/browser integration and authenticated context are separate gates;
these primitives alone do not establish a functioning hosted onboarding flow.
The isolated fixture mounts the actual custody screen without SMS or network.
Owner custody, recovery and signing run on Android with the same-owner HTTPS
browser. The existing offline tool remains available as an optional advanced
path; Windows is not a dependency of this Android owner path.

Pairing can scan a canonical, bounded pairing QR after the owner independently
enters the HTTPS server. Explicit server confirmation precedes the existing
phone claim/proof; comparison and authenticated browser approval remain separate.
Manual entry shares the same controller. The permissionless Google scanner
requires Google Play Services and its scanner module; unavailable scanning leaves
manual entry available. No owner root, archive recovery material or account
credential belongs in a pairing QR.

The app records only a nonsecret unresolved-operation marker before pairing HTTP.
It survives Activity/process loss and blocks another claim until the original
ticket is explicitly reconciled in the browser. No automatic retry occurs.
Cancellation clears inputs and suppresses late UI results; the existing synchronous
HTTP client may complete already dispatched requests. This is not server rollback.

The ordinary Android entry mounts the custody UI and a same-owner HTTPS browser.
Native requests use that browser's original owner session and independently
entered origin. They require authenticated database time, include full request
round-trip uncertainty, and refresh authority before review and signing and
after signing. Expected line scope comes from the original persisted pending
proposal returned through authenticated status. Other proposal scopes require
an authenticated registry of exact public proposals. Each context is revalidated
after native signing before output is published. Missing hosted contracts fail
closed.

Browser public imports use frozen process-local bytes. A separate archive
recovery import requires native consent displaying the full account, origin,
root fingerprint, archive identity and encrypted-backup digest. Fresh native
AEAD verification of the selected recovery material and a fresh same-session
check precede a one-read, expiring grant. Root recovery tokens and root scalars
are never accepted through this browser handoff.

The private transport permits at most eight cumulative metadata descriptor opens
within the original 30-second grant. Descriptors hold no private copies. The
first positive payload read selects one consumer, retires competing descriptors,
and allows a sequential total of 32 bytes; a new payload requires a fresh grant.
Closing metadata does not renew the deadline. Owner cancellation, observed withdrawal,
expiry or closing the consumer wipes the shared managed recovery buffer. Bytes already
delivered to Android, Chromium or the page cannot be retracted or proven erased
by provider revocation.

The browser accepts generic binary file metadata only for its explicitly selected
Android archive-recovery input. Input purpose and MIME do not authenticate native
provenance or owner authority. The native chooser still requires the exact archive
purpose, successful AEAD proof, the current owner session and separate consent;
browser account-wide archive decryption keeps its own consent.

The Android owner-custody implementation uses a recoverable software owner root.
It is separate from the hardware-backed Android device and content keys. The
owner root can authorize account ceremonies; creating or restoring it does not
publish a root, enroll a phone, activate content transfer or establish server
authority.

## Creation and independent recovery

The native `zrotext-android-owner-custody::custody::create` operation takes a
nonzero account ID and an exact canonical HTTPS origin. It generates a new
nonzero P-256 owner root and a separate 256-bit recovery secret using fallible
system randomness. It uses the existing root-material codecs without changing
their algorithms or wire formats:

| Artifact | Existing format | Contents |
| --- | --- | --- |
| Encrypted root backup | RootBackup01 (`ZTRB`) | Account, origin, root fingerprint and authenticated encrypted root material |
| Public root card | PublicRootCard01 (`ZTRC`) | Canonical origin, genesis RootPin02 and encrypted-backup digest |
| Recovery token | RecoveryToken01 (`ZTRK1`) | High-entropy recovery material with a context-bound transcription checksum |

Creation returns the public identity and root pin, encrypted backup, public card
and an explicitly zeroizing token buffer. It does not return the root scalar.
Before returning, creation authenticates a codec readback and checks the actual
decrypted root identity, then drops the root and recovery material. This readback
checks the generated bytes; it does not prove that the owner retained an
independent recovery kit.

The owner must retain an encrypted backup and public card outside app-private
storage, retain the token separately, and independently retain or compare the
full account, origin and root fingerprint. A local encrypted copy alone is not
recovery. A cancelled, failed or ambiguous export cannot establish readiness.
Root recovery and archive recovery are different kits and ceremonies.

The separate native `custody::recover` call requires the retained encrypted
backup, public card, token and independently supplied expected identity. It
consults no creation object, readiness flag, local wrapping key, login password
or persistent app state. It checks bounded public framing, the card's backup
digest and full expected identity, decodes the token against its exact context,
and calls the existing root-backup opener. Both AEAD tags and the public identity
derived from the decrypted root must match before a `RootSecret` is returned.
A public-card digest or token checksum is insufficient to authenticate a root.

A fresh check must use reimported, independently retained artifacts after
discarding creation state. The same native API supports restoration after loss
of all app-private data and local wrapping keys because those are not recovery
inputs. Success only demonstrates possession of the expected root for that
invocation; it is not a server enrollment receipt.

## Native lifetime and signing boundary

The recovered `RootSecret` is a native zeroizing value for an explicitly approved
operation. It must never be serialized, returned through managed callbacks,
stored as plaintext, logged or cached as an unlocked background signer. The
native signing layer uses existing typed root-material transcripts, independently
expected account/origin/fingerprint, current session authority and bounded time.
Recovery success does not bypass challenge expiry, owner approval, cancellation,
one-use handling or server acceptance.

The recovery token is the intentional secret reveal needed for independent
retention. Callers must protect and clear their token input/output buffers and
keep it out of clipboard, logs, intents and ordinary file exports. Native
zeroization cannot guarantee erasure of UI, IME, OS or compiler-generated copies.
Process death must leave no usable unlocked authority; a new process starts a
new owner ceremony.

## Private owner handoff

After the authenticated hosted flow passes acceptance, the owner performs this
setup personally on Android:

1. Open **Setup**, then **Set up or recover owner custody on Android**. Enter the
   independently known account UUID and exact HTTPS owner origin.
2. Create the encrypted owner kit. Compare and retain its full root fingerprint
   and public identity. Reveal the recovery token privately, record it separately
   from the encrypted backup, and acknowledge that deliberate retention.
3. Save the encrypted backup and public card to independently retained storage.
   Reimport those saved copies and the separately retained token, supplying the
   expected identity again. Successful fresh recovery establishes local kit
   possession; server enrollment is a later ceremony.
4. Sign in and complete the existing MFA flow in the owner browser. Review each
   exact public proposal and its independent scope in the native signing UI,
   recover the root afresh and consent separately for each operation. Transfer
   only the displayed public proposal, signature or signed manifest.
5. Retain and check the separate encrypted archive kit and its separate recovery
   material. An archive recovery browser import requires its own native identity
   comparison, proof and consent. Keep the root token out of that import.

No developer, reviewer or service operator receives the owner's token or creates
the owner's private kit. Loss of app data requires retained independent copies;
the phone's local encrypted store cannot substitute for them.

## Threat model and verification limits

The recoverable root is not a nonexportable hardware-generated owner root.
Hardware-backed device/content keys retain their separate requirements. Owner
authority and device/content keys on the same phone share a compromised-phone
failure domain; separate key roles do not provide independent hardware trust.
An attacker with the encrypted backup and its separate recovery token can
recover the software root. Independent fingerprint comparison protects the
intended identity; it cannot authenticate an origin or owner intent supplied by
an already compromised interface.

Synthetic native tests cover restoration without creation state or local wrapper
keys, wrong account/origin/fingerprint, a checksum-valid wrong token, corrupted
ciphertext even with a matching public-card digest, malformed and oversized
artifacts, partial randomness failure, backup creation failure, failed AEAD
readback and the unchanged root-material vectors. Existing codec tests also
exercise authenticated invalid or substituted root scalars after decryption.
These checks do not establish secure Android reveal/export destinations,
physical TEE/StrongBox behavior, supported-ABI or 16 KB native loading, signed
fresh-install behavior, integrated server enrollment or carrier delivery.
Those require their own review and validation before product release.

## Isolated Android fixture

The fixture mounts the real owner-custody screen in a separate package. Its
manifest declares no SMS or network permissions and no gateway services.
The normal gateway build is not modified by this fixture init script. The
init script rejects release tasks, so it cannot produce a store candidate.

With the repository's pinned Rust toolchain, official NDK r28 or newer, and the
existing Android SDK installed, build the native library from source:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
python3 scripts/build_android_owner_custody.py --ndk "$ANDROID_NDK_HOME"
cd android
./gradlew -I ../scripts/android-owner-custody-fixture.init.gradle :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon --no-configuration-cache
```

The native build checks 16 KiB alignment of every ELF LOAD segment before
staging each supported ABI. This is an alignment check, not proof that the
library loads on every device or a 16 KiB-page Android system. The dedicated
`Android owner custody fixture` CI workflow builds and runs the synthetic JNI
and UI tests on a disposable emulator. These tests cannot establish physical
hardware custody or carrier delivery.

Owners must eventually perform their own private custody setup. A developer
or reviewer must not precreate a founder root, receive its recovery token, or
substitute login credentials for independent recovery. Reusable store-reviewer
access and an actual remote-messaging foreground-service demonstration are
separate product and submission gates; this fixture grants neither.
