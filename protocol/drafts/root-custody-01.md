# Generation-one encrypted root custody adapter

**Candidate implementation, default off.** The server library's explicitly
enabled owner-authentication router composes generation-one root enrollment and
immutable encrypted bundle publication. The standard server never calls
`with_root_custody_enabled`, has no environment switch for it, and exposes none
of these routes. This does not enable sealed messages or close Q1/Q10. An
independently distributed owner signing client and browser/SDK/phone provisioning
drills remain release requirements; a relay-served page is not independent trust.

## Owner intent and the encrypted-only boundary

The owner generates and seals the root locally using the existing root-backup
codec and publishes the same encrypted backup/public card bytes as the offline
owner CLI. The server accepts no private root, archive key or recovery token.
Unknown JSON fields are refused. Backup/card sizes are bounded before decoding
and then checked by the existing exact public-framing validators: backup at most
748 bytes and card at most 645 bytes, generation one only, exact account/origin/
fingerprint and SHA-256 of the exact backup in the card. The server cannot verify
backup AEAD tags or prove restorability; the owner must perform local restore-check
with the independently intended identity before signing publication.

The owner separately compares the full RootPin02 fingerprint through the
independent recovery card/direct comparison channel defined in Q1. The request
must supply this intended fingerprint separately; it cannot be absent or differ
from the challenged pin. A boolean "compared" or a normal login is insufficient.
The server can enforce equality and possession, not prove that a human used an
independent channel. An owner client must never fill this field by copying an
untrusted relay response or the uploaded bundle's own metadata.

## Authenticated request sequence

Paths below are relative to the owner-authentication router (normally `/auth`).
Each route requires a live owner session, canonical HTTPS Origin and the
session-bound double-submit CSRF proof, including encrypted export reads. The
transaction rechecks active account, verified owner, unrevoked membership and
session, enabled MFA and the existing 72-hour root-ceremony idle-session limit.
Responses, including errors, are `Cache-Control: no-store`. The body cap remains
16 KiB; base64 uses canonical padded standard encoding with no aliases.

1. `POST /sealed-root/challenge` accepts `root_pin_b64`,
   `independently_compared_fingerprint_b64`, `encrypted_backup_b64` and
   `public_card_b64`. It validates public identity/bounds and comparison, then
   replaces the existing one-use five-minute enrollment challenge using the
   owner-management budget. It returns `unsigned_enrollment_b64`,
   `custody_statement_b64` and the exact `root_pin_b64`. No bundle or authority is
   committed at issuance. A replaced, expired or foreign-session challenge fails.
2. The independent signer checks the existing enrollment U against its intended
   account, user/session, origin, pin and current challenge, and recomputes the
   custody statement below from its own exact immutable bundle. It signs the
   existing enrollment transcript and the custody statement separately. The
   current offline CLI's narrow `unlock` command signs enrollment only; it does
   not yet provide this second signature or an online publish command.
3. `POST /sealed-root` accepts `unsigned_enrollment_b64`,
   `enrollment_signature_b64`, `custody_signature_b64`, the same independently
   compared fingerprint and encrypted backup/public card fields, and `mfa_code`.
   The database's current challenge supplies expected pin, identity and times.
   Both signatures are verified before a fresh TOTP/unused MFA recovery factor
   is consumed. Factor, authority, permanent trust history, consumed challenge,
   enrollment receipt and custody row commit together. A failed custody insert
   rolls back every write; it does not leave partial enrollment.
4. `GET /sealed-root` requires `x-zrotext-root-fingerprint` containing the owner's
   independently compared 32-byte fingerprint in canonical base64. It returns
   one bounded export with account/challenge/backup IDs, generation, exact pin,
   fingerprint, backup/card bytes, the unsigned enrollment and custody signature,
   and commit time. It locks authority before
   account, verifies current generation/pin and stored hashes/public framing,
   and rechecks the owner/MFA/session fence. An absent bundle is 404; comparison
   mismatch, damaged storage or an unsupported later generation fails closed.

Custody signature bytes are exactly 64-byte low-s P-256 `r || s`, over SHA-256
of the following exact message (no prehash/double hashing by the caller):

```text
"ZTSE/root-custody/v1" || NUL
|| length(U)[u32be] || exact enrollment U
|| SHA-256(exact encrypted backup)[32]
|| SHA-256(exact public card)[32]
|| independently compared RootPin02 fingerprint[32]
```

U uses the existing [enrollment grammar](root-enrollment-01.md); this new domain
does not change it or the `unlock` transcript. Every bundle byte, root comparison,
nonce, challenge/session/owner/account, service origin and deadline is bound.
Reject DER, high-s, invalid scalars/width, wrong root or changed bytes. A new
signature over a substituted bundle cannot be authorized by a stolen login.

## Persistence, replay, retention and history

Migration 070 adds one immutable generation-one custody row per account; storage
is intrinsically bounded without a pagination or unbounded draft-upload queue.
There is no update, overwrite, restore, reset, rotation or rewrap endpoint. A
concurrent completion has at most one winner under existing account/challenge
locks; permanent enrollment history rejects a second attempt. Changed same-slot
bytes are not accepted as a refresh. After a lost reply, authenticate again and
export the receipt/bundle, comparing exact intended pin and bundle bytes. This
read reconciles outcome without consuming another factor or creating authority.

Custody persists for account lifetime, with no shorter secret-material TTL
introduced here. Export retrieves original encrypted/public bytes only; private
material remains in the independently kept kit. Ordinary deletion/update/truncate
is refused by trust-history guards. Account erasure cascades through the custody
row, preserving the existing account-erasure authority rather than a new deletion
bypass. Schema upgrades must install the additive migration before enabling a
controlled library adapter; no applied migration is edited.

The root-only backup contains no archive keys and cannot decrypt message history.
Old ciphertext keeps its existing retention policy and requires matching retained
decryption keys. Publication, login, export or a historical receipt never repins
a browser/SDK/phone, creates device/connector grants, restores revoked keys or
authorizes dispatch. All clients independently compare the same account,
generation-one pin and fingerprint with their existing RootPin02 verifiers; any
different generation/root, missing comparison or directory substitution must
stop provisioning. Rotation/lost-all are separate Q3/Q10 contracts.

The candidate SDK's `verifyPublishedRootBundle` also supports browser Web Crypto
consumers: it captures all buffers before asynchronous validation, checks the
intended independent pin/origin, exact public backup/card/enrollment framing,
backup digest, and canonical root signature over the complete custody statement.
It returns defensive public/ciphertext copies and initial trust metadata, never
persists a pin or grants a dispatch permission. Phone integration must use the
same independently intended RootPin02 and validate this additional custody
signature before accepting the export; a phone custody adapter is not supplied.

## Verification and remaining evidence

The shared public signature corpus is
[`root-custody-01.json`](../v1/vectors/root-custody-01.json), consumed by Rust,
the SDK and an independent Python transcript/framing check. It references the
existing synthetic encrypted backup and public card corpus; no private material
is supplied by this custody fixture.

Rust tests exercise real P-256 signatures and encrypted root-backup/card codecs,
independently reconstruct the custody transcript, and reject modified bundle,
comparison, account/origin, challenge and oversized inputs. Disposable PostgreSQL
tests exercise actual atomic publication, immutable bytes/export after reconnect,
one-winner concurrency, revocation, injected insert failure with factor/challenge
rollback, and account-erasure cascade. The opt-in HTTP test checks cookie owner
auth/CSRF, independent statement reconstruction, completion and no-store export.
Default-router tests ensure these endpoints are absent without library opt-in.

These are synthetic local tests, not physical-device or independently delivered
client evidence. Follow-up owner-client second-signature/publish support, MFA/
comparison UX, real process-restart/kill fault tests, browser/SDK/phone phishing
and pin-comparison drills, and canary sweeps of deployed logging/backups remain
unverified. Keep live material and dated captures private. No hosted service
configuration or sealed-runtime enablement is supplied by this implementation.
