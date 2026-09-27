# Dormant root enrollment transactions

The server's `sealed_root_ceremony` module composes the [candidate possession
transcript](root-enrollment-01.md) with database state. No HTTP route, CLI, or
runtime sealed gate calls it. It does not generate or receive a private root key.

The future request adapter must authenticate the owner request, enforce CSRF
and the configured canonical origin, and establish independent owner software,
custody and full-fingerprint comparison. A valid possession signature alone
does not prove those properties. The transaction independently rechecks the
current verified owner, live session and enabled MFA rather than accepting a
cached step-up flag.

Challenge issuance replaces one bounded row per account, invalidating the older
nonce and challenge ID. It charges the existing owner-management budget and
stores only a random nonce's digest. The returned candidate bytes bind the
account, user, session, exact root fingerprint, configured origin and at most
five minutes of database wall time. Issuance neither consumes a factor nor
creates authority or signing-role reservations.

Completion owns one READ COMMITTED transaction. It locks account, user,
membership, session, MFA and challenge in that order. Existing authority or
permanent enrollment history is rejected with a nonlocking read after the
account lock: it never acquires an existing authority lock after account,
preserving the admission module's authority-before-account ordering. Existing
revocation writers may win, wait, or cause a retryable database failure; a
failed transaction grants no enrollment.

The expected transcript comes from the locked challenge and its hash-matched
nonce. Completion verifies root possession before consuming a fresh TOTP or
unused recovery factor. An invalid factor commits only the existing failure
budget. A valid completion atomically writes generation-one authority, the
permanent marker and role claims, consumed challenge/factor, and an immutable
public receipt. Any subsequent failure rolls all of these back. After blocking
writes, completion rechecks session state, nondecreasing database wall time,
challenge expiry and the original accepted TOTP window before committing.
This does not promise that a deadline remains valid after an arbitrary commit
delay, and registration is never a dispatch permission.

The receipt copies historical actor IDs without retaining their session or
user rows. Ordinary receipt updates, deletion and truncation fail; account
erasure cascades. Receipt reads require current authenticated owner state. The
caller must compare the exact returned public root pin with its intended pin
when reconciling a lost reply. A receipt does not establish current authority,
re-enroll a deleted authority, or bypass the permanent enrollment marker.

Root reset, rotation, trusted clock acquisition, owner-client distribution and
recovery UX, live request/grant adapters and physical-device interoperability
remain separate prerequisites. This module does not complete those gates.
