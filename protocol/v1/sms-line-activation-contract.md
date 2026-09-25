# Internal SMS line activation contract

**Dormant.** Migrations 033–035 and 037 and the `issue_sms_line_challenge`,
`activate_sms_line_binding`, and `sms_line_binding_ready` functions define a
separate SMS-only line scope for Android API 28+. The owner can provision an SMS
approval public key through the account API. The activation exchange below is
off unless the hub sets `SMS_LINE_ACTIVATION_ENABLED=true`. General sending
stays closed.

An authenticated owner session issues a five-minute challenge for an enrolled
device and a stable owner-assigned line UUID. A distinct SMS owner approval key
signs the exact device proof. The existing sealed owner key does not satisfy
this scope. Provisioning the SMS key uses a separate, MFA-bound owner ceremony
with device-key role separation.
The challenge, generation, account, device, line, and current writer session
are checked in one database transaction. A consumed or expired challenge,
revoked key/device, old generation, stale writer epoch, or changed signature
does not activate the line.

All integers are fixed-width big-endian and UUIDs are 16 network-order bytes:

```text
sms_device_statement = ASCII("ZTSMS/line/device-confirm/v1\0") ||
  account_id[16] || line_id[16] || device_id[16] || generation:i64 ||
  challenge_id[16] || nonce[32] || android_api_level:u16 ||
  active_subscription_count:u8 || selected_subscription_id:i32

sms_owner_statement = ASCII("ZTSMS/line/owner-approve/v1\0") ||
  sms_device_statement || SHA-256(device_signature_der)
```

## Owner SMS approval-key ceremony

`POST /v1/auth/sms-line-owner-keys/challenge` accepts
`{"signing_key_sec1_b64":"..."}`: canonical standard Base64 for one
uncompressed P-256 public key (65 bytes). The response contains a challenge
UUID, a 32-byte random nonce in standard Base64, and the Base64url SHA-256 key
fingerprint. The owner must have an enabled MFA factor. The browser supplies
the current owner session, exact HTTPS Origin, and matching CSRF cookie/header.

The owner signs these exact bytes with the matching private key using P-256
ECDSA/SHA-256 and canonical DER:

```text
owner_key_registration = ASCII("ZTSMS/owner-key/register/v1\0") ||
  account_id[16] || user_id[16] || session_id[16] || challenge_id[16] ||
  nonce[32] || SHA-256(signing_key_sec1)[32]
```

`POST /v1/auth/sms-line-owner-keys` takes `challenge_id`, `nonce_b64`,
`signature_der_b64`, and `mfa_code` (fresh TOTP or unused recovery code). The
nonce expires after five minutes and is single use. Issuing a new challenge
cancels earlier pending challenges for the account. Registration rejects keys
already used for sealed owner approval, an enrolled device, or prior SMS owner
approval, including revoked keys. The server only stores the public key.

`DELETE /v1/auth/sms-line-owner-keys/{fingerprint}` takes a fresh `mfa_code`
and revokes the active key. It revokes active and pending SMS bindings; active
SMS phone-line identities become revoked so their current generation cannot
appear active. Sealed bindings stay active. The change and an append-only audit
record commit together. `GET /v1/auth/sms-line-owner-keys` lists fingerprints
and active status for the signed-in owner. Mutations require owner session,
Origin, CSRF, and fresh MFA. The server never accepts or stores a private key.
An owner must revoke the active SMS approval key before disabling MFA; the
MFA disable endpoint returns `revoke_sms_owner_key_first` until then.
The fixed registration transcript is in
[sms-owner-key-registration.vector.json](sms-owner-key-registration.vector.json).

Each signature is canonical DER P-256 ECDSA/SHA-256. The server requires API
28+, exactly one declared active subscription, and a nonnegative selected
local subscription ID. These are signed **device declarations**, not
independent hardware facts. A subscription ID alone does not prove that the
physical SIM is unchanged after a swap. Android must take a fresh observation
and fail closed on an ambiguous or changed SIM mapping before any line-bound
capture or upload; physical SIM identity on API 28 remains an unresolved gate.
The fixed binary statement vector is in
[sms-line-activation.vector.json](sms-line-activation.vector.json).

The binding row records `purpose='sms'`. The sealed preflight and sealed
inbound database trigger require `purpose='sealed'`, so an SMS proof cannot
authorize sealed-content storage. The SMS preflight and STOP insert trigger
accept an active binding of either purpose; a later sealed activation keeps
the SMS STOP channel available. Neither purpose authorizes outbound sending,
ciphertext webhooks, or RCS capture. The two scopes share a line's monotonic
generation. Upgrading from SMS to sealed revokes the former active binding;
after sealed activation, SMS-only activation is refused as a downgrade.

## Activation exchange

The owner signs over the device signature, so the device answers first and the
server stores its proof until the owner approves. All owner routes are under
`/v1/auth`, need the owner session and CSRF cookie/header, and return
`not_found` while the exchange is disabled. Mutations also need the exact
HTTPS Origin and share a per-owner rate limit.

1. `POST /v1/auth/sms-lines/{line_id}/activations` with `{"device_id":"UUID"}`
   issues a challenge and returns `challenge_id`, `generation`, and
   `expires_at_ms` (201). A new challenge supersedes a pending one for the line.
2. The device's own authenticated stream sends `sms_line_challenge` (line,
   device, generation, Base64url nonce, expiry) within a few seconds, on
   whichever hub holds the session, and again after a reconnect.
3. The device answers with `sms_line_proof`: the declared API level,
   subscription count and selected subscription ID, and its DER signature over
   `sms_device_statement`. The hub verifies it with the enrolled device key and
   stores it with the exact device session that delivered it, then replies
   `sms_line_proof_ack` with `accepted`. An exact replay is accepted again; a
   different proof cannot replace a stored one.
4. `GET /v1/auth/sms-lines/{line_id}/activations/{challenge_id}` returns
   `status` (`awaiting_device`, `awaiting_owner`, `activated`, `closed`). While
   `awaiting_owner` it includes the declaration and standard Base64
   `device_statement_b64`, `device_signature_der_b64`, and the exact
   `owner_statement_b64` to sign.
5. `POST .../{challenge_id}/approve` with `{"owner_signature_der_b64":"..."}`
   activates the binding (204). Activation runs under the stored device session,
   so the connection that delivered the proof must still hold a live lease; a
   reconnect needs a new challenge, and the status then reads `closed`. Any
   failed fence returns `forbidden`.
6. The device stream then sends `sms_line_activated` with the SHA-256 digests of
   the exact device statement and DER signature, only when the active binding's
   confirmation digest matches that proof. Each device connection sends it once
   during the 15 minutes after activation, so a dropped connection does not lose
   it; the device ignores a digest that does not match the proof it holds.

The hub keeps the challenge nonce only while an exchange can still activate or
acknowledge. It clears the nonce once the resend window ends, or once the
challenge is superseded, revoked or has been expired for 15 minutes. Stored
proofs, recorded acknowledgements and cleared nonces are write-once in the
database. The server never receives the owner's private key.

The current PostgreSQL tests use synthetic keys and declared subscription
values. The Android gateway answers a pushed challenge only for API 29+ with
exactly one selected, active physical SIM, keeps the prepared proof in memory,
and installs its local line binding only from an `sms_line_activated` frame
whose digests match that proof and a fresh SIM observation, until 15 minutes
after the challenge expiry to allow the hub's resends. A restarted app
cannot install an earlier proof; the owner opens a new activation. The owner page at `/owner/sms-lines` creates the SMS approval key as a
non-extractable WebCrypto P-256 key in the browser's IndexedDB, registers it
with the MFA-bound ceremony, and approves an activation only after it parses
the device statement, checks its account, line, device, generation and
challenge against the activation it opened, and rebuilds `owner_statement`
itself; it refuses when the server's copy differs. Physical SIM testing and a
real carrier receive test are still required.
