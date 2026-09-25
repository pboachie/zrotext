# Internal SMS line activation contract

**Prerequisite only.** Migration 033 and the `issue_sms_line_challenge`,
`activate_sms_line_binding`, and `sms_line_binding_ready` functions define a
separate SMS-only line scope for Android API 28+. No HTTP or device-stream route
calls these functions. No owner approval key can yet be provisioned through the
application, and Android does not yet generate these proofs or persist a
verified mapping to the selected subscription. General sending stays closed.

An authenticated owner session issues a five-minute challenge for an enrolled
device and a stable owner-assigned line UUID. A distinct SMS owner approval key
signs the exact device proof. The existing sealed owner key does not satisfy
this scope. Provisioning the SMS key still needs a separate, MFA-bound owner
ceremony with device-key role separation before this contract can be exposed.
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

The current PostgreSQL tests use synthetic keys and declared subscription
values. A live owner ceremony, Android implementation, route integration,
physical SIM testing, and a real carrier receive test are still required.
