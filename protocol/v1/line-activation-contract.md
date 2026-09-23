# Internal line-activation contract

**Prerequisite, not a sealed-content protocol or live enrollment API.** This
contract is implemented by migration 019 and
`sealed_inbound::line_activation`. No HTTP/WebSocket route calls it, no owner
key provisioning ceremony exists, and the Android app does not produce these
proofs or enforce the selected subscription on a later SMS. M1 keeps its
existing Android API range. A future sealed client must require API 31+.

## Trust and challenge

The owner allocates a stable random `line_id` UUID within its account and
chooses an approved, unrevoked device. An authenticated owner session may
prepare the next pending binding generation and receive a 32-byte random
challenge nonce with a five-minute lifetime. The database stores only its
SHA-256 digest. An existing active generation continues working until a new
generation activates. Expired and consumed challenges cannot activate, and
the stored challenge identity, expiry and consumption cannot be rolled back.

The transaction reads an active P-256 owner approval key from
`line_owner_approval_keys`. That table has **no provisioning route**. Before
any production use, the key must be bound to an owner-root-pinned, verified
manifest through a separately authenticated ceremony; an arbitrary key
inserted by a relay or database operator is not a content trust root. The
device signature uses its already enrolled P-256 device authentication key.
The transaction rejects an owner/device public-key alias; the eventual
manifest role policy must also prevent that alias at registration.

## Exact signed bytes

All integers use fixed-width big-endian encoding; UUIDs use 16 network-order
bytes. There is no JSON, text normalization, optional field or trailing data
in either transcript.

```text
device_statement = ASCII("ZTSE/line/device-confirm/v1\0") ||
  account_id[16] || line_id[16] || device_id[16] || generation:i64 ||
  challenge_id[16] || nonce[32] || android_api_level:u16 ||
  active_subscription_count:u8 || selected_subscription_id:i32

owner_statement = ASCII("ZTSE/line/owner-approve/v1\0") ||
  device_statement || SHA-256(device_signature_der)
```

Each signature is canonical DER P-256 ECDSA/SHA-256 over its respective
statement. The owner signs only after seeing the device's exact statement and
signature. The server checks both against stored public keys, binds the
account, line, device, generation and one-use nonce, and stores SHA-256 of
each statement concatenated with its signature as an audit anchor. It does
not store the local subscription index or any SMS body, sender or recipient.

The internal contract accepts `android_api_level >= 31`, exactly one declared
active subscription, and a nonnegative selected local subscription ID. A
multi-SIM or ambiguous declaration fails closed. These fields are signed
**device declarations**, not independently verified hardware facts. The
future Android implementation must derive them from a fresh local SIM
observation, show a meaningful line/device comparison to the owner, and
recheck the selected SIM before every sealed send or inbound capture. A
changed subscription index or uncertain SIM mapping must pause sealed mode
until a new approved generation is bound. How to distinguish physical SIM
replacement when Android reuses a local index remains an open Q8 decision.

## Transaction and limits

Activation requires an unexpired owner session, active owner key, unrevoked
device/key, current writer session epoch and lease on an enabled site, current
deployment epoch, pending binding, and matching unconsumed challenge. It locks
those rows in one PostgreSQL transaction, verifies both signatures, revokes
the previous active binding, activates the pending generation, advances the
line generation and consumes the challenge before commit. A stale hub session,
revoked key/device, cross-account line, altered selected subscription, changed
signature, expired nonce or replay does not activate a line.

There is still no sealed-content route, full envelope parser/verifier,
owner-root-pinned manifest, Android proof producer, ciphertext webhook, or
real SIM test. The virtual tests exercise the transaction with synthetic keys
and local subscription declarations. They do not establish a production
cryptography or physical SIM security claim.
