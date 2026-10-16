# Phone pairing recovery, version 1

The independently selected HTTPS origin remains trusted before any QR scan or
request. Its `/v1/device-stream` path, with `wss` replacing `https`, is the only
stream address. A response never supplies another origin or stream address.

`POST /v1/enrollment/pairings/{pairing_id}/binding/challenge` accepts a closed
JSON object containing `key_fingerprint`: exactly 64 uppercase hexadecimal
characters for the existing local P-256 signing key. The response contains
exactly `schema_version` (1), `account_id`, `pairing_id`, `challenge_id`,
`challenge_nonce` (canonical unpadded base64url, 32 bytes), `key_fingerprint`.
UUIDs are canonical lowercase UUID strings. The response account is a public
locator; it is not an approved binding or permission to connect.

`POST /v1/enrollment/pairings/{pairing_id}/binding` accepts exactly
`account_id`, `challenge_id`, `challenge_nonce`, `signature_der`. The signature
is canonical unpadded base64url encoding of a P-256 ECDSA DER signature over
SHA-256 of the following concatenation:

1. ASCII `ZROTEXT-PAIRING-BINDING-V1` followed by one NUL byte.
2. Account UUID, pairing UUID, challenge UUID, each 16 network-order bytes.
3. The existing key fingerprint and challenge nonce, each 32 raw bytes.

The server HMAC binds account, pairing, challenge ID and fingerprint using a
separate purpose from enrollment and socket authentication. Challenge IDs carry
their issuance time; validity is 60 seconds with 10 seconds skew. A proof only
reads state. It cannot claim, approve, cancel, enroll, start a connection or
activate a SIM. Original enrollment signatures cannot answer this challenge.

The closed response contains `schema_version` (1), `status`, `account_id`,
`pairing_id`, `device_id` (UUID or null), `comparison_code` (eight digits or
null), `key_fingerprint`. Status is one of `pending`, `approved`, `expired`,
`cancelled`, `proof_rejected`, `awaiting_proof`. Only `approved` includes a
device ID. Only a verified `pending` or retained `approved` ceremony may include
the comparison code. An approved binding remains recoverable after the short
ceremony retention window; its comparison code then becomes null.

Every result rechecks the authoritative writer and current account, device and
key state. Unknown locators, mismatched keys, revoked devices/keys and disabled
accounts receive generic 404 responses. Invalid input receives 400, rate limits
429, unavailable authoritative storage 503. All responses are `no-store`.
Anonymous binding traffic uses a shared route ceiling, with no per-locator
budget: public IDs and fingerprints cannot spend a share belonging to the
original phone.

One narrow pre-claim exception permits the phone to stop waiting when a claim
never arrived. The challenge route returns 409 with exactly
`{"code":"pairing_cancelled"}` or `{"code":"pairing_expired"}` only for an
actual, active-account row that is unclaimed and unapproved and has that
authoritative terminal condition. This contains no identity, binding or
comparison value and grants no authority. Missing rows and every claimed,
approved, revoked or mismatched-key ceremony remain generic unknown results.
Clients may retire that local locator after 409 and explicitly scan a
replacement; they never repeat a claim or proof automatically.

Android stores only the trusted origin and public pairing/account/fingerprint
locators. It must use an existing key for recovery; reinstall or key loss
requires a new pairing. It never persists tickets, comparison codes, enrollment
nonces or signatures. Lost claim/proof outcomes are observed through this
protocol. `awaiting_proof`, `proof_rejected`, `expired` and `cancelled` require
the owner to inspect and replace the affected ceremony; clients do not replay
the original claim/proof. The owner still compares the exact code and full
fingerprint and explicitly approves through the authenticated owner endpoint.
