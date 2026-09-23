# ADR 0002: Account, enrollment, and heartbeat foundations

Status: accepted, 2026-09-22. This decision describes the account and device connection foundation; later protocol extensions are documented separately.

## Account and verification

Owner passwords use Argon2id. Sessions and API keys store separate keyed
verifiers; cookie mutations require the configured exact HTTPS Origin and a
session-bound CSRF value. Registration and resend queue a one-use email code
in PostgreSQL in the same transaction as the challenge. Migration 005 adds
the outbox and resend throttle. The code is reconstructed from its random
challenge UUID and an operational pepper; plaintext code is not stored in
PostgreSQL. A worker claims one item under a lease, sends with bounded TLS
SMTP, and acknowledges by lease ID. Retry after ambiguous SMTP acceptance
may send the same code twice. Six failed attempts dead-letter the item;
password-authenticated resend can revive it within its validity window.
The account remains pending after delivery failure. No live SMTP send has
been verified.

## Phone identity and session

One-use five-minute pairing approves a P-256 signing key generated in Android
Keystore after the owner compares a code and fingerprint. The phone signs a
fresh one-use socket challenge using the bytes in
[device-stream.md](../../protocol/v1/device-stream.md). The writer checks
site, device, key, account, and deployment authority before incrementing
the persistent session epoch. New connections fence older sockets. A fresh
site can register its configured `SITE_ID` while SMS dispatch is disabled;
startup never re-enables an operator-disabled or draining site. Readiness
falls to 503 when that site is disabled or draining.

The current device stream carries heartbeat frames only. It admits at most
128 sockets per process, limits frames and handshake time, and checks the
writer before acknowledging heartbeats. It does not use an account-wide
token, URL credential, or browser cookie. The older M0 test-token socket
remains separate. No grant, radio adapter, or inbound handler is connected.

## Migration and limits

The locked migrator applies numbered migrations on a fresh schema.
An older pre-migration volume requires backup and an explicit shape-checked baseline
before applying later migrations. The [device-stream contract](../../protocol/v1/device-stream.md)
and current server code describe subsequent connection behavior.
