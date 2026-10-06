<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Authenticated owner session time

`GET /v1/auth/session` retains its existing owner-session cookie authentication
and returns `account_id`, `user_id`, `session_id`, `role`, and `server_now_ms`.
`server_now_ms` is a positive decimal string within the signed 64-bit range,
sampled from PostgreSQL `clock_timestamp()` in a final live-principal check.
The response remains `Cache-Control: no-store`.

The final statement checks the same session, account, user, membership role and
CSRF digest, together with session and membership revocation, absolute and idle
expiry, verified user identity and enabled account. A valid Observer still
receives its own Observer role; the endpoint never upgrades it to Owner.
Clients performing owner signing must require the Owner role themselves.

This is a time sample for an authenticated response, not a new credential,
lease or signing permission. Clients must bind it to the same independently
selected HTTPS origin and unchanged current cookies/session, use monotonic
elapsed time and bounded request latency/sample age, and invalidate it on
session, origin or lifecycle changes. Downloaded proposals and device bearer
tokens do not establish owner authentication or server time.

Typed signing requires authoritative proposal revalidation both before and
after signing, including the current checkpoint, line/lease, interval, expiry
and exact public proposal bytes. A successful session check alone cannot prove
that those proposal-specific authorities remain unchanged. Completion still
uses the existing authenticated one-use/CAS and factor checks.
