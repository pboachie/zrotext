# Profile03 reviewed grants and signed fetch

The optional server composition connects a real reviewed03 queue entry to a
distinct one-attempt grant ledger and signed ciphertext fetch. Main startup does
not mount it. Source, DTO validation and a device signature do not establish
hosted, hardware or carrier readiness. Submission and radio evidence require
their own typed integration; legacy grant handlers are not a fallback.

An authenticated negotiated03 socket can publish the existing closed Ready03
after its own verified manifest installation and physical checks. Readiness is
retained for subsequent distinct reviewed messages. Each grant independently
locks and verifies the original admission owner/session, current accepted
ancestry, installed three-signature interval, same full device lease, physical
receipt, current connector mappings, ciphertext and authenticated SMS ceiling.
The original short review window is checked at original admission time; current
permission is checked at present time. Neither can substitute for the other.

The factory atomically claims the queued job and message and creates its attempt,
one-use fence and immutable grant. One issued attempt is supported per message
lifetime. Its nonpersonal tombstone survives content/message erasure until
account erasure. Any granted, submitting or unknown device fence blocks another
grant even after expiry. A committed grant whose socket write fails remains
unresolved; there is no automatic retry, replacement attempt or legacy dispatch.
Current applicable billing is rechecked without a second quota reservation.

The socket conservatively spaces grants by at least sixty seconds, limits new
grants to 1024 per connection and readiness publications to 64 per connection. A
publication cannot reset either budget. These are overload limits, never a
history-erasure or unknown-attempt recovery mechanism.
The attempt budget closes the connection after the last grant's complete
bounded lifetime, requiring a reconnect rather than silently stopping its queue.
The original durable fence survives that reconnect.

`POST /v1/sealed/dispatch/envelope03` accepts only the existing closed Fetch03
object and strict device-enrolled signature over its unchanged362-byte
transcript. The configured site, deployment and origin are independent server
inputs. Owner cookies, bearers and browser Origin headers confer no access.
The request is bounded4096 bytes with a five-second body deadline and eight
concurrent fetches. Independent anonymous-route and verified-device request
budgets survive later refusal; public UUIDs cannot spend a real device's verified
share. Every response is closed JSON with `no-store` and `nosniff`.

The reply contains exactly the sole ciphertext, original reviewed intent and
signature, immutable acceptance and interval times, selection epoch, distinct
`message_manifest_permission03` current projection and required active
`interval_permission03`. The actual attempt UUID and SHA256 of the exact362-byte
fetch transcript correlate the current projection before device storage/key
access. Both permission comparisons use one final held time, and both permission
ends equal the exact original grant expiry. If any current bound cannot cover
that entire end, fetch refuses; it never shortens or renews the grant. Fetch is
data-read-only and rolls back its locks without renewing times or tuples.

The original ten evidence fields remain immutable. Actual current signed
manifest and ancestry prefix are separate; the phone must already have verified
the whole accepted chain, durable highwater/readback, its original proofs and
opaque local physical/custody handle. JSON identity equality is not installation
or hardware authority. Existing first-only and `message_permission03` parsers
stay unchanged. The new shape is described by
[`profile03-fetch-permission.schema.json`](../protocol/v1/profile03-fetch-permission.schema.json);
that schema verifies shape only. Sign-out, Stop, changed owner/manifest/full lease,
physical or mappings, erased originals and submitted/unknown/expired fences
refuse the original fetch.
