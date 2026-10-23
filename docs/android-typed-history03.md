# Android typed history

The typed history path retains callback facts independently of permission to
send. Each newly reserved typed attempt records its original configured origin
and enrolled signing point. Its callbacks receive a durable per-attempt arrival
ordinal in the same Room transaction as the immutable raw fact. Raw wall times,
including backward, zero or future observations, remain unchanged.

An outcome command uses the first authenticated assertion time rather than the
raw callback time. Before clock I/O, the journal retains the original source
event identity. A sent-segment assertion keeps that raw event identity. Complete
delivery and contrary-callback assertions have their own retained identities and
the exact raw facts from which they were derived. Complete delivery does not
invent missing sent callbacks. Timeout and crash evidence are supported by the
binary codec; their actual source producers are separate work.

The passive socket port correlates a fresh, durably entered request with the
actual original actor, configured origin, message, attempt, current connection
and lease. It supports actual line-activation versions 1 and 2 without widening
the current-content parser. A successful read requires a round trip of at most
two seconds and produces a short-lived RAM clock. Historical JSON or an entered
cold request cannot recreate that clock or its one-use transport ticket.

The first exact outcome command and its first-upload classification are committed
together before reporting transport may use them. The passive worker then commits
an exact I/O envelope before its first upload. Reconnect, Stop and unknown results
preserve the original assertion bytes, identity and time. A possibly entered upload
is never automatically resent. Pending work is scanned in bounded pages; immutable
history has no lifetime row cap.

The distinct outcome request and acknowledgment use the same authenticated original
enrolled actor and configured routing origin. A successful acknowledgment records
only the immutable outcome receipt; it contains no clock, current permission,
refund or send capability. Submit status cannot acknowledge an outcome. Connection
and acknowledgment routing remain independent of withdrawn effect-health lifetimes.

Home's Message details offers **Sync delivery updates**. Each explicit action checks
one page of at most sixteen saved assertions under the actual current same-actor
connection. An uncertain prior upload can be replayed only with its exact original
assertion, event and time; the new envelope carries the actual current connection
epoch and receives its own durable I/O burn. It never starts a connection, creates
an assertion or retries an SMS. Unconfirmed updates stay saved for a later explicit
sync. Room 24 to 25 adds two empty reporting tables. An upgraded completed assertion
without its original first-upload classification requires explicit sync; absence of
that new row is not evidence that no earlier upload occurred.

Closing before platform entry first withdraws the caller's RAM lifetime. The
same Room writer then chooses between entry and a permanent closing barrier.
The barrier wins before clock waits and cannot regain entry after a late ACK or
restart. A fresh passive clock may finalize the exact negative record only if
there are still no entry, callbacks or conflicts and its time is at least the
original submit observation. Missing time, storage or actor continuity leaves
the barrier pending. It does not prove server acceptance or release server busy
state.

Room 22 to 23 adds nullable origin and ordering provenance for existing rows and
two initially empty history tables. Migration does not adopt a reporting host,
backfill a callback order, create a key, or initialize a capture counter. Old
rows without that original provenance remain historical and unsupported by the
new producer.

This component prepares local assertion packets and negative closure records and
mounts the passive outcome uploader. The [positive submit consumer](android-typed-submit03.md)
is separate, and signed closure-proof transport remains unfinished. A schema, local ACK hash, clock or
retained history row provides no radio permission. Source review and local JVM
execution are distinct from server integration, device and carrier acceptance.
