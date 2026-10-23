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

The first exact outcome command is committed before any later reporting
transport may use it. Reconnect, Stop and unknown results preserve its original
bytes, identity and time. Completed commands are not regenerated or automatically
resent. Pending work is scanned in bounded pages; immutable history has no
lifetime row cap.

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

This component prepares local assertion packets and negative closure records.
The independently verified positive submit factory, outcome uploader and signed
closure-proof transport remain separate. A schema, local ACK hash, clock or
retained history row provides no radio permission. Source review and local JVM
execution are distinct from server integration, device and carrier acceptance.
