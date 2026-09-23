# ADR 0001: Runtime, authority, and ambiguous submission

Status: accepted, 2026-09-22. This records the original runtime and delivery-state decisions; later implementation may extend the described foundation.

## Runtime

Use a Rust workspace with a pure domain model, an Axum server, and a deterministic device simulator. PostgreSQL is the state authority. Kotlin/Compose is the Android telephony surface. The initial foundation exposed `/healthz` and `/readyz`; later routes are described in the current code and protocol docs.

The same server image accepts `SITE_ID`, `INSTANCE_ID`, `DATABASE_URL`, `DEPLOYMENT_EPOCH`, and `DISPATCH_ENABLED`. Each site may serve traffic once it can reach the same authoritative writer. `DISPATCH_ENABLED=false` in the Compose example. The two-hub Compose profile is a local wiring check, not independent geographic resilience.

## State and execution decision

The stable client message UUID and `(account_id, idempotency_key)` uniqueness live at the writer. Identical retries return the same message; a changed request under one key is rejected. A device connection increments a writer-owned epoch. Grants bind message, attempt, device, generation, session epoch, deployment epoch, recipient digest, and expiry. A hub without writer access issues no grants. A stale connection cannot dispatch after another hub acquires the device session.

The phone persists `submitting` before `SmsManager`. A successful sent callback means `submitted`, never `delivered`. Delivery needs its own callback. A crash or lost callback after intent becomes `unknown`; a late callback may reconcile it. Neither lease expiry nor site failover proves the radio did not submit. Once a grant exists, another attempt requires conclusive no-submit evidence or a new operator-initiated message with a duplicate warning. PostgreSQL transactions and the Android journal implement these rules.

```text
site A hub ── grant(epoch 4) ──> phone intent ──> radio call ──X ACK
                                         phone restarts → unknown
site B hub ── connect(epoch 5) ──> writer rejects new grant for same message
writer link lost ──> both hubs fail closed for new writes/grants
```

## Health, drain, and promotion

`/healthz` reports process liveness. `/readyz` returns 200 only when this instance reaches a writable PostgreSQL primary with the configured deployment epoch; otherwise 503. Public responses contain no internal IDs or topology. A graceful process stop drains new HTTP accepts via Axum shutdown. A draining hub stops issuing grants and closes sockets for reconnect. Worker readiness also requires a valid dispatch fence and bounded queue lag.

Automatic database promotion is excluded. A planned authority move must fence the old writer, reconcile grants and journals, promote exactly one standby, increment an externally controlled deployment epoch, then enable writes. A two-site partition cannot create two writers. No independent per-site queues are allowed.

## Persistence and migration boundary

The initial schema establishes authority, site, device-session, idempotency, and dispatch-fence records. Numbered migrations add message, attempt, and event tables through a locked migration runner; applications must not race migrations at startup in both sites. Schema changes require compatible rollout and an ADR update.

## Rejected alternatives

No automatic retry after an ambiguous radio call, no automatic database promotion without external fencing, no independently writable site queues, no runtime Redis/NATS/S3/Kubernetes, and no sealed-content implementation before byte-level review.
