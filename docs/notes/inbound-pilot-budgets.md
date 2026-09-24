# Inbound pilot storage budgets

Fresh authenticated, signed pilot events have a durable fixed-window budget of
200 per device and 1,000 per account in 24 hours. Account scoping prevents one
tenant from spending another tenant's allowance; device rotation cannot evade
the account allowance. UUID and sequence changes do not reset either budget.
The window starts on the first accepted event and renews after 24 hours, rather
than at midnight. These are conservative pilot safety defaults, not billing
entitlements. Review legitimate traffic before expanding the pilot.

Both charges, event insertion and webhook queue insertion share one PostgreSQL
transaction. Invalid signatures, conflicting replays, stale sessions and rejected
charges leave no partial event, queue entry or budget consumption. An exact
accepted replay is free and can recover a lost ACK even after the budget fills.
The existing socket handler closes without ACK on ingest rejection; devices must
retain unacknowledged events and retry after the window renews, with backoff.
Reconnection does not reset the durable budget.

Endpoint creation already serializes per account and caps endpoints at eight.
This bounds fresh pilot fanout at 8,000 queue entries per account per window.
Budgets limit growth rate, not lifetime storage; retention remains an operational
requirement. They do not limit replay frame rate or signature-verification CPU.

The sealed inbound module currently provides identity readiness only and cannot
ingest content. Any future sealed ingest path must apply durable account/device
budgets in the same transaction after authenticating and deduplicating an event,
and recheck the session lease before commit. Readiness alone is not admission.
