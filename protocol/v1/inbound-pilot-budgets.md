# Inbound pilot storage budgets

Fresh authenticated, signed pilot events have a durable fixed-window budget of
200 per device and 1,000 per account in 24 hours. Account scoping prevents one
tenant from spending another tenant's allowance; device rotation cannot evade
the account allowance. UUID and sequence changes do not reset either budget.
The window starts on the first accepted event and renews after 24 hours, rather
than at midnight. These are conservative pilot safety defaults, not billing
entitlements. Review legitimate traffic before expanding the pilot.

Consent changes do not spend that shared budget. Attempt-bound `opt_out`,
`opt_out_review` and `opt_in` events, and line-bound unsolicited opt-outs, have
their own budget of 10,000 per device in 24 hours with no account-wide ceiling.
A busy account, or another device's junk events, therefore cannot defer a STOP
or START; only a single device sending more than 10,000 consent changes in one
window is deferred. That limit is far above the replies one phone receives and
still bounds the rows a misbehaving device key can write.

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

The dormant sealed candidate ingest transaction has no transport caller yet.
It charges the same shared account/device budget after authenticating and
deduplicating an event and before its INSERT, in the same transaction, and
rechecks the session lease before commit. An exact stored replay is free, and a
concurrent writer that stores the same event first returns the charge.
Readiness alone is not admission.
