# Android protection setup and recovery

The setup guide places protection between browser pairing approval and SMS access.
The phone first starts an ordinary authenticated connection; that specific setup
action needs neither a selected SIM nor SMS permissions. Choose **Set up or check
saved protection** while the setup screen remains foreground. SMS receiving access
is requested only after the original installed protection has been verified again.
The UI's displayed status is not permission to skip that check.

Protection setup has one permanent local command for the installation. Its service,
account, device, setup, opening and command identities are retained before network
I/O. An exact retry reads the original record; selecting another service or line
does not replace it. The Room migration adds empty tables and creates no keys,
protection pin or capture counter.

Each canary, suppression HMAC, journal/inbound AES and withdrawal-sender AES provider
operation has a separate committed entry and an immutable public result. An entered
operation without a result is unknown. A restart preserves that state and may
reconcile the original result; it cannot authorize another generation call. Results
from another command, changed operation, skipped provider or changed result refuse.
No method deletes or resets the original command or these entries.

The actual ordinary socket adapter retains the exact existing point that signed
its device challenge. It correlates each closed control reply with the original
command, configured WSS origin, current connection and pending request. The server
must independently retain the genuine approved pairing before committing its
once-only opening. No conversation election or capture bootstrap is needed.
Opening packets, row absence and a stored packet alone authorize nothing.

The foreground worker verifies that opening before the four individual provider
calls. Each provider and each of the two proof signatures has its own permanent
entry. A returned result is appended to that exact entry even if setup was paused
while the provider was blocked; no next operation follows the withdrawn decision.
Leaving the setup pane or backgrounding the app withdraws that decision permanently.
Resuming allows a new explicit action, never revival of the old one.

Only a newly entered proof request can supply the setup clock: its actual
nonce-correlated round trip must take at most two seconds. Historical replies do
not renew the original thirty-second signing window. **Recover original setup
proof** explicitly requests a new nonce over the same retained provider results;
the server must close the exact prior unaccepted proof. It never generates another
key. An unconfirmed first request can use a new request only after an actual later
authenticated claim, a fresh locked exact-command absence read and no retained
challenge or signature. Same-connection absence remains unknown.

After acceptance, another fresh exact status read, both original signatures and
all four existing providers are required to install the association and expected
suppression identity in one Room transaction. A lost installation can be completed
after the signing window only from that same accepted original proof and local
history; it cannot regenerate or re-sign it. Every production suppression-key read
and effect lease rechecks the original proof/receipt, both AES probes, canary,
enrolled signer and unchanged rows. A known in-process negative receipt may resolve
its own sender token; that path grants no effect lease or cold-hold recovery.

Older aliases or protected history without their original continuity evidence need
separate recovery. The journal does not adopt them, replace pairing, discard local
STOPs or reconstruct counters from empty tables or a server maximum. Existing
suppression and capture-routing history is retained by the additive migrations.
Already-granted SMS access, pre-contract aliases, pruned pairing provenance or a
missing half of the original local history are explicit recovery-needed cases.
Do not uninstall, delete keys or clear application data to try to repair them.
The fresh setup path cannot adopt those aliases or clear a withdrawal quarantine.

This protection flow does not initialize the separate capture sequence allocator,
approve a SIM, restore an interval, send SMS or authorize content access. Those
boundaries remain separate. Source, JVM checks and a real installed-device journey
are distinct qualification scopes; none implies carrier acceptance.
