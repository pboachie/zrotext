# Android protection setup journal

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

Opening packets are retained candidates. Journal state, row absence and a stored
packet are not first-origin proof or permission to call a provider. A separately
authenticated control adapter must verify the original server opening and present
device before generation, then the exact accepted association and actual existing
key probes before installing protection. That adapter and positive key/pin factory
are not implemented by this journal component. Passive recovery classification
does not invoke providers, clear quarantine, submit messages or return readiness.

Older aliases or protected history without their original continuity evidence need
separate recovery. The journal does not adopt them, replace pairing, discard local
STOPs or reconstruct counters from empty tables or a server maximum. Existing
suppression and capture-routing history is retained by the additive migration.
