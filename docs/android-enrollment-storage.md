# Android enrollment storage checks

Explicit reader/root enrollment separates full validation from the short storage
lifetime guard. Full checks resolve the authenticated host, exact line record,
selected subscription, ordinary permissions, actual SIM/profile continuity and
existing key identities before and after the storage operation.

The production factory owns real subscription, permission and selected-preference
callbacks. Registration starts on main and must observe its actual first
subscription callback before enrollment continues. Each IO thread must complete
full validation in that same captured callback epoch before entering protected
storage. An event withdraws the old epoch at callback entry; another action or
thread cannot renew it. Close withdraws immediately before asynchronous cleanup.

Checks while the root storage monitor is held use only this callback lifetime,
foreground state, authenticated host and exact existing opaque SIM/profile lease
where applicable. They perform no Room query, framework read or key lookup. The
final storage precommit repeats the RAM checks and root-comparison receipt guard.
Supported legacy physical-SIM enrollment retains its full outside-storage checks
and also uses the owned callback epoch; a cached preference is never continuity.

A changed observation, lost permission/host or foreground exit pauses the pending
operation. Reopen enrollment for a fresh explicitly validated callback lifetime.
Existing keys, compared roots, completed records and unknown effects are retained.
The guard provides local lifetime checks, not Android attestation or atomic
carrier truth. It grants no installation, content consent, Ready or SMS permission.
