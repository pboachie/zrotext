# First-origin device protection setup

The experimental protection-origin control installs metadata for a fresh Android
protection setup. It is separate from line registration, profile election,
conversation consent and the capture counter. An opening or accepted receipt
provides no message, capture, signing-key recovery or radio permission.

The server requires the distinct protection-storage capability and an actual
current authenticated device connection. It retains the enrolled point that
verified the socket proof, compares it with the locked current key, and copies
an approved pairing's original public evidence before that pairing is pruned.
A current key or an empty local database cannot establish that missing history.
Pre-existing installations with unproven original protection keys require
recovery; this control does not adopt their current aliases.

The phone retains one installation-wide setup command before its first request.
The server commits its once-only opening before any provider key operation. Each
of four provider operations has its own irreversible local reservation: HMAC,
journal AES, withdrawal-sender AES and a distinct canary signing key. The same
opening binds the contextual HMAC probe and the ordered two-purpose AES probes.
Provider entry with an unknown result never permits another generation attempt.
Two separately reserved signatures bind the exact association and fresh server
challenge. The server accepts the complete original packet atomically with its
receipt. Installing local expected tags requires that receipt, both original
signatures, the retained local provider results and independent existing-key
probe checks. It does not clear an earlier suppression quarantine.

The ordinary socket wire uses the closed `protection_origin_*` request family;
it does not require profile03 negotiation. Requests and actual producer replies
fit the existing 4096-byte ordinary frame limit. Canonical UUID, base64url,
decimal time, required-null and duplicate-field rules are defined in
[the control schema](../protocol/v1/device-protection-control-v1.schema.json).
The [public synthetic proof vector](../protocol/v1/vectors/device-protection-origin-v1.json)
checks the 329-byte association, 393-byte core and 521-byte two-signature packet.
It proves no Android provider custody or current server permission.

A proof's original acceptance window is at most thirty seconds and is also
bounded by the actual device lease and hosted backend expiry when applicable.
An exact retry returns its original challenge without renewing that window.
Historical status does not supply a new signing clock. A later explicit action
may install an already accepted original after that window only with a fresh
same-original, nonretired actor status and every original local proof fact.
No status alone recreates keys or authorizes installation.

If the first proof request's reply was lost before any local challenge or
signature existed, same-connection `not_found` remains unknown. Explicit recovery
requires a genuinely later claimed connection, its strictly greater epoch and a
fresh correlated locked READ COMMITTED absence check. The atomic writer still
refuses any existing attempt; it can fix only the same original opening and
provider association. Other proof recovery must name the exact expired,
unaccepted predecessor. Every old command, provider burn and proof remains
retained. Revoking, deleting or replacing the original enrolled actor permanently
retires the origin, including when its point is later restored.

Each authenticated request consumes its ordinary management or read budget in a
separate committed transaction before business parsing or proof verification.
Explicit proof replacements have an additional fixed-window budget across
connections. A refusal cannot reset those budgets or retry a provider operation.
Schema capability, local journal facts, authentication, current server checks and
provider possession remain independent requirements. Source and synthetic tests
do not establish a supported device installation or hosted end-to-end journey.
