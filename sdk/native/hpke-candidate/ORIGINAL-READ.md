# Verified original HTTPS reads

This experimental profile02 integration joins the dedicated role3 HTTPS
transport, independently enrolled accepted-history checkpoint, phone selection
verification and native envelope reader. It does not send SMS, consume an event,
authorize a workflow proposal or use an owner credential.

Go `OriginalCurrentClient.ReadSoftware` and Rust
`OriginalCurrentClient::read_software` explicitly accept an exportable recipient
scalar. Windows `ReadHardware` / `read_hardware` require the qualified protected
recipient; they cannot export it or fall back to a software key. Existing runtime
requirements remain Go 1.26.9 and Rust 1.97.1.

Supply the independently enrolled root/fingerprint, selected grant scope,
existing `OriginalReplyCheckpoint`, HTTPS transport, role3 credential and trusted
clock to the current client. A read takes the selected event and an optional
accepted manifest baseline: Go zero / Rust `None` chooses the oldest retained
version inside the service's 32-manifest window. An explicit baseline must exist
in that window. Each overlapping manifest is independently reverified and must
match the retained version/digest. Server acceptance timestamps remain separate
from the monotonic local checkpoint clock.

The closed response must correlate the event, accepted historical and activation
manifests, dual phone signatures and exact encrypted envelope. The client commits
the verified current proof before opening. After authenticated decryption it
requests and durably verifies fresh current authority; revocation, changed
manifest, expiry, rollback, failed persistence or HTTP failure suppresses
plaintext. Neither request retries automatically. Concurrent use refuses; an
uncertain checkpoint update requires reconstructing the client from the existing
checkpoint. The final proof is a point-in-time check, not perpetual authorization.

The result contains transient plaintext, event, SHA-256 of the exact envelope,
accepted request baseline and final authority snapshot. Rust plaintext is
zeroized on drop. Go returns an immutable string that callers must treat as
sensitive; it cannot promise erasure of application copies. Existing reader
buffers are cleared on failed final checks. Trusted checkpoint paths and the
documented whole-database rollback limitation remain unchanged.

`test-original-read.py` pins the maintained signed fixture producer and runs
synthetic local TLS. It checks genuine ciphertext opening, history overlap,
correlation, canonical encoding, both phone signatures, ciphertext corruption,
final authority refusal and zero retries. `--hardware` performs three separate
Windows PCP cases with newly created native public points and no selected private
scalar: success, final service refusal and corrupted ciphertext. Private receipts
precede key creation; exact owned deletion and refused reopen are required.
Hosted CI runs software cases on Linux and Windows and does not claim TPM
qualification. Local hardware tests require a qualifying Windows provider.

Page metadata, authenticated consume/status, workflow proposal submission,
profile03 original grants, contact/template parity and installed-archive
qualification of these new methods remain separate work. No package is published
by these checks.
