# Dormant conversation activation contract

This contract is exercised by the explicit conversation simulator. No production
route, Android receiver, browser signer or radio transport consumes it yet.
Existing owner-signed manifest authority is required; activation creates no root
credential and grants no additional manifest roles. The simulator generates fresh
fixture keys and a temporary loopback transport only.

The canonical statement starts with `ZTCA` followed by byte `01`. UUIDs are their
16 network-order bytes. Every integer is an eight-byte big-endian positive signed
storage integer. Text uses a one-byte length followed by ASCII bytes; peer is
3–16 bytes of E.164 syntax, site and instance are 1–64 graphic ASCII bytes.

Fields occur in this exact order:

1. Account, device and line UUID; line binding generation.
2. Interval, receipt and originating browser session UUID; nonzero 32-byte nonce.
3. Pending expiry in Unix milliseconds; exact peer; disclosure version
   `conversation-content-v1`; SHA-256 of the exact disclosure text in the vector.
4. Exact 32-byte archive reader ID and phone signer ID; trust generation.
5. Predecessor version and 32-byte digest; activation version and 32-byte digest.
   Activation version equals predecessor plus one.
6. Connection epoch, deployment epoch, site and instance.

Trailing bytes and noncanonical encodings are rejected. Approval signs
`zrotext/conversation/approve/v1` plus NUL, a four-byte big-endian statement
length and the complete statement. Installation uses the distinct
`zrotext/conversation/install/v1` plus NUL domain with the same length and bytes.
Both signatures are 64-byte P-256 IEEE P1363 ECDSA signatures with low S. The
statement digest is SHA-256 of its approval transcript. The cross-language vector
is [conversation-activation.json](vectors/conversation-activation.json).

The server stores immutable scope and verified activation manifest provenance.
`pending` can become `install_pending` only after exact phone approval and owner
manifest admission. `install_pending` can become `active` only after exact phone
installation acknowledgment. Initial approval and installation require the exact
signed connection/deployment tuple. Duplicate acknowledgments are idempotent.
An already active installation may recover under a renewed, authenticated current
phone lease, with the same immutable consent and current exact reader authority.

Server acceptance and installation alone never make the phone journal eligible.
The phone must verify a fresh, challenge-bound active response with an authenticated
transport adapter. The explicit simulator signs a separately named **fixture**
lease proof; this is not a shipped response-signing scheme or credential. Phone
admission measures the at-most-60-second lease from request start and does not
extend it through duplicate responses.

The journal reserves the first PDU identity durably before protecting its body.
It captures only under its verified active scope. Retry retains the original
receipt time, capture identity, interval and protected bytes. The simulator sends
the resulting profile-02 envelope through real sealed ingest and returns the
stored ciphertext for independent HPKE/body decryption. This proves synthetic
content handling, not device reception or carrier delivery.

New ingest requires the originating browser session, current manifest, current
phone lease, exact peer/line/generation, phone signer and exactly one selected
archive reader. Manifest authority locks precede account locks. Temporal gates
run again after storage waits. Original verified ingest provenance is immutable.
Benign manifest renewal can authorize retained history using that original
snapshot and the current exact reader authority; ciphertext is not rewritten.
Rotated/revoked root generations or unavailable current keys cannot read history.
Already queued older-manifest envelopes are not admitted through a new interval.

Stop closes admission and preserves authorized retained history. Withdrawal also
denies history; it does not mean deletion. Origin expiry/revocation closes capture,
while a fresh owner session can read retained history when current key authority
permits. The legacy selection reader refuses events carrying interval provenance.
Inventory exports bounded interval/event metadata, excluding statements, key
material and content. Retention removes provenance after body purge and closed
interval metadata after 30 days without retained provenance. Guarded account
deletion inventories both tables and retains everything when existing immutable
trust or audit blockers refuse deletion.

Production gates remain: approved policy/disclosure publication; production owner
signer custody and authenticated phone/browser adapters; shared receiver/Pause
gate wiring; durable offline closure across restart; browser profile-02 reading;
exact user-confirmed send; physical-device evidence. No simulator pass enables
production or establishes Google approval.
