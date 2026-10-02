# Initial conversation reader authority candidate

This fixture-tested candidate composes an existing independently compared account
root with an initial reader manifest. It creates no credentials, archive keys or
phone keys. A paired phone alone supplies neither reader authority nor content
consent. Ordinary browser setup remains unavailable without the owner's existing
root custody, independently compared phone export and archive receipt.

The public `ZTCG01` proposal uses these ordered fields, with big-endian numbers:

| Field | Encoding |
|---|---|
| Magic | `ZTCG` followed by byte `01` |
| Account, owner session, device, line | Four nonzero 16-byte UUID values |
| Paired phone signing fingerprint | 32 bytes, SHA-256 of canonical SEC1 |
| Line binding generation | Positive signed-storage-compatible u64 |
| Exact peer | u8 byte length and ASCII E.164 text |
| Owner origin | u16 byte length and canonical HTTPS origin |
| Independently compared root fingerprint | 32 bytes |
| Existing root pin | 94-byte profile-02 root pin |
| Issued and expires | Two positive u64 milliseconds |
| Unsigned manifest | u16 byte length and canonical unsigned profile-02 bytes |

The unsigned manifest must have the same account, generation one, version one,
zero previous digest, the existing pin's root point and exactly four active
records in canonical role order: phone reader (1, scope 4), account archive reader
(2, scope 12), phone signer (4, scope 2), owner root (6, scope 0). Roles 1 and 4
bind the exact device and line. Roles 2 and 6 have zero device and line fields.
Every record begins at issued and ends at expires, and the manifest lifetime is
at most 24 hours. No point is reused. The browser requests 30 minutes.

The fixture phone export is exactly 223 bytes: `ZTPK` plus byte `01`, account,
device, line UUIDs (16 bytes each), paired phone signing fingerprint (32 bytes), binding generation
(u64), phone reader point (65 bytes) and phone signer point (65 bytes). Its
comparison fingerprint is SHA-256 of UTF-8 `ZTSE/phone-keys/v1` plus NUL plus the
complete export. The owner must compare this fingerprint directly on the selected
phone before importing it. UUID equality and possession of an device credential do
not authenticate the public points' independent origin. Supporting a real phone
export requires a separate explicit phone action; this contract is not a claim
that every deployed phone exports it.

The browser imports an existing `ZTAB01` encrypted archive and checks its public
account, root fingerprint, origin, archive point and key ID against an independently
accepted archive receipt. This proves public identity consistency only. It does
not authenticate its AEAD ciphertext or recover the archive key. Session archive
unlock still uses the separate existing archive recovery artifact and verifies
the decrypted scalar's actual public point.

The offline custodian must reconstruct the canonical manifest using independently
selected public points and context and sign only the exact reviewed unsigned bytes.
The browser independently verifies the signature and rechecks the owner session,
root, paired phone signing key, line generation and expiry around signing and
installation. Server installation must perform the same checks in a transaction
with a provisioned nonrevoked authority and a version-zero compare-and-swap.
The install request carries the exact `expected_session_id` from the reviewed
selection; the authenticated current owner session must match it before any write.
A newly authenticated session cannot adopt another session's in-progress ceremony.
The accepted version-one manifest is reread and independently verified before
the browser presents its accepted checkpoint. Concurrent forks, changed keys,
revoked sessions, expiry and missing verification fail closed.

The root manifest does not sign the browser session, peer, line binding generation
or paired phone signing fingerprint. Those fields are contextual review and authenticated server
fences, not signed content consent. Separate browser content consent, activation,
explicit phone approval, installation and session signer enrollment remain
required before capture or replies.

The deterministic synthetic public codec vector is
[`conversation-genesis-01.json`](../v1/vectors/conversation-genesis-01.json).
