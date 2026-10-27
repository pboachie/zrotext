# Candidate profile03 conversation interval

This additive source dependency under #1594/#1566/#1054 preserves all ZTCA01/02
bytes and domains. The optional library integration remains absent from main
startup; this contract is not current send permission.

The exact ZTCA03 header is `ZTCA || 03 || 03 || 03 || 00`. Follow it with
nine nonzero UUIDs: account, device, line, immutable binding, interval, receipt,
owner user, owner session, durable opening. Then eight positive signed-range
u64be values: binding generation, vault generation, manifest version, selection
epoch, issued-ms, setup-expiry, interval-start, interval-end. Then thirteen raw32
values: physical reader, archive reader, phone role4 signer, browser role5 signer,
root fingerprint, manifest digest, election commitment, election bundle SHA256,
canonical owner-session digest, configured-origin digest, actual device-session
digest, physical-selection digest, CSPRNG nonce. Zero values refuse.

Then encode u8 length plus exact `conversation-content03-v1`, SHA256 of
`conversation_interval03::DISCLOSURE`, u8 peer length plus ASCII E.164 peer3..16,
u8 integration count0..6, and each connectorUUID16/readGrantUUID16/keyID32.
Mappings sort strictly by keyID with unique connector/grant IDs. Exact length is
692 + peer length +64*count, or695..1092. All other/trailing bytes refuse.

Interval start equals issued time. Setup lifetime is positive and at most five
minutes; interval lifetime is positive and at most24hours. Actual owner session,
selected key/manifest and physical lease bounds remain independently enforced.
Consent pins the actual current03 manifest and does not manufacture a successor.
An original enrolled/SEALED approval key does not substitute for role4 or role5.

The browser role5 signs `L(zrotext/conversation/request03/v1, statement)`.
After explicit phone disclosure and actual role4 custody/currentness, the phone
signs `L(zrotext/conversation/approve03/v1, statement || SHA256(ownerRaw64))`,
then `L(zrotext/conversation/install03/v1, statement || SHA256(ownerRaw64) ||
SHA256(phoneApprovalRaw64))`. L is existing label, one NUL, u32be length and exact
payload. All received P256 signatures are strict low-S raw64, never normalized.

The source verifier checks genuine manifest/election cryptography relative to
separately trusted current inputs. Actual cookie/origin/CSRF, fresh owner MFA,
authorized integration mappings, nonexportable browser/phone custody, immutable
ledger, one-use local journal, post-wait currentness and durable installed ACK
remain mandatory admission integration. No interval becomes active from a
constructor, a received phase, reader Ready03 or elapsed setup deadline. UNKNOWN
retains exact original bytes and signatures without automatic reopening.
