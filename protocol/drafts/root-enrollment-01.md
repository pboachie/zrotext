# Generation-one owner root enrollment: candidate possession transcript

**Proposed, dormant contract.** This defines a possession transcript for the
existing [RootPin02 candidate](zt-sealed-draft-02-manifest-candidate.md).
It does not enroll a root, establish trust, enable a route, or close Q1, Q3 or
Q10 in the [decision log](zt-009-decision-log.md). There is no HTTP endpoint,
database write, client custody implementation or sealed runtime caller.

## Pin and independent context

The exact 94-byte pin remains `ZTRP[4] || 02[u8] || account_id[16] ||
generation[u64be] || root_public_point[65]`. This ceremony accepts **generation
one only**, a nonzero account, and an on-curve uncompressed P-256 point beginning
with `04`. No trailing bytes or alternate point encoding is accepted.

The fingerprint is `SHA-256("ZTSE/root-pin/v2\0" || exact_pin)`; `\0` denotes one
zero byte, not two printable characters. This binds account, generation and
point. It is unrelated to the SMS owner-approval key fingerprint and role.

The verifier requires an independently supplied expected challenge containing
every field below. The expected account must also match the pin. Constructing
that expectation from received proof bytes would discard the context check.
This module cannot authenticate the source of its arguments.

## Exact unsigned bytes U

Integers are unsigned big-endian. UUIDs are raw 16-byte identities, not text.
All four UUID fields must be nonzero; this grammar does not impose a UUID version.

| Offset | Field | Width |
|---:|---|---:|
| 0 | Magic `ZTRE` | 4 |
| 4 | Ceremony version `01` | 1 |
| 5 | Account ID | 16 |
| 21 | Owner user ID | 16 |
| 37 | Owner session ID | 16 |
| 53 | Challenge ID | 16 |
| 69 | Challenge nonce | 32 |
| 101 | RootPin02 fingerprint | 32 |
| 133 | Issued time in milliseconds | 8 |
| 141 | Expiry time in milliseconds | 8 |
| 149 | Origin byte length N | 2 |
| 151 | Canonical origin | N |

`1 <= N <= 512`; the exact total is `151 + N`, at most 663 bytes. Reject larger
input before parsing or allocating. The origin grammar further constrains the
minimum valid length. No optional fields, unknown version, padding or trailing
bytes are accepted. The future challenge issuer must generate a uniformly random
32-byte nonce; the pure validator checks its width, not its entropy.

Times satisfy `1 <= issued < expires <= 2^63 - 1` and
`expires - issued <= 300000`. Given a caller-supplied trusted `now`, require
`issued <= now < expires`, with no future grace. Validation cannot establish a
trustworthy clock or make a challenge single-use.

## Canonical service origin

The origin is ASCII and must equal the existing server's canonical HTTPS origin
serialization byte-for-byte: parse using the existing `url` crate, require
HTTPS, a host, empty username, no password, an implicit `/` path, no query or
fragment, and require `origin().ascii_serialization()` to equal the original
input. The input contains **no trailing slash**; URL parsing supplies the
implicit path. The API rejects aliases rather than normalizing them.

This requires lowercase scheme/host, ASCII IDNA A-label form, omission of default
port 443 and canonical decimal nondefault ports. Whitespace, Unicode, backslashes,
userinfo, paths, queries and fragments are refused. IPv4 and bracketed IPv6 are
allowed only in the URL parser's canonical spelling. This is an identity
serialization rule, not DNS validation, reachability, TLS validation or an SSRF
policy; no network request is made. A trailing DNS dot accepted by that serializer
remains a distinct origin and is never stripped. Both expected context and owner
intent must match the exact spelling.

The owner client must select/verify its intended service origin independently;
an attacker-chosen origin supplied with a challenge is not authenticated intent.

## Possession signature

The exact signing transcript is:

```text
T = "ZTSE/root-enroll/v1\0" || u32be(length(U)) || exact_received_U
```

The domain is exactly 20 bytes; the largest transcript is 687 bytes. Sign T with
ECDSA P-256/SHA-256. The signature is supplied separately as exactly 64 bytes,
`r[32] || s[32]`. Require `1 <= r < n` and `1 <= s <= floor(n/2)` before
verification. Reject DER, zero/out-of-range scalars and high-s signatures; never
normalize a received signature. Signers may canonicalize their own signatures.
Verification hashes received U, not a parsed-and-reserialized replacement.
Changing framing, domain, context or any field invalidates the proof.

## What success means

`sealed_root_enrollment::verify` returns a `PossessionProof` containing the public
fingerprint. It supplies no manifest authority, enrollment token or permission
to insert an authority row. Repeated verification succeeds: one-time use requires
future transactional challenge consumption.

A future server ceremony must independently authorize the live owner/session,
perform fresh MFA, recheck expiry after lock waits, prevent role aliases, enforce
immutable enrollment history and atomically consume the challenge before any
effect. Those rules are outside this pure module. Existing SMS approvals cannot
be reused as a content root. Generation changes, reset and rotation are refused
by this contract and need their own reviewed continuity/recovery flow.

Clients must separately compare the full fingerprint through an authenticated
owner-controlled channel distinct from the relay directory and QR payload, and
persist trust before any effect. A relay-delivered browser can be replaced by a
malicious relay; this transcript does not solve independently delivered client
code, key custody, lost keys, recovery, trusted time or rollback. A public
fingerprint card is not a private-key recovery kit.

## Tests

The public [fixture](../v1/vectors/root-enrollment-01.json) was generated with an
ephemeral Node/OpenSSL P-256 key; only public bytes and signatures are retained.
Rust checks parsing, encoding and possession through
`cargo test --locked -p zrotext-server --test root_enrollment`.
An independent Node/OpenSSL consumer checks exact offsets, fingerprint,
transcript, signature and altered-field/high-s rejection. It runs through the
existing `test_ztse_draft_vectors.py` CI discovery, without SDK modifications or
new dependencies. These synthetic tests do not demonstrate an independent human
fingerprint comparison, MFA/session ceremony or real enrollment.
