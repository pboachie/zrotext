# Candidate reviewed-send authorization for profile03

This describes the historical ZTRI01 component. The explicit
[V2 component](profile03-reviewed-intent-v2-candidate.md) has a separate header,
signature domain and no plaintext commitment. V1 APIs and vectors retain their
exact historical grammar; corrected production composition must refuse new V1
effects rather than reinterpret these bytes.

This additive, unmounted dependency addresses #1475 under #1054. It specifies a
reviewed intent, not a new envelope, election, dispatch grant or live permission.
Existing ZTCS01, profile02, E500, envelope03, CurrentAuthority03 and the closed
25-field grant03 grammar remain unchanged. No route, storage adapter, migration,
owner UI, maintained receiver or radio execution is mounted here.

## Trusted context and custody boundary

`ReviewContext03` in the [TypeScript dependency](../../sdk/typescript/src/reviewed-intent03.ts)
captures an independently authenticated current adapter read. Its local handle
only identifies a private snapshot; callers cannot turn arbitrary records into
authenticated server authority by invoking its constructor.

Inputs are the existing immutable current selection plus its live permission
comparison/deadline, positive account-selection epoch, genuine manifest/election
proof handles, exact owner account/user/session, configured canonical HTTPS
origin, approved conversation interval/peer, role5 signer and exact reader set.
The constructor recomputes rather than accepts these commitments:

- Owner-session digest: SHA256 of the existing
  `L("ZTSE/line/payload-profile/owner-session/v1", account16 || user16 || session16)`.
- Origin digest: SHA256 of the exact configured canonical HTTPS origin UTF-8
  serialization without a trailing slash. Normalizing a request-origin string
  into a match does not authenticate it.

Here `L(label, bytes)` means ASCII label, one NUL, u32be byte length, then bytes.
The authenticated adapter must separately enforce current origin, owner role,
CSRF, session/MFA/step-up policy, approved interval and all permission fences.
Canonical digest equality does none of this. Positive account-selection epoch
and interval ID must originate in the actual locked records. Current interval
start/end remain independently checked permission bounds, not client claims.

All closed records/scalars and genuine ordinary Uint8Array buffers are captured
and copied before asynchronous work. Shared/disguised buffers, accessors, extra
fields and sparse/extended recipient arrays refuse. Manifest/election runtime
brands are checked. Returned projections own copies of private snapshots.

## Candidate binary intent

This candidate elects the distinct header `ZTRI || 01 || 03 || 03 || 00`:
four ASCII bytes, operation version1, envelope profile3, manifest profile3 and
one reserved zero byte. This is a new candidate allocation, not a deployed
operation or a reinterpretation of existing bytes. No external kind registry
number or HTTP route is allocated.

After the eight-byte header, concatenate the following rows in order. There is
no JSON normalization, optional ceiling, padding or trailing data. Fixed UUIDs
are nonzero raw16. Digests/key IDs are nonzero raw32. Every integer is u64be in
`1..=2^63-1`; JavaScript inputs require bigint, with no coercion.

| Group | Exact field order |
| --- | --- |
| Eight UUIDs | account, device, line, immutable binding, owner user, owner session, conversation interval, message |
| Eight integers | binding generation, vault generation, manifest version, account-selection epoch, message observed-ms, message expiry-ms, review issued-ms, review expiry-ms |
| Eleven digests | selected physical reader key ID, root fingerprint, manifest digest, election commitment, election bundle SHA256, canonical owner-session digest, configured-origin digest, role5 signer key ID, exact envelope SHA256, exact unsigned-envelope SHA256, strict-UTF8 body SHA256 |
| Peer | u8 length then exact ASCII E.164-shaped bytes: `+`, first digit1..9, remaining decimal digits; total length3..16 |
| Recipients | u8 count2..8, then each role-u8 and raw32 key ID, strictly ascending by role then unsigned lexicographic key ID |
| SMS ceiling | One mandatory integer byte1..6, with no unsigned competing field/header/default |

The complete intent length is `555 + peer_length + 33 * recipient_count`:
624..835 bytes. Recipient policy is exactly one role1 physical recipient matching
the current selected reader, device and line, exactly one role2 archive, and at
most six role3 integrations. Repeated or unsorted role/key pairs refuse; the
actual envelope wraps must equal this exact set and order. The current verified
manifest independently authorizes every selected key and the role5 signer.

The body digest is computed locally from nonempty strict UTF-8 text up to32768
bytes, excluding NUL, leading BOM and unpaired surrogates. It is owner-attested
opaque metadata to the server, which cannot independently derive it from the
ciphertext. This pure dependency neither decrypts nor confirms the visible body.
Its relation to the actual composer/plaintext and explicit visible confirmation
is a separate browser/native custody obligation. No plaintext belongs in the
admission request, sidecar, persistence or logs.

## Signature and envelope verification

The exact signature transcript is:

```text
L("zrotext/conversation/reviewed-send03/v1", exact_intent_bytes)
```

Use ECDSA P-256/SHA256 under the currently selected manifest role5 signing key,
strict canonical low-S raw64, never DER or normalized received signature bytes.
This domain is separate from existing confirmed02 and envelope03 signatures.
The dependency verifies the real role5 envelope signature under its existing
`ZTSE/sign/v3` domain as well as the new intent signature. It checks exact
envelope header, lengths, protected identity/time/peer, ordered wraps, P-256
ephemeral points and both recomputed ciphertext commitments. No valid intent
signature can rescue an invalid envelope or authorize a different reader set.

## Time and immutable identity

At the original signing/admission comparison instant `trustedNow` require:

```text
observed <= reviewIssued <= trustedNow < reviewExpiry <= messageExpiry
0 < reviewExpiry - reviewIssued <= 30000
0 < messageExpiry - observed <= 900000
```

The comparison clock must also be at least the context's captured clock. A later
context cannot be backdated to validate an earlier review/admission; historical
delivery verification needs its separate authenticated acceptance receipt.

Observed time must be at least the approved interval start, the current clock
must be inside that interval, and message expiry must not exceed its end. These
are explicit new reviewed03 interval-lifetime bounds; they do not modify old02.
Message expiry must not exceed current permission, selected signer/readers,
manifest or approved interval deadlines. Observed time must fall within all
selected outbound key lifetimes, preserving existing03 authorization. There is
no new `manifest.issued <= observed` rule. Current manifest comparison rules
and authenticated current selection are still independently required.

This is an explicit **new reviewed03 timing policy**: short review authorization
of at most30 seconds, with a separate message lifetime of at most900 seconds.
Existing confirmed02 limits the entire observed-to-message-expiry lifetime to
30 seconds; this candidate does not claim unchanged confirmed02 semantics.
Refreshing current permission must not extend either original signed deadline
or change selection, epoch, owner/session, interval, recipient or message identity.

`verifyReviewedIntent03` uses the original signing/admission clock. A future
delivery verifier must independently establish acceptance during that original
review window from an authenticated immutable receipt, then check the current
message deadline and current delivery authority. It must neither treat the old
clock as present permission nor demand a newly renewed review as an implicit
retry. This slice does not implement that receipt or later verifier.

Do not bind transport connection/site/deployment epochs into this message
intent. The immutable physical reader/binding is bound here; the later signed
grant/fetch independently authenticates its current full lease, site, deployment
and key. A reconnect cannot silently rewrite reviewed message identity.

## Integration obligations and failure cases

The SDK exports only from its new module, leaving the shared index untouched.
`encode/decode` provide structural bytes; `prepare` performs local commitment
checks; the private verified handle proves component cryptography relative to
explicitly trusted context/time. It is not a browser one-use ticket, signature
consent, DB read, nonce consumption, commit, quota reservation or replay ledger.

Future signing/admission must re-read and recheck authenticated permissions,
selection and epoch under the qualified production writer fence. Persist exact
intent/signature/envelope and the single authenticated ceiling atomically with
the accepted identity and original acceptance time. Exact replay must compare
every immutable field and preserve redaction/tombstones. UNKNOWN never permits
automatic recompose, resend, renewed review or key/identity substitution.

Future fetch must transport exact intent and signature as an explicitly elected
sidecar. The independent receiver must verify its provenance and compare the
existing signed grant ceiling with the same authenticated intent ceiling before
any radio effect. Merely adding a field to the closed grant03 grammar, trusting
an unsigned client ceiling, or upgrading old NULL rows is not compatible.

Acceptance includes canonical vectors and real signed/encrypted03 composition;
ceiling1/6 positives and missing/null/0/7/fraction/string/boolean refusals;
identity/epoch/session/origin/interval/message/body/wrap mutation; wrong domain,
key, low-S and real envelope signature; expiry/overflow/lifetime boundaries;
async alias mutation; malformed/trailing/duplicate framing; and replay against
a different current context. Successful component tests establish no mounted
production adapter, Android custody, carrier delivery or store-review readiness.
