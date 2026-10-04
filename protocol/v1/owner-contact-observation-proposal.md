<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Proposed owner contact reader observation

The `http_owner_contact_observation` library router is **unmounted**. The ordinary
server has no route, switch or capability that enables it. This proposal depends
on the existing contact-reader-statement manifest record inspection. It observes
public records for an already enrolled account; it enrolls no root or reader.

## Request

`GET /v1/owner/contact-reader-observation` accepts no query or JSON. Exactly one
`x-zrotext-contact-reader` selects a nonzero 32-byte account archive reader ID.
Exactly one `x-zrotext-root-fingerprint` carries a nonzero 32-byte fingerprint
that the application has independently compared. Both are canonical padded
standard base64, exactly 44 ASCII characters. Aliases, extra values and bounds
violations are refused before database acquisition. Equality with stored trust
does not prove that the application actually performed independent comparison.

The existing owner session cookie and session-bound double-submit CSRF cookie
and `x-zrotext-csrf` header are required. Initial authentication checks actual
membership, verified user, enabled account, session revocation, absolute and
idle expiry. It uses the maintained authentication functions, with no alternate
principal constructor. Same-origin GETs need no Origin header. This router adds
no CORS grants. Any Authorization header is refused, including a bearer beside
cookies; shared authentication's cookie/header parsing policy is unchanged.

Transfer-Encoding is forbidden. Content-Length is absent or exactly one `0`;
noncanonical zeroes, invalid lengths and multiple values are refused. After
actual owner authentication, the body must finish within one second and contain
zero bytes. An unfinished stream or any byte is refused without buffering a
payload. No caller supplies an account, user, session, time or root point.
HEAD, POST and other unsupported methods return405. All candidate outcomes,
including authentication, parser, method and temporary errors, carry
`Cache-Control: no-store`.

## Closed public JSON

Success has `Content-Type: application/json`. These are the complete top-level
fields, in serializer declaration order:

| Field | Source and exact representation |
| --- | --- |
| `account_id` | Actual authenticated account; canonical lowercase UUID |
| `root_pin_b64` | Current immutable94-byte pin;128 padded base64 characters |
| `root_fingerprint_b64` | Current32-byte fingerprint;44 characters |
| `trust_generation` | String `"1"`; other generations refused |
| `manifest_version` | Positive signed64-bit integer as canonical decimal string |
| `manifest_digest_b64` | Current32-byte semantic digest;44 characters |
| `manifest_b64` | Exact signed current bytes; at most11223 decoded bytes/14964 base64 characters |
| `observed_ms` | Actual database comparison time; positive signed64-bit decimal string |
| `manifest_issued_ms` | Signed issued time; positive signed64-bit decimal string |
| `manifest_expires_ms` | Signed expiry; positive signed64-bit decimal string |
| `signed_until_ms` | Minimum of signed manifest, selected reader and root-writer expiries |
| `reader` | Selected account archive role2/scope12 public record |
| `root_writer` | Account root-writer role6/scope0 public record |

Each key object has exactly `key_id_b64` (32/44), `public_point_b64` (uncompressed
P-25665/88), `from_ms` (nonnegative signed64-bit decimal string) and `until_ms`
(positive signed64-bit decimal string), in that order. Its interval must include
the comparison time. The maintained signed manifest parser enforces its own
stricter current9751-byte maximum and existing issued-time grace; this proposal
does not widen it. The response has a20KiB UTF-8 byte maximum and is buffered
before publication. Overflow is refused; values are never truncated.

There are no owner/session identifiers, private keys, ciphertext, contact
plaintext, custody artifacts or permission flags. Fields named `current`,
`allowed`, `validForMs` or a session/MFA lease are absent. A client must verify
the copied signature, independent root pin, records and retained history with
the existing verifier. Returned JSON is neither a branded authorization object
nor evidence of private-key possession.

## Transaction and lifetime

An actual READ COMMITTED transaction sets local lock timeout3s and statement
timeout5s. It takes the existing current authority row FOR UPDATE, verifies the
stored pin, generation, version, digest and manifest at actual database time,
then checks the real current owner with the existing ordinary joined SELECT.
The account-only record inspection calls the existing manifest helper, requires
generation1, selected active role2/scope12 and active root6/scope0, and uses the
current-row/time recheck with no high-water write. No envelope or phone identity
is synthesized.

After bounded copying/encoding, the actual record inspection and owner SELECT
repeat immediately before commit. The source operation returns bytes only after
commit acknowledgement. A ten-second outward handler deadline includes pool
acquisition, initial authentication, body check, transaction and response
construction. A final deadline check discards late success. No background
operation is spawned by this router, and no implicit retry or durable business
identity is created on refusal, timeout or unknown transport outcome.

The ordinary final owner SELECT checks membership role/revocation, session
revocation and absolute expiry, verified user and enabled account. It does not
hold those rows, repeat idle expiry or establish an MFA/session lease. A
revocation committed before that final query refuses; one committed afterward
can invalidate the observation before commit or delivery. Signed intervals can
expire after their checked instant. The authority row stays locked until the
transaction finishes, but these point-in-time public observations cannot
authorize later signing, protected reads, ciphertext CAS or other mutations.

The named AccountSlot guards four outward requests per account only. It does
not bound cleaning backends or guarantee database lock release on request
completion. On ordinary refusal, explicit rollback is attempted while the
request is live; only successful acknowledgement proves rollback for that path.
Timeout, disconnect or failed acknowledgement uses maintained Transaction and
PooledClient Drop. The pool asynchronously attempts DISCARD ALL for two seconds,
then drops an unready client; the existing global16 request-socket permits stay
with the driver, including while cleanup continues. Neither that timer nor
request/account-slot release proves backend settlement. No new cleanup observer,
pool API or quarantine is introduced. Initial authentication may independently
perform its existing coarse last_used_at update.

## Refusal and availability

Malformed ingress is400; missing/invalid owner proof is401 or403 under maintained
authentication policy; unsuitable current authority, fingerprint, selected reader
or clock is403; database/capacity/deadline failure is503. Errors contain static
codes, with no protected account/key values. No source record, authority,
high-water, grant, debit, intent or provider attempt is written by observation.

The candidate can be instantiated for ordinary synthetic tests. Already enrolled
synthetic root/manifest fixture rows model stored trust and do not prove a root
enrollment ceremony. Authentication fixtures use genuine registration,
password-backed email verification and login. Parser/serializer tests do not
attest PostgreSQL execution. There is no statement issuer, contact root-signing
caller, custody acceptance, contact storage/read route or application journey in
this cut. Broader contact acceptance remains a separate requirement.
