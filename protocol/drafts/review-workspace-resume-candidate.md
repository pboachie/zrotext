# Candidate root-bound review workspace continuation

This candidate codec proves possession of one retained generation-one root for
one exact continuation challenge. It has no mounted HTTP or native caller and
does not authenticate a broker, establish an enrolled/current root, consume a
challenge or issue a session. It is separate from ordinary owner authentication,
enrollment, custody publication, root replacement and SMS authorization.

An isolated review realm may provide a reusable broker login. That login must
never grant membership or sessions for previous reviewers' workspaces. A fresh
independent reviewer needs a fresh workspace and legitimate first root genesis.
A returning reviewer must continue the same workspace with their retained root;
session loss must not silently create another workspace, reset old work or
promote a pending enrollment key to an accepted root.

## Independent inputs

The retained encrypted root kit supplies the independently intended account,
exact origin, RootPin02 and fingerprint. Genuine recovery and explicit native
consent remain necessary. This is a recoverable software root; the codec does
not claim hardware-backed or non-exportable root custody.

The other scope values must come from an authenticated, same-browser review
broker challenge/context response, including fresh trusted server time. Broker
principal, broker session and authentication event are distinct from an owner
principal/session. They must not construct ordinary owner authority before the
durable resume transaction accepts the actual enrolled root. A public imported
proposal is only a selector; copying its fields into the expected context proves
nothing. Refresh a stale broker clock before inspecting a newer challenge.

The component takes these independent inputs explicitly. Its types do not prove
that an adapter obtained them through authenticated transport, a private kit,
structural deployment isolation or current database reads.

## Exact unsigned bytes

All integers are unsigned big-endian and must be positive and at most the
signed 64-bit maximum. UUID fields are raw 16 bytes and nonzero. Nonce and browser
binding are nonzero 32-byte values. Reject alternate encodings and trailing bytes.

| Offset | Bytes | Value |
| --- | ---: | --- |
| 0 | 5 | `ZTRW` followed by byte `01` |
| 5 | 16 | Realm ID |
| 21 | 16 | Broker principal ID |
| 37 | 16 | Authenticated broker session ID, never its secret bearer |
| 53 | 16 | Broker authentication event ID |
| 69 | 8 | Broker credential revision |
| 77 | 16 | Existing workspace account ID |
| 93 | 16 | Existing workspace owner user ID |
| 109 | 16 | Resume challenge ID |
| 125 | 32 | Fresh server-issued challenge nonce |
| 157 | 32 | Commitment to the exact private browser continuation |
| 189 | 8 | Issued UTC milliseconds |
| 197 | 8 | Expiry UTC milliseconds |
| 205 | 94 | Existing generation-one RootPin02 |
| 299 | 32 | Existing `ZTSE/root-pin/v2` fingerprint |
| 331 | 2 | Origin byte length, 1 through 512 |
| 333 | length | Exact canonical ASCII HTTPS origin |

The total unsigned length is `333 + origin_length`, at most 845 bytes. The
RootPin02 must bind the same account, generation exactly one and a valid
uncompressed P-256 point. Recompute its fingerprint under the existing root-pin
purpose. The exact existing canonical-origin predicate applies; aliases, a
trailing slash, default port, credentials, paths, queries and fragments refuse.

Require `0 < issued < expiry <= i64::MAX` and `expiry - issued <= 300000`.
Inspection requires `issued <= captured_time <= inspection_time < expiry`.
Signing rechecks `inspection_time <= fresh_time < expiry` after secret entry.
Times come from an authenticated broker context, anchored and refreshed by the
future native adapter; an imported timestamp or phone wall clock is insufficient.
The maximum five-minute challenge window does not define a login/session lifetime
or allow renewal of a previous challenge. A durable consumer may use a shorter
window and must recheck real database time and credential/session revision.

## Signing and verification

The exact signed transcript is ASCII `ZTSE/review-workspace/resume/v1`, NUL,
the unsigned byte length as u32 big-endian, and the exact unsigned bytes.
P-256 ECDSA uses SHA-256 over that transcript. Signatures are exactly 64 bytes,
raw `r || s`, with nonzero scalars below the curve order and canonical low `s`.
Receivers refuse high `s`; they must not normalize received signatures.

The public verifier compares every scope field and pin to the independently
expected values before verifying the signature. A validly resigned change of
realm, broker, session, event, credential revision, account, owner, challenge,
nonce, browser binding, origin or time remains a context mismatch. Enrollment,
custody, other signature purposes and unframed bytes cannot authorize resume.

The Rust `unlock` feature alone exposes the typed signer. Inspection captures an
owned immutable snapshot. Signing consumes that snapshot, independently checks
that the recovered private root owns the exact public pin, rechecks fresh time,
and returns only a public signature. It neither stores root material nor offers
an arbitrary-byte signing method. Consuming a local value is not durable replay
prevention: another process can inspect the same public challenge again.

The [public vector](../v1/vectors/review-workspace-resume-01.json) was signed and
verified independently with a P-256 implementation. Its scalar-one synthetic
test key is public test data, not a credential or an enrolled review account.
Rust checks possession and adversarial signatures; the
[stdlib vector check](../v1/tests/test_review_workspace_resume.py) independently
checks framing, offsets, hashes and the existing pin fingerprint.

## Durable consumer obligations before mounting

The server must first authenticate the reusable broker credential in a
structurally isolated realm with distinct origin, database identity, keys,
credential mounts and network policy. Realm/origin/database markers supplied by
a request, a copied marker or a configuration boolean do not establish isolation.

Resolve the workspace and owner without enumeration or granting password-only
access. Require the actual already enrolled, currently eligible generation-one
root for that account, exact broker identity/session/event/revision and private
browser continuation. Never select a root from the supplied pin or a pending
enrollment challenge. Historical possession/enrollment alone is not current
authorization. Revocation, deletion or an incompatible current root must refuse.

Under the action's established lock order, recheck currentness and trusted time,
consume the exact challenge atomically with issuance of the intended account/user
session, and reconcile a lost response using its exact private continuation.
Replay, changed bindings, wrong root, credential changes, expiration, races and
UNKNOWN must never mint another workspace or session as a fallback. Before root
enrollment, continuation requires its existing session or exact private attempt;
this enrolled-root codec cannot recover a lost pre-enrollment continuation.

No actual provisioning, durable replay/currentness, broker recovery, consent UI,
native bridge, browser path, production feature parity or external reviewer-policy
acceptance is provided by this component. Ordinary MFA and all current owner,
root, archive, line, manifest, epoch, dispatch, receiver and SMS journal checks
remain unchanged.
