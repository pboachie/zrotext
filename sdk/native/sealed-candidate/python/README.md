# Native Python sealed candidate

Experimental cryptographic companion for [native parity #1128](https://github.com/pboachie/zrotext/issues/1128).
This module is separate from stable Python package exports and generated HTTP
clients. It does not establish live permission, independent rollback protection,
delivery, remote device attestation or release readiness.

The distribution is `zrotext-native-candidate==0.1.0a1` and its normal Python
import is `zrotext_native_candidate`. Requires Python 3.12 or later and exactly
PyCA cryptography 50.0.2, cffi 2.1.1 and pycparser 3.11. Setuptools 84.0.0 is the
pinned build backend. Existing `zrotext` SDK imports and generated HTTP clients
are unchanged. No package has been published by this work.

```python
from zrotext_native_candidate import ElectionJournal, OutboundJournal
from zrotext_native_candidate import HardwareRecipient, HardwareSigner
from zrotext_native_candidate import sealed_candidate, election03
```

Importing on Linux/macOS works for public verification and explicit software
candidate cryptography. Protected providers require Windows, the actual
Microsoft Platform Crypto Provider, supported TPM algorithms and successful
local qualification. Missing crypto dependencies fail installation/import;
unsupported protected capabilities raise `CngUnavailable` or `SealedError`.
There is no silent software fallback. Python 3.12 is the exercised CI version.

Wheel contents are restricted to the package's thirteen modules and distribution
metadata/license. Source archives add build metadata and this README; neither
archive includes tests, fixture producers, private receipts, sample scalars or
repository tooling. Both carry AGPL-3.0-only license metadata and full text.
`check_package.py --output <artifact-directory> --workflow-source <reviewed-workflow-package> --time-policy-source <shared-fixture-checkout>` builds both formats in temporary
storage, checks exact archive/dependency contents, installs each into a fresh
virtual environment and exercises real signed evidence, decryption, composition
and journal replay outside the checkout. Its isolated consumers then pass their
native ciphertext to the independent TypeScript/HPKE verifier. CI runs this
check on Ubuntu and Windows; passing package checks do not imply publication or
full legacy replacement acceptance.

Implemented and executed with PyCA `cryptography==50.0.2`:

- Exact profile-02 root pin comparison, manifest syntax, key IDs, role/scope
  rules, low-S P-256 signatures, semantic digest, predecessor/high-water checks
  and dual-signed root transitions. Verifier tokens keep immutable byte snapshots.
- Profile-03 generation-one, zero-anchor manifest upgrade from original signed
  profile-02 evidence and subsequent profile-03 successors. Unsupported genesis
  and generation transitions refuse. Historical predecessor evidence cannot be
  replaced with caller-created metadata.
- `verify_manifest03_current` independently verifies received current03 bytes
  against a genuine accepted03 token, requiring the same unsigned identity and
  predecessor profile and a nonregressing fresh comparison time. Alternate valid
  low-S signatures are accepted as semantic identity; the original token and
  persisted election bytes remain unchanged. The new immutable token has its own
  comparison floor. This neither installs new authority nor authorizes exact
  transport replay or replacement of retained signed evidence. Tests compare ten
  acceptance/refusal cases with the maintained TypeScript verifier and confirm
  the election journal still rejects same-version byte replacement.
- Bounded profile-02/03 inbound/outbound envelope syntax, origin signature,
  manifest/line/device/recipient binding and exact byte identity. Public
  verification returns no execution capability or accepted election.
- Full profile-02 archive inbound opening: historical signer authority at
  observation time, current reader authority, same root and accepted predecessor
  lineage, RFC 9180 base-mode P-256/HKDF-SHA256/AES128GCM unwrap with the profile's
  exact info and empty wrap AAD, then AES256GCM authentication and strict body text.
  Additional integration wraps require an independently verified exact selection.
- Profile-03 accepted-election proof: exact original signed02/accepted03 evidence,
  expected core, immutable accepted-record digests, device signature, owner
  signature over the device-signature digest, and registry key IDs. Independently
  authenticated current authority must match account, device, line, binding,
  selected reader, root, accepted lineage, manifest and live permission deadline.
- Current profile-03 outbound ciphertext opening to the elected reader, using
  nonempty profile03 wrap AAD and authenticated body text. The caller supplies
  independently expected message identity and peer; hardware custody is required
  by default. The returned text and byte digests confer no SMS authority.

The HPKE implementation uses native PyCA ECDH, HKDF and AEAD primitives with the
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) labeled schedule. TypeScript
`@hpke/core` independently produces the full encrypted fixture. Tests consume
existing signed genesis, rotation and profile-03 vectors rather than accepting
shape-only stand-ins. Profile-03 public vectors contain no recipient private
scalar and therefore establish public verification, not profile-03 decryption.
The separate `produce-election03.mjs` test invokes the maintained TS election
verifier and outbound composer with fresh ciphertext, including a TPM public
recipient supplied by the native test. That executable producer/consumer path
tests actual profile03 decryption without exporting the TPM private key.

## Election inputs are trusted adapter records

`verify_accepted_election03` requires independently authenticated `expected_core`,
the immutable accepted record, device enrollment signing point and owner approval
point. Supplying received packet fields as these expected values does not prove
the adapter's authority. The module authenticates the relation between these
inputs and exact signed evidence; it does not read a backend, confirm MFA or
commit an election. It retains the original signed02 bytes rather than accepting
a newly signed semantic alias as original evidence.

`require_current_election03` requires a separate present-authority tuple. A
historical accepted challenge may have expired, but its signatures never renew
current permission. The present tuple must name a manifest whose verified lineage
contains the accepted03 identity. Concurrent durable election selection and
trusted-clock/current-permission acquisition remain adapter responsibilities.
The signed-manifest checkpoint stores manifest lineage, not a live permission.

`open_elected_outbound03` reads current selected ciphertext only; it does not
admit archived03 envelopes, issue a live grant, verify a separate audience grant,
advance replay state, or call an SMS receiver. `require_hardware=False` is an
explicit software-candidate test option; no platform failure triggers fallback.

## Custody and authority boundary

`RecipientCustody` documents the public-point/ECDH provider contract.
`SoftwareRecipient` holds an exportable PyCA software key and cannot qualify
protected storage. The optional Windows `HardwareRecipient` uses only Microsoft
Platform Crypto Provider. Qualification cumulatively checks its hardware
implementation flag, export-policy zero readback, exact ECDH P-256 public-blob
magic/width and curve membership, rejected private-blob export, and actual ECDH
agreement against an independently generated PyCA peer. A software KSP is never
a fallback. Local provider observations are not remote TPM attestation.
The native calls follow Microsoft's
[key storage provider](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers),
[property](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers)
and [NCrypt derivation](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptderivekey)
contracts; the raw ECDH output is converted from little endian for RFC 9180.
`open_archive_protected02` requires this qualified provider; a caller's boolean
capability flag cannot admit a different provider.

PCP versions may return `Length=0` for ECC while exporting the exact P-256 public
blob, and may reject private export with `NTE_BAD_TYPE` rather than `NTE_PERM`.
These statuses are recorded as part of the cumulative check, not treated alone
as proof. Unsupported platforms, algorithms, exports or ECDH operations refuse.
Creation uses fresh UUID aliases, no overwrite/provisioning or UI policy, and
requires a trusted callback to fsync a pending-alias receipt before creation.
Reopening requires the independently expected public point. Cleanup addresses
only the exact created/opened handle; it never enumerates aliases. The PCP can
reject `SILENT` on deletion, so deletion of these keys uses zero flags. Other key
operations use silent flags where supported. Keep recovery receipts if cleanup
fails; closing a handle does not delete a persisted key.

`CheckpointStore` provides SQLite WAL/FULL-sync atomic compare-and-swap for up
to 1,024 signed manifest records. It reconstructs verifier evidence from the
independently supplied root pin on reopen, preserves the original signed02
predecessor for03 upgrades, and refuses corruption, stale revisions, clock
regression and unsupported profile downgrades. It stores public signed evidence
only. Use an access-controlled local directory. Root transitions are currently
outside this checkpoint adapter's generation-one chain surface.

`RootCheckpointStore` supplies a separate profile-02 rotation-aware format. A
dual-signed transition and its exact new-root genesis manifest form one atomic
checkpoint row under revision CAS. Reopen always starts from the independently
enrolled original root and replays every signature, digest anchor, generation
increment and version. The caller must supply independently compared successor
root points in `approved_roots={generation: public_point}` again on every open;
database bytes never approve their own replacement root. Approvals are captured
immutably before storage is read. Missing approvals, partial/corrupt pairs,
clock regressions and foreign database formats refuse without a trust reset.

Existing maintained TypeScript dual-root rotation vectors are verified by both
implementations. Tests cover restart, concurrent CAS, failed insertion and
process termination before commit; installed wheel/sdist consumers also restore
the rotated checkpoint. This does not migrate plain/election checkpoint files,
renew current permissions or provide independent rollback detection. Profile03
root/generation transitions remain unsupported by the current reviewed profile,
and this store refuses profile03 rather than inventing a transition contract.

`ElectionJournal` uses a separate database format to atomically append the exact
signed03 manifest, accepted binding/election tuple and original signed bundle
after an existing signed02 checkpoint. A competing writer must supply the same
expected revision; only one commits. Reopening and `snapshot_election` reverify
the signed history and original bundle against independently authenticated
expected core, accepted record and registry signing points supplied again by
the caller. Stored bytes cannot supply those expectations. Later signed03
manifest updates also require these expectations; second elections and root
transitions are refused. Existing plain checkpoint databases are not migrated
implicitly. A failed initial schema creation leaves an unusable file rather
than authorizing an automatic reset.

This journal persists local evidence of an externally accepted election, not
server acceptance, fresh permission or a sender replay decision. Current
authority must still be independently refreshed and checked before opening.
Tests cover restart and actual TypeScript candidate opening, concurrent CAS,
failed second insert, process exit before commit, evidence substitution and
deleted/corrupt journal refusal. Missing records never reset trust.

SQLite transactions provide local crash/concurrency durability, **not hardware
antirollback**: restoring an old complete valid database cannot be detected
without an independent high-water source. No live grant, audience permission,
receipt store or sender replay journal is supplied. `advance_trust02` alone only
proposes an immutable high-water token; the checkpoint transaction must commit
before an integration accepts effects. Python process-local tokens are not a sandbox against
code already executing in the same interpreter. The trusted caller supplies the
independently compared root, routing scope, current manifest and trusted time.

Owned mutable working DH/KDF/key/plaintext buffers are wiped in `finally` blocks.
PyCA, Python immutable intermediate objects and returned text may retain copies;
this is not an erasure guarantee. Authentication failure precedes text decoding,
and text refusal does not retain a plaintext-carrying decode exception.

`HardwareSigner` qualifies an ECDSA P-256 key in the same hardware provider,
including an independently verified signature challenge. It records pending
aliases before creation, binds reopen to an independent public point and
canonicalizes signatures to low-S. It uses
[NCryptSignHash](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash)
over SHA-256 of the exact profile-03 signature transcript; it cannot act as
recipient custody. Export rejection alone does not qualify hardware custody.

`compose_outbound03` checks current election, signer/recipient scopes, selected
device, deadlines and strict text before drawing randomness. It creates fresh
CEK, nonce and HPKE ephemeral material, authenticates profile-03 wrap/body AAD,
then verifies the resulting signature against the manifest-authorized point.
Protected signing is the default; `SoftwareSigner` requires explicit opt-out.
Independent TypeScript manifest/election verification and HPKE/WebCrypto tests
consume ciphertext composed with a real TPM signing key.

Use `OutboundJournal.compose_or_replay` before exposing bytes to transport. It
commits exact ciphertext under the account/message/device/line identity, refuses
changed intent under that identity, and returns identical stored bytes on retry
without new encryption or signing. Every call still checks present authority.
Concurrent writers serialize under SQLite; failed persistence returns no
candidate. Store files in an access-controlled directory: ciphertext and intent
hashes remain sensitive metadata. Preserve the journal across unknown transport
outcomes. Deletion or restoration of an older complete database cannot be
detected here; this is neither hardware antirollback nor an SMS replay/effect
decision. It does not authorize transport or replace the production receiver.

`compose_outbound02` adds the maintained profile-02 public composer's candidate
wire contract to this package. Supply a verified profile-02 manifest, explicit
device/line/message/peer/times, signer custody, and `(role, key_id, public_point)`
recipient tuples. It returns `Composition` with exact envelope bytes and the
unsigned SHA-256 retry identity. `SealedEnvelopeError.code` uses the TypeScript
error categories; ten refusal categories are compared by executing the actual
TS public wrapper. The Python call uses snake-case names and a string peer.
Protected signing is the default; production randomness overrides refuse.
The profile-02 wrap AAD is empty, unlike profile03. Tests independently open
native output with TS HPKE/WebCrypto, including actual TPM signatures.

Profile-02 grammar intentionally permits a zero message ID and non-live
candidate observation/expiry times when the maintained composer does. This
does not authorize sending: admission/current permission remain separate.
Profile-03 election checks are not silently applied to profile02. Callers must
retain the returned exact bytes and unsigned digest for profile02 retries;
`OutboundJournal02` provides this persistence while the existing `OutboundJournal`
API remains specifically profile03. Existing
TypeScript and legacy Python entrypoints remain unchanged.

`OutboundJournal02` uses a separate SQLite format pinned to the independently
compared original root. Supply a nonzero 16-byte caller-owned `intent_id`, the
original composition inputs, `expected_revision`, and an independently accepted
`current_manifest` on every `compose_or_replay` call. Both original and current
manifests must authorize the same signer/recipient points, and the original must
be on the current chain. Unlike the fresh candidate composer, this journal
requires a positive observation at or before current time and unexpired intent.
It never interprets a current manifest as a live backend grant.

The return is `(new_revision, Composition)`. Ciphertext and the comparison-time
high-water commit together before return. Every successful call advances the
local revision, including replay. After a conflict or unknown result, read
`revision()` and retry the same intent and original inputs; never reset the
database or create a replacement intent to force another composition. Existing
intent retries return identical signed bytes without fresh randomness or signing.
A different intent cannot compose the same account/message/device/line identity.
Current revocation, expiry, lineage or clock failures refuse before replay.

The journal stores an intent digest and encrypted envelope, not body plaintext
or private keys. WAL/FULL synchronous transactions provide local atomicity;
whole-database rollback/replacement resistance requires a separate external
anchor. Root-generation changes and profile03 journals are not implicitly
migrated. This is neither a carrier-effect journal nor delivery permission.

## Remaining work before full native parity

`verify_archive_reply_selection02` verifies the bounded ZTCA02 payload and both
phone approval/installation low-S signatures on an independently accepted
activation manifest. Supply independent acceptance time, account/device/line,
conversation interval, peer and archive reader. The returned opaque token holds
an immutable snapshot; copying its metadata cannot mint another verified token.
Pass it as `selection`, together with `interval`, to `open_archive_candidate02`
or `open_archive_protected02`. Opening checks activation lineage, historical
signer authority, current archive authority and exactly the approved archive and
integration wrap set before using the archive key. It never acquires a role-3
private key or grants an integration capability. Without selection, the existing
single-archive-wrap rule remains in force.

Selection expiry bounds installation acceptance; it does not independently
delete previously captured content. The signed epochs/session identify the
approved payload and do not establish current backend permission. Callers must
supply independently accepted activation/current evidence; no device-service
call, permission renewal, live capture or delivery is implemented here. Tests
execute the maintained TypeScript selection verifier and archive reader before
opening the same signed selection and ciphertext natively. Wheel and sdist
consumers exercise this path outside the source checkout.

| Surface | Current boundary / required follow-on |
|---|---|
| Native outbound composition | Native fresh crypto, TPM signing and exact local ciphertext replay implemented; live grant/transport/receiver integration remains separate |
| Profile-03 body opening | Current elected ciphertext verified/opened, including TPM tests; live backend/admission/grant/audience and receiver composition remain separate |
| Protected custody | Windows TPM provider with actual key/ECDH/opening/reopen tests; remote attestation, independent antirollback and other OS providers remain unsupported |
| Integration reader selection | Signed selection and native role-3 opening with initial/final dedicated TLS grant proofs; live deployment integration remains separate |
| Live authority and delivery | SDK/server/grant/journal/receiver integration and controlled device acceptance remain under #1054/#1004 |
| Publication / replacement | Neither stable package removal nor registry publication is authorized by these tests |

Run from the repository root after building the maintained TypeScript SDK:

```sh
cd sdk/typescript
npm ci --ignore-scripts --no-audit --no-fund
npm run build
cd ../..
python -m pip install -r sdk/native/sealed-candidate/python/requirements.txt
python -m unittest discover -s sdk/native/sealed-candidate/python -p 'test_*.py'
```

Use an isolated Python environment. Tests invoke the synthetic TypeScript producer
with Node, without an HTTP server, provider account, device, or SMS action.
Windows tests use fresh hardware keys with private pending-alias receipts and
targeted deletion; an unavailable TPM is reported as a skip, not protected
acceptance. Once creation is attempted, later qualification failures fail the
test. Linux and hosted Windows CI results must be read separately from executed
hardware-provider evidence.
## Sealed HTTP integration

`SealedHttpClient` connects the candidate journals to binary sealed submission,
status, cancellation and status-only reconciliation. `prepare02(journal, **inputs)`
uses `OutboundJournal02` and its caller-owned intent/CAS revision;
`prepare03(journal, **inputs)` uses the elected profile03 journal. Both commit
before returning a `PreparedSubmission`. Retain the database and original input
identity across failures; calling preparation again revalidates authority and
returns the original ciphertext. Never reset the journal to force a retry.

The client requires an application-owned `authorizer` callback. Each request
contains `action`, `message_id`, `device_id`, `unsigned_digest` (hex), and
`now_ms`. Return exactly those bindings plus `expires_ms` only after independently
checking current permission. A missing, throwing, mismatched or expired decision
refuses the action. This callback is trusted integration code, **not** an
authenticated server grant primitive. Production grant verification remains a
separate prerequisite; cryptographic manifests or database rows cannot supply it.

Preparation first calls the adapter with action `compose` and an empty digest
(ciphertext does not exist yet), then checks again after persistence with the
exact digest. Journal cryptographic checks use the supplied trusted clock's
current value. Submission and metadata operations check before the exchange and
again after a valid response; the decision must still be current after TLS
connection setup and before request bytes are sent. A post-response authority
failure after submit/cancel preserves an unknown effect result.

`submit(prepared)` sends only the stored binary envelope, with no caller
idempotency header. The default is one attempt and no automatic retries, including
network loss or explicit rate refusal. Opting into `max_attempts` permits up to
three attempts with identical bytes; only network
failure, `rate_limited`, `billing_pending` and `unavailable` can retry. Every retry
requires a fresh adapter decision. Timeout, redirects, malformed/truncated
responses and foreign message metadata do not automatically resend. A previous
unknown attempt stays unknown if a later authority check or admission refusal
fails. Errors expose only bounded classifications and the unsigned digest.

`status(prepared)`, `cancel(prepared)` and `reconcile(prepared)` never retry.
Reconciliation is a status read, never a new send. It remains possible after
intent expiry when independently authorized. Returned metadata is bound to the
original message and device; cancellation requires a `cancelled` result.
There is no pagination API in this integration slice.

The HTTPS transport verifies TLS, ignores proxy/cookie state, rejects all
redirects, bounds response bytes and framing, and caps the whole attempt,
including TLS setup and DNS wait. At most sixteen daemon workers can remain
outstanding; a delayed resolver is checked for cancellation before submission.
Python cannot forcibly terminate an OS resolver. This is component acceptance,
not live delivery, carrier completion or production device integration.

Installed wheel and sdist consumers execute actual synthetic HTTPS submission,
exact retry, reconciliation and cancellation outside the checkout. Source tests
also cover timeout after observed receipt, authority expiry during TLS,
untrusted TLS, response mismatches, framing failure and protected-profile
composition through the existing journals. No registry publication is implied.

## Original replies and optional workflow integration

`OriginalReplyClient` accepts an independently selected `scope`, locally accepted
manifest history, recipient custody and a trusted clock. Its dedicated `ztr_`
credential accesses `/v1/reply-events`; it is never reused as a workflow credential.
The scope contains account/device/line/interval/connector/read-grant UUID bytes,
the selected reader ID and peer. Protected custody is required by default.
Software fixture custody requires explicit `require_protected=False`; unsupported
providers never silently fall back.

`read_verified(event)` verifies the phone-approved selection, exact original
role-3 ciphertext identity and signed manifest chain, then checks the current
grant again after decryption. A changed, expired, foreign or revoked final proof
prevents plaintext release. The result contains transient plaintext, the original
event/digest identity, accepted baseline version and final authority. `read(event)`
returns only the transient text. Mutable CEK/plaintext working buffers are cleared;
Python/provider copies and returned strings are outside the erasure guarantee.

Current proofs bind the original account, interval, device, line, connector,
read-grant and reader. Manifest chains are bounded to 32 entries, accepted history
to 64 snapshots, and currentness to the maintained 30-second observation bound.
The client rejects forks, gaps, rollback and concurrent operations. Supply an
`OriginalReplyCheckpoint` for durable accepted history and comparison-clock CAS.
The explicit `accepted_history` compatibility mode remains memory-only. A service
response cannot select the local scope or custody key. TLS proof verification is component behavior, not evidence that a
particular deployment has granted permission or completed device acceptance.

Create a checkpoint once using `OriginalReplyCheckpoint.create(path, root_pin,
independently_compared_fingerprint, scope=scope, accepted_history=history,
comparison_ms=now)`. Bootstrap requires a complete independently accepted
profile02 chain from the supplied generation-one root. On subsequent starts,
open `OriginalReplyCheckpoint(path, root_pin, independently_compared_fingerprint,
scope=scope)` and pass `checkpoint=checkpoint` to `OriginalReplyClient`, omitting
`accepted_history`. Both root comparison and scope remain independent application
inputs. Existing, missing, foreign, corrupt or unsupported state never triggers
automatic replacement, migration, enrollment or a new trust baseline.

Every durable proof commits the accepted signed history and comparison clock in
one SQLite transaction before publishing it to the client. Restore replays every
signature and predecessor from the external root; an unchanged version still
advances the CAS revision and accepted comparison clock. The original accepted
bytes remain stable even if a later proof carries another valid signature of the
same manifest identity. The 64-manifest capacity fails closed without eviction.
Root transitions and profile03 are not inferred from original-reply proof chains.
If the postcommit freshness check observes a later time, a final comparison-only
CAS transaction persists that time before authority or plaintext is returned.
The trusted client samples and revalidates freshness and the signed manifest
while holding the write lock, so lock contention cannot bypass expiry. No newer,
unpersisted clock sample is taken after that final transaction. Commit latency
after the last locked check remains part of the trusted local storage boundary;
this is not a real-time guarantee against a stalled operating system.

Durable consumption and status bracket their single request with fresh, committed
current proofs. A stale concurrent client fails CAS before consumption; failure
after an effect attempt remains unknown, including a lost acknowledgement of a
successful commit. Reopen the existing checkpoint explicitly, then recover using
the same caller-retained consumption ID and `status`. Never automatically repeat
`consume`. The final plaintext proof is committed and checked again for expiry
before release. A failed postcommit fence leaves the old client stale.

SQLite WAL with FULL synchronization provides local transaction durability and
concurrent CAS. It does not prevent an attacker restoring an older whole database
or rolling back the host clock and storage together. External durable anchoring
is required for that threat. No live grant, credential, event ciphertext or
plaintext is persisted here; fresh authenticated service proofs are still required.

`page(cursor=None, limit=20)` returns bounded event metadata with the maintained
opaque `(accepted_at_ms, event_id)` cursor; metadata is neither a plaintext read
nor STOP classification. `consume(request)` makes one effect attempt with a
caller-retained request/event identity. After uncertainty, use `status(request_id)`
to recover; there is no automatic retry, resend or new consumption identity.
Invalid post-effect results remain unknown. Owner-review consumption needs no
workflow package and does not obtain proposal or dispatch authority.

Proposal consumption requires the optional `workflow` extra, whose ordinary
package coordinate is `zrotext-workflow-candidate==0.1.0a1`, plus a separate trusted
`output_credential` callback returning a canonical `ztw_` credential. The existing
native workflow package supplies its exact descriptor schema and canonical digest.
The output credential is sent only in `x-zrotext-output-authorization` for proposal
consumption. Missing extras or credentials, foreign account/line descriptors and
mismatched returned action/digest identities fail closed. The extra is imported
lazily, so ordinary crypto/read consumers remain usable without it.

CI builds the reviewed workflow package at
`9c0e969466e2cb8778e03287c7214ba78a50eee1` (#1229), then tests clean installation
without the extra and co-installation with it. Installed wheel and sdist consumers
perform actual synthetic TLS selected reading, final current proof, pagination,
durable checkpoint reopen, owner-review/proposal consumption and status recovery. The maintained TypeScript
producer independently opens the same role-3 software fixture; an optional public
point also tests qualified Windows TPM opening without exporting its private key.
These checks do not claim #1054 live grant deployment or #1004 device acceptance.

## Client-only encrypted templates

`encrypted_template` provides the maintained ZTWT01 candidate template format.
`canonical_template_bytes(template, values)` validates plain text identifiers,
reserved names, UTF-16 bounds, paired/lone surrogate rules and sorted canonical
JSON. `template_digest` hashes those local canonical bytes. A plaintext digest
must remain in the selected customer client; it is not relay metadata.
`preview_encrypted_template(content)` returns local substituted text and
`estimate_segments(text)` applies the bounded GSM/UCS-2 estimate with at most six
parts. This is not a carrier, billing or actual Android `divideMessage` result.

`seal_encrypted_template(manifest, scope, now_ms, content)` and
`open_encrypted_template(manifest, scope, now_ms, custody, envelope)` use fresh
P-256/HKDF-SHA256/AES-128-GCM HPKE encapsulation in the dedicated template domain.
The scope uses the maintained field names (`accountId`, `deviceId`, `lineId`,
`intervalId`, `templateId`, `bindingGeneration`, `revision`, `expiresMs`,
`trustGeneration`, `manifestVersion`, `peerDigest`, `readerId`, `manifestDigest`).
All scope bytes are captured into the exact 222-byte AAD; the envelope includes
the encapsulation and exact ciphertext length. A genuine current profile02
manifest must authorize the active role-2 archive reader and role-4 line signer.
Integration role-3 credentials are never an archive alias. Expiry is bounded to
30 days from the supplied comparison, and revisions to 1 through 128.

The bytes variants seal/open authenticated content of 1 through 32768 bytes.
The structured opener additionally requires strict UTF-8 and exact canonical
content, rejecting duplicate JSON keys, alternative serialization and unknown
fields. `encrypted_template_digest` hashes encrypted transport bytes. Protected
opening defaults to a qualified Windows TPM recipient; software fixtures require
explicit `require_protected=False`. Provider/manifest public points must match.
Owned mutable plaintext and derived-key buffers are cleared on success or failure;
immutable Python/provider copies and returned content remain outside this bound.

These are local candidate content helpers, without a template persistence client,
current backend grant, browser/device adapter, scheduling or dispatch permission.
Callers remain responsible for independently current manifest comparison and
durable accepted history. Contact reader statements and content mutations use
different domains and are not handled by these template functions.

Interop tests use the maintained TypeScript implementation with its serialized
software fixture key and test native opening with an actual qualified TPM when
available. They do not qualify arbitrary nonextractable WebCrypto template keys:
browser custody needs separate acceptance and is not covered by the software
fixture result. The native path binds the exact manifest public point.

Historical contact integrity helpers accept genuine generation-one profile02
manifest history and independently compared account, HTTPS origin and root
fingerprint. `verify_contact_reader_statement01`, `verify_contact_field01`,
`verify_contact_mutation01` and `verify_contact_transition01` verify low-S root
signatures, exact binary encodings, revision links and retained/replaced/cleared
field commitments. Their opaque tokens prove historical integrity only. They do
not install access, authorize a current owner, decrypt contact fields, sign new
contact content or establish current deletion state. No network or storage effect
is performed. Identity accessors return defensive copies.

Contact origins use the pinned `ada-url==1.27.0` native WHATWG parser, whose
bundled Ada 3.3.0 matches the maintained Node 24.13 runtime. This dependency is
necessary for canonical IDNA/punycode, numeric host and IPv6 behavior that Python
standard-library URL/IDNA parsing does not implement equivalently. Its CFFI
dependency is already explicitly pinned. CPython 3.12 Windows and Linux binary
wheels are available; normal package resolution installs the dependency without
vendoring its binaries into this distribution. See the [maintained bindings](https://github.com/ada-url/ada-python)
and [pinned release](https://pypi.org/project/ada-url/1.27.0/).

The original input must still be 9..512 printable ASCII characters and exactly
equal the parser's HTTPS origin, without credentials, path, query or fragment.
No normalization fallback is accepted. Valid canonical punycode is supported;
Unicode input and noncanonical aliases remain refused. Dependency/runtime upgrades
must repeat maintained TypeScript differential qualification. Tests compare actual
statement encoder acceptance and exact unsigned bytes across host punctuation,
ports, numeric/IPv6 aliases, Unicode scalar samples and contextual IDNA cases.
The fresh TypeScript fixture signs a genuine genesis-to-successor history and
create/update/clear/conversion commitments; its ciphertexts are opaque synthetic
payloads, not evidence of a production contact encryption implementation.

Outbound profile03 composition requires every selected signer/recipient key's
activation time to be at or before the signed observation, in addition to trusted
current-time activation and the existing upper expiry bounds. Manifest issuance
is a separate freshness/skew check; an otherwise valid observation before issuance
is not refused solely for that reason. Profile02 and inbound rules are unchanged.
The shared fourteen-case fixture generator constructs genuine fresh root-signed
manifests and dual-signed elections. Accepted native outputs independently open
all three HPKE wraps in maintained TypeScript. Set `ZROTEXT_TIME_POLICY_SOURCE`
to the pinned shared fixture checkout when running native tests; provide the same
checkout with `check_package.py --time-policy-source` for installed qualification.
The CI workflow records the exact shared source revision and builds its TypeScript
fixture dependencies separately.

The native outbound03 reader applies the same selected signer/recipient key
lifetime coverage (`key.start <= observed` and `expires <= key.end`) before any
HPKE unwrap. It does not add a manifest-issuance lower bound to observation.
Shared accepted cases self-open natively as well as independently in TypeScript;
authentically signed out-of-lifetime ciphertext is refused before recipient use.
Profile02 and inbound envelope checks retain their existing policies.

`ContactHistory` adapts the maintained contact-local-history contract to native
SQLite. Supply the independently enrolled generation-one root pin/fingerprint,
canonical origin, immutable capacity (1..256), a contact metadata path, and the
path of a separately maintained native `CheckpointStore`. `create=True` is an
explicit new-file operation; ordinary opens never reset, migrate or recreate
missing history. Root evidence must be a complete profile02 genesis/successor
chain of at most 64 manifests. Every comparison replays its signatures from the
external pin and verifies the mutation statement's archive/root records at its
declared issuance. Profile03 and root-transition histories remain unsupported
for this contact contract. Current root history is read again after recording;
a changed/unavailable root returns `recorded_needs_recheck`.

`lookup(contact_id)` returns `accepted_local_history` metadata, or an unavailable
reason. Its opaque local token is bound to that adapter and exact persisted row;
it is never a restored cryptographic transition token. `accept(expected=...,
transition=..., statement=...)` requires genuine native historical acceptance,
checks exact revision/digest/routing continuity, and atomically compares and
updates the row and total count under `BEGIN IMMEDIATE`. Repeating an identical
revision is idempotent; forks, skipped revisions, stale tokens and terminal rows
are refused without retry. Returned metadata is copied. Stored rows contain only
bounded metadata (1024-byte header, at most 256 rows of 2048 bytes), never signed
content, ciphertext or plaintext; SQLite/WAL overhead is outside that logical
payload bound. The root evidence database is separate and contains public signed
manifests. Records are not evicted and reductions do not free the count budget.

`mark_unavailable(expected=...)` atomically replaces an exact row with a terminal
contact identifier. It works at full capacity and maximum revision. An explicit
`reduction_only=True` open requires the existing matching header but no root
evidence; it cannot create or positively accept history. Missing or rolled-back
root evidence leaves a valid local token available for reduction. Malformed
storage fails closed without clearing it. A storage/lifecycle failure after a
write attempt returns `write_unknown`; reopen and look up the exact contact to
reconcile local state. These results never acknowledge a server operation.

Use `close()` or a context manager. The adapter permits one operation, at most
four live/opening adapters per loaded module, a ten-second checked operation
deadline, and a thirty-minute lifetime. SQLite lock waits are bounded to five
seconds; owned connections close when the synchronous operation unwinds. Native
callers must close on application suspension/cancellation; this package does not
install browser visibility handlers. Deadlines are checked at bounded operation
boundaries, not preemptive thread cancellation or a hard disk-I/O deadline.

Accepted root/version/time floors detect observable regressions against retained
rows. Ordinary SQLite cannot detect restoration of both databases to matching
older snapshots, replacement with internally valid metadata, or same-root reset
without an independent durable anchor. Local metadata is not authenticated
against a malicious filesystem writer. This adapter makes no hardware antirollback,
current permission, remote head/deletion, field readability or encryption claim;
it does not requalify retained fields' older statements or custody. Tests use real
SQLite races/process exits and fresh maintained TypeScript signed transitions;
both installed wheel and sdist consumers exercise create/update/clear, restart
and terminal reduction through normal public imports.

`produce_contact_field01` and `produce_contact_transition01` produce the
maintained historical contact commitments over caller-supplied opaque ciphertext.
They do not encrypt fields, recover an owner key, install a reader, authorize a
current owner or send data. Supply a genuine statement, exact independently
expected account/origin/root fingerprint/contact/routing identity, and a separate
`OwnerRootSigner`. Mutation production additionally requires the exact genuine
previous transition and statement, expected legacy generation, and matching
replacement field tokens. Scope, revision, slot and predecessor checks complete
before signing. The returned `HistoricalProduction` contains copied immutable
`signed_bytes`, a genuinely verified historical token, and the explicit
`produced_historical_integrity` classification.

`OwnerRootSigner.create(record_pending_alias)` and `.open(alias, expected_point)`
reuse the existing local Windows Platform Crypto Provider qualification: exact
hardware provider, P-256 shape/on-curve point, export-policy observation, private
export refusal and real signing verification. It has a separate key namespace
and accepts only `ZT/contact-field/commitment/v1` and
`ZT/contact-field/mutation/v1`, with strict unsigned frame checks. The existing
integration `HardwareSigner` domains remain unchanged and reject this root
capability. Every producer independently matches the key point to the genuine
statement before signing and verifies the complete signed result before return.
There is no software fallback. `SoftwareOwnerRootSigner` requires explicit
`require_hardware=False` and remains an experimental test capability.

Optional `ContactCancellation` is one-way: call `.cancel()` to revoke an ongoing
operation. The producer checks a ten-second deadline and admits at most four
workers per loaded module. Cancellation or expiry stops outward delivery without
claiming to undo a signature. An unresolved provider operation continues to own
its admission until it actually settles; late output is discarded. No retry is
performed. Callers own signer handles and pending-alias receipts throughout this
period. Native threads cannot forcibly cancel an NCrypt call. Mutable working
frames are cleared when the worker settles; immutable Python/provider copies and
caller-owned ciphertext are outside that erasure guarantee.

The independent TypeScript consumer verifies native create/update/clear/conversion
chains and all field signatures. The protected test builds synthetic enrollment
frames in TypeScript, signs them using private test plumbing on a fresh TPM root,
and checks actual native commitments in TypeScript before exact owned-key cleanup.
That fixture plumbing does not expand the public root signer's domain API.
Installed wheel/sdist consumers exercise the explicit software candidate and
independent verification; the separate local TPM test establishes the tested
Windows provider observation, not remote attestation or browser/device acceptance.
