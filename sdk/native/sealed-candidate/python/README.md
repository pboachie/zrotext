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
`check_package.py --output <artifact-directory>` builds both formats in temporary
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
| Integration reader selection | Signed selection verifies exact archive-opening wrap sets; role-3 grant acquisition and live integration remain separate |
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
