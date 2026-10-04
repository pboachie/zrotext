# Contact accepted local history (unmounted SDK)

This candidate SDK adapter records bounded metadata from genuine historical contact
transitions. It supplies `accepted_local_history`, never current permission, a
remote contact head, remote deletion, field readability, or a restored contact
integrity brand. Its functional prerequisites are the contact reader statement and
compound historical contact verifier. No ordinary contact UI or server route calls
this module. The account contact encryption roadmap remains open.

## Application boundary and API

`openContactLocalHistory01` owns its contact IndexedDB connection and, in `history`
mode, its maintained `Draft02TrustStore` connection. The application supplies an
account ID, canonical HTTPS origin, generation-one root pin and independently
compared root fingerprint, an immutable local record budget, mode and abort signal.
It accepts no injected store, read callback, structural manifest or acceptance flag.
Application-owned IndexedDB and honest application JavaScript are the trust boundary;
malicious storage, browser rollback and arbitrary same-origin JavaScript are outside it.

The frozen adapter exposes `lookup(contactId)`, `accept({expected, transition,
statement})`, `markUnavailable({expected})` and `close()`. Runtime-private WeakMaps
bind adapters and local-record tokens to one instance and exact closed row. Copied
methods, forged tokens and invalid historical verifier brands refuse. Tokens expose
only `kind: local_record`; they cannot be supplied as a private historical transition.
Returned metadata is an owned clone. Repeated identical lookups reuse one token;
observing a different row invalidates the old token. Closure invalidates all tokens.

`lookup` returns either `accepted_local_history` with available mutation-statement
history evidence, or `unavailable` with a reason and, for an existing valid row, a
local reduction token. The evidence does not verify retained older field statements
or establish access to an old reader's private key. Corrupt representations refuse
without clearing storage. Closed lifecycle, stale CAS, invalid input, cold updates,
forks and storage exhaustion produce explicit errors; no automatic retry advances
the expected token.

## Historical acceptance and exact local CAS

Before awaiting, `accept` captures owned identity metadata through the genuine
private transition and statement accessors. It matches their exact whole statement
digest, manifest tuple, account, origin and generation-one independently compared
root. It uses the internally opened maintained store's `verifyStoredHistory` at
the statement's declared issue time, then inspects the actual privately verified
role-2 scope-12 reader and role-6 scope-0 root records. Reader/root points, IDs,
intervals, account, manifest version/digest and root generation must agree.

The complete observed root snapshot must remain equal before and after historical
verification. Known stored root floors refuse observed regression in version,
digest, anchor or trusted time. An observed reset can make evidence unavailable;
the maintained store has no reset epoch, so an intervening same-root reset or
whole-database rollback cannot reliably be detected. No result is a current claim.

Contact metadata and its admission counter change in one IndexedDB transaction.
`expected: null` means an absent local row, not an absent remote contact. Only a
genuine create/conversion transition to revision one may initialize that row. An
exact private expected token must match every stored byte/scalar for an existing
row. Equal revision requires exact metadata equality. An update must be the exact
successor of the recorded revision and whole mutation digest, preserving routing
and nondecreasing manifest and reader identities. Local-unavailable rows never
reopen. Concurrent instances serialize on IndexedDB; a stale loser refuses.

The root and contact databases cannot share an atomic transaction. An observed
advance during the historical precheck refuses before contact effects. After
contact commit, another root read either matches or returns
`recorded_needs_recheck`; this preserves recorded historical metadata without
claiming rollback or a current head. Lifecycle loss after a transaction attempt
returns `write_unknown`. Reopen and exact-key lookup reconcile local metadata;
they do not acknowledge a remote operation or change its request identity.

## Bounded records and handles

The fixed local candidate database is `ztse-contact-local-history-v1`, with one
account/root/origin-bound header and contact rows keyed by contact ID. It is a
local implementation name, not a wire namespace. The configured budget is 1..256
tracked identities; another configuration refuses rather than silently expanding
it. This is a local adapter budget, not an account contact limit.

Accepted rows contain only contact ID, revision, whole mutation digest, request ID,
routing commitment, two slot tags/seal revisions/digests, statement and manifest
commitments, reader ID/generation, root writer ID, declared comparison time and
observed root version/digest/anchor/time. They contain no ciphertext, signed bytes,
signatures, plaintext, phone, consent/purpose, session, device or line data. The
header payload is at most 1024 bytes and each accepted row at most 2048 bytes:
logical payload <= 1024 + 256 * 2048 bytes. Browser indexing/quota overhead is
separate and quota errors remain possible. There is no journal, field history,
receipt table, automatic eviction or durable metadata expiry.

At most four opening/live adapters exist per loaded module. Each owns at most two
connections; reduction-only mode owns one. Permits are charged before asynchronous
open and remain charged until every late owned handle closes. One operation runs
per adapter, without a queue. Open and each operation have a ten-second deadline;
the adapter's absolute lifetime is thirty minutes. Retries cannot renew lifetime.
Explicit close, abort, visibility loss and deadline invalidate transient metadata,
abort its active contact transaction and close only its owned connections.
Late promises are observed and cannot publish an adapter, receipt or token.

## Local privacy reduction and availability limits

`markUnavailable` irreversibly overwrites one existing row with only schema,
local-unavailable state and contact ID. It needs the exact private local token,
not a root history, active key, new signature, successor revision or spare capacity.
An existing matching header can be opened in `local_reduction` mode after root
loss or mismatch. This mode cannot create a header or positive history. Reductions
remain possible at maximum revision and full budget; repeated terminal reductions
allocate nothing. The persistent identity counter remains unchanged, preserving
the local stop fence. Stale reduction tokens cannot silently stop a newer row.

A local stop is not an authenticated owner erasure decision or remote-deleted
state. A server 404, exported object or caller-shaped receipt cannot supply a token
or restore a historical brand. This module invokes no server deletion, withdrawal
or financial lifecycle hooks. Backend purpose-specific withdrawal and unresolved
submission liability remain independent requirements.

The maintained root store retains 64 manifest versions. Missing, pruned, gapped,
corrupt or different-root history makes positive evidence unavailable while a valid
existing local token can still reduce metadata. Cold state, second devices and
unavailable history establish no permission. There is no import/restore factory,
checkpoint transfer, remote latest/deletion witness, retained old-reader custody or
field encryption/decryption here. Retaining erased ciphertext to rebuild proof is
outside this cut.

## Verification scope

Focused tests use actual maintained synthetic signed history and verifier brands,
existing fake-indexeddb, and the built SDK packaged into isolated Chromium.
Controls cover exact statement binding, owned capture, local fork CAS, root
advancement, pruning, corruption, root loss/mismatch, MAX/full reduction, bounded
handles, deadlines, aborts and late promises. MAX reduction fixtures explicitly
seed a durable maximum-revision representation; they do not fabricate a signed
maximum-revision transition. Browser visibility loss uses a controlled platform
property and a browser lifecycle event. No real-page integration, remote owner
ceremony, physical device, provider or production activation is demonstrated.
