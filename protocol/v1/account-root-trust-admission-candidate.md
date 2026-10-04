# Candidate account root review page

The account root review page is a public-only caller of the maintained profile-02
trust store and historical contact reader-statement verifier. It supplies no
private key, current permission, remote root publication or contact operation.

## Explicit serving composition

`ACCOUNT_ROOT_TRUST_ENABLED` defaults to false. Disabled startup does not read
`ACCOUNT_ROOT_TRUST_SDK_DIRECTORY` or add routes. Enabling requires configured
account routes and an explicitly supplied fixed public SDK package; unavailable
prerequisites refuse startup. It does not require or enable conversations, WSS,
phone enrollment or root custody. Ordinary authentication remains unchanged.
Both Compose app services forward the flag as false and directory as empty by
default. No package volume or container mount is added; an operator enabling this
candidate must separately supply a package path visible inside that runtime.

Build the maintained TypeScript SDK, then run
`node scripts/package_account_root_trust_browser.mjs <external-empty-directory>`.
The output contains only `sdk/draft02-manifest.js`, `sdk/draft02-trust-store.js`
and `sdk/contact-reader-statement.js`. The latter two import only the manifest
module. Files are strict UTF-8, bounded to 128 KiB each, and fixed by name.
Links, reparse ancestors, missing/extra files and unsupported imports are refused.
Packaging fetches nothing, performs no build and never mounts the output.
The trusted maintained build and application JS are the code trust boundary;
graph inspection is not authentication of arbitrary operator-supplied JS.

The opt-in serves `/owner/account/root-trust`, `/owner/account/root-trust.js`
and the three files under `/v1/owner/account-root-trust-sdk/sdk/`.
Responses carry no-store, nosniff, restrictive same-origin CSP and no-referrer.
Only GET/HEAD serve assets; POST refuses, and any query string refuses with an
empty 400 response. Unknown paths remain 404.
There is no request-selected disk path, database connection or mutation handler.
The two embedded page assets are part of the strict release web inventory.

## Independent public inputs

Before reading relay metadata, the owner supplies the independently retained
account UUID, canonical HTTPS kit origin equal to the actual page origin, and
full 32-byte root fingerprint. Inputs are not reconstructed from a statement,
session response, server observation or a saved acceptance boolean.

The public card starts with exact five bytes `ZTRC` followed by byte 1; its
u16 origin length is 9..512, total size is exactly 133 plus that length. Its
embedded root pin is exactly 94 bytes, starts with `ZTRP` followed by byte 2,
and must identify generation one. Card syntax extraction is followed by the
maintained curve/fingerprint enrollment verifier and exact account comparison.
The card tail is a public encrypted-backup digest. Card-only review does not
authenticate a backup or claim full published-bundle custody verification.
No encrypted backup, recovery token, secret or browser private-key bridge is used.

Signed manifest input is 364..9751 bytes with at most 64 records. Its maintained
signature, root, time, genesis and successor verification remains authoritative.
The immutable review displays account, origin, fingerprint, root point, manifest
version/digest/interval and every public record identity/point/interval/state.
The owner explicitly accepts or declines that displayed local history.

The actual same-origin `/v1/auth/session` GET uses cookies, no-store and refuses
redirects. Its bounded closed response has account_id, user_id, session_id and
role; only owner for the independently expected account is accepted. It has no
session expiry field. The selected account is privately copied before the first
await; changing the visible account refuses rather than becoming a new authority
expectation. Frozen account/session/user and copied CSRF-reference comparisons
are application lifecycle checks. This Cookie-only GET provides no held lease
or server-bound CSRF authentication; future issuer POST authorization is separate.

## Genuine local trust and finite lifetime

The controller internally opens the actual default Draft02TrustStore connection.
It accepts no caller store, read/CAS callbacks or structural capability factory.
Independent pin enrollment is PIN_ONLY, never accepted manifest history.
Fresh genesis one, same digest/version or a contiguous signed next manifest can
be accepted through the maintained store. Cold non-genesis, forks, missing or
pruned/gapped history, corrupt rows and root mismatch remain unavailable.
There is no reenroll, corruption clear, time reset or generic checkpoint import.

Operations have a ten-second outward deadline; the frozen review has a five-minute
cap shortened by signed manifest expiry. Initial crypto/open/read/history and
final waits race closure/deadline. At most four unresolved module operations are
charged through actual settlement. Late errors are observed, late handles closed,
and late UI publication refused. Ten seconds does not guarantee underlying
IndexedDB rollback or crypto settlement. Close releases owned connections and
clears copied public buffers/references; engine/helper internal copies are outside
any complete memory-zeroization claim.

Positive local writes use genuine store CAS. The controller compares its captured
previous snapshot immediately before writing; the maintained helper reads and
atomically checks its own write snapshot. A concurrent identical installation can
be semantically the same content; a changed head/fork cannot be silently advanced.
After acceptance the page verifies stored history at its own captured comparison
time, rereads the snapshot and checks owner-session stability. This result remains
accepted local history, not current account authority or proof of a remote effect.

History rows contain kind, digest and bytes, not per-manifest acceptance timestamps.
Immediate confirmation uses its operation's real captured clock. Later historical
review uses independently intended declared issued time under a genuine retained
successor chain. lastTrustedTimeMs is not an acceptance timestamp. History is
bounded to 64 manifests; pruning cannot be bypassed by importing saved JSON.

If a positive local write might have started, keep only the copied public
account/origin/fingerprint/version/digest/comparison tuple as an unknown outcome.
Decline, timeout or drift does not prove no effect. Reconciliation is read-only,
checks the actual independently pinned local store and history, and keeps unknown
operation identity. Matching content does not prove which request committed.
No automatic retry, new CAS, reset or remote erasure is permitted; the page refuses
a new positive review while that unknown identity remains. Closing/reloading is
not durable reconciliation and cannot restore a current claim.

## Historical statement consumer and limits

An optional statement review requires a bounded flat expected-intent JSON with
authorizationId/accountId UUIDs; origin; positive decimal-string trustGeneration,
manifestVersion, readerGeneration, issuedMs and untilMs; lowercase fixed-width
rootFingerprint/manifestDigest/readerId/readerPoint hex; and numeric capability 3.
The independent expected statementDigest is the full signed-packet SHA-256,
encoded as exactly 64 lowercase hexadecimal characters and compared separately.
Generation must be one. Duplicate keys, escapes, nesting and extra fields refuse.
This complete expected identity comes from independent owner intent review,
not from the signed statement being checked.

The page restores actual retained history for that intended digest/time, invokes
the unchanged historical reader-statement verifier, compares every intended
field and full signed-packet digest. Saved JSON/projections never restore
the private manifest/statement brands. The result is historical integrity only;
old-reader private custody, current installation and consent remain separate.

This opt-in remains a candidate prerequisite. Genuine durable issuer state,
current owner MFA/root signing, current field storage/predecessor/deletion CAS,
independent restore/no-reuse admission, cold second-device checkpoint, retained
reader custody and enrolled-account erasure are not supplied by this page.

## Paired owner intent and offline signature review

The same private page controller can review an original contact-reader intent.
Its inputs include an independently retained, nonzero 16-byte kit ID as 32
lowercase hexadecimal characters, reader ID and public point, and requested end
time. The kit ID is not derived from the public card's backup digest. Account,
origin and full root fingerprint remain independent inputs. A genuine accepted
local history connection is required; saved JSON, a server observation, status
projection or exported acceptance boolean cannot substitute for it.

The page reads only `GET /v1/owner/export?contact_reader_only=state`, with actual
browser-managed Cookie authentication and the current CSRF cookie **value** in
`x-zrotext-csrf`. It does not fetch private owner takeout. The closed 4096-byte
UTF-8 response is `{kind:"contact_reader_state",state:null|State}`. Null, absent,
corrupt or unavailable state refuses creation; none means revision zero. State
has root_pin_b64, root_fingerprint_b64, trust_generation, last_mutation_ms,
current and signed_statement. Current has phase, mutation_revision,
allocation_generation and observed_ms; active/withdrawn also have authorization,
generation and statement_digest. Only active carries a whole signed statement.
The original active packet must verify through the real retained history and
statement helper before it can supply the previous identity.

Creation captures exactly create_request, expected_revision, prior,
selected_reader_id, compared_root_fingerprint and requested_until_ms. Prior is
either `{phase:"empty"}` or the exact active/withdrawn phase, authorization,
generation and digest. The independent root, reader point/intervals and current
tuple are compared before approval. Revisions without room for allocation and
completion refuse. The canonical input digest uses the maintained issuer
version/account/origin/Create transcript; it excludes a reconciling session.

All issuer responses use a duplicate-aware bounded JSON parser before objects
are materialized. Only closed object/string/null DTOs are accepted, with at most
eight nested levels and 256 members. Escaped key aliases, duplicate members,
arrays, numbers, booleans, extra fields and trailing data refuse. Decimal fields
are canonical signed-63-bit decimal strings, with zero accepted only in fields
that allow it. Binary fields use canonical padded standard base64 with exact
fixed widths or the maintained bounded packet widths. General responses are at
most 20 KiB UTF-8; proposal/recovery files are at most 32 KiB.

One approval starts its absolute 60-second monotonic deadline before owner state
review. Original signed source and requested-end bounds can only shorten it.
Exactly three positive transport attempts are shared by CREATE and COMPLETE;
the slot is consumed immediately before calling fetch. CREATE retry is explicit
and sends the same frozen original bytes and identity. A Pending ACK, signature
import, session sample, exported file, error or read-only reconciliation never
renews time or capacity. Each File or HTTP operation has an outward bound of
at most ten seconds, also shortened by the operation/approval deadline. Crypto
and IndexedDB work race lifecycle/deadline cancellation without an underlying
settlement guarantee. All underlying jobs share the existing module-global
four-unsettled-job bound through actual settlement, including after close.

Pending binds the original commitment, allocation revision, authorization,
generation, unsigned digest/bytes, original creator/session and immutable
historical creation source. The page verifies the actual stored manifest chain
at that source's original observation time, compares all reader/root records,
and invokes the genuine unsigned encoder. This is not a live current source
brand. Drift, missing/pruned history or mismatched observations refuses positive
handoff. Final owner/session checks surround positive publication.
The source's signed_until_ms is the independently verified minimum of manifest,
reader and root-writer expiries; it is not the requested intent end time. Pending
until_ms must equal the original requested_until_ms and may be strictly shorter
than that source ceiling. A forged expanded/contracted ceiling or an interval
changed from the original owner intent refuses.

The public proposal download has exactly create and pending, preserving the
original Create and bounded Pending JSON. The displayed `contact-reader-sign`
template uses the real offline command's account/origin/bundle/proposal/output/
reader/reader-point/until arguments. The full independently compared fingerprint
is displayed for the separate hidden-console ceremony. This page neither
recovers RootSecret nor proves completion of that ceremony. Import requires the
whole signed packet to match the original unsigned bytes, genuine retained
history, independent expected identity and the helper's private verified result.
Another signature cannot silently replace the imported packet.

Completion requires a freshly entered factor. The input is cleared immediately;
the factor is not put in proposal/recovery files or retained outcome metadata.
Only an exact whole-packet receipt acknowledges completion. An adverse response
or late/lost ACK ends positive approval and retains the original uncertainty;
there is no automatic COMPLETE retry, new identity, reset or replacement CAS.
Decline, expiry, input/session drift, pagehide or hidden-page teardown disables
positive actions and releases the local store. Engine/transport internal copies
are outside a complete zeroization claim.

Read-only original lookup, exact cancellation and exact withdrawal use a fresh
ordinary owner observation and the real CSRF value. They do not require retained
root history or MFA and do not recreate approval. Historical Pending/receipt
content is metadata only; unavailable/pruned does not prove no effect. A public
recovery file retains only account, origin, kit ID, reader point, original Create,
input digest, nullable Pending and nullable whole packet. Import recomputes the
original commitment and permits only read-only reconciliation. It cannot restore
local history, verified brands, current authority or a positive attempt budget.

The page asset remains an opt-in candidate. Missing admitted aggregate/genesis,
independent restore frontier, configured authenticated issuer or custody gates
leave the ordinary flow unavailable. Rendered tests use synthetic Cookie/issuer
transport with genuine SDK signatures and IndexedDB; they do not prove actual
server DTO-to-offline-parser execution, owner MFA, private custody or end-to-end
runtime admission. The three-module package and server/auth/schema/export/erase
contracts are unchanged by this page cut.
