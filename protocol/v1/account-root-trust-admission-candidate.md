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
