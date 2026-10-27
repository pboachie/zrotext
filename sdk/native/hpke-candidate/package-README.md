# Experimental native companion archives

`package-native.py` builds the existing AGPL-3.0-only candidate library as
`zrotext-hpke-candidate` Rust `0.1.0` or the
`github.com/pboachie/zrotext/sdk/native/hpke-candidate/go` module `v0.1.0`.
These coordinates are experimental and are not published by this gate. They are
separate from Tungsten's generated HTTP SDK packages.

Run with Python 3.11+, Node, OpenSSL, Cargo/Rust 1.99.1 or Go 1.26.10 on PATH.
The signed TLS fixture producer additionally requires Python `cryptography==46.0.5` and `ada-url==1.27.0`:

```sh
python sdk/native/hpke-candidate/package-native.py --language rust --archive PATH_TO_REVIEWED_PROFILE02_PRODUCER --election PATH_TO_REVIEWED_PROFILE03_PRODUCER --original PATH_TO_REVIEWED_ORIGINAL_PRODUCER --template PATH_TO_REVIEWED_TEMPLATE_PRODUCER --save-oracle PATH_TO_REVIEWED_SAVE_ORACLE --opening-oracle PATH_TO_REVIEWED_OPENING_ORACLE --authoring-oracle PATH_TO_REVIEWED_AUTHORING_ORACLE --contact PATH_TO_REVIEWED_CONTACT_PRODUCER --context PATH_TO_REVIEWED_CONTEXT_PRODUCER --context-oracle PATH_TO_REVIEWED_CONTEXT_ORACLE --output NEW_OUTPUT_DIRECTORY --require-protected
```

Use `--language go` for the Go module. The script verifies exact producer commits
and clean tracked files; install/build their maintained TypeScript dependencies
first. The output directory must not exist. Outputs contain the bounded archive,
consumer dependency lock/checksums and a qualification report; temporary keys,
receipts and databases are not archive members. The maintained source checkouts
are independent fixture producers, not package dependencies.

Archives include runtime source, metadata, README and license. Public-API test
harnesses are copied separately into a new consumer. The staged library source
is removed before ordinary candidate registry resolution. Cargo uses a fresh
sparse registry and public crates.io transitive dependencies. Go uses a local
module feed followed by the public module proxy, with checksum verification for
public dependencies; only the unpublished candidate module is exempt from the
public checksum database. No path, replace, workspace or private-checkout
dependency is accepted. Consumer dependency/build caches are fresh.

Installed acceptance runs actual journal crash/CAS/restore and authenticated
root transition controls. Twenty-four separately compiled consumer probes also
cover selected original ciphertext, durable history, HTTPS transport, signed
current proofs, verified reads and page discovery, saved owner-review intent,
and typed proposal consumption/status. The six actual TLS suites preserve
independent read/output credentials, exact descriptor binding, and recovery
from an uncertain response without a second consume. Fixture generation uses
the exact maintained original producer recorded in `PRODUCERS`; test runners
receive installed executable paths and never rebuild the library from source.

Template consumers compare canonical content and SMS segment previews with the
maintained TypeScript oracle, then exercise authenticated ZTWT01 sealing and
opening against an independently pinned producer. TypeScript opens two fresh
native seals. Current-authority changes, clock regression, malformed scopes,
tampering and content-size limits must fail closed.

Separate installed owner-template consumers exercise authenticated cold HTTPS
reads and reviewed save, explicit retry and GET reconciliation against the
maintained state machine. The fixture verifies Cookie/CSRF authority, exact
ciphertext and idempotency identity, refusal and uncertainty, busy/close
fencing, deadlines and contradictory heads. A matching reconciliation read
does not acknowledge or silently clear an uncertain write. No automatic retry
or live owner-service acceptance is implied.

The current-template opening consumer uses a sixth pinned producer/oracle and
the installed library's explicit opening lifecycle. Software TLS controls and
maintained comparisons check exact client binding, currentness, point binding,
tamper refusal, delayed callbacks and client closure before plaintext publication.
Repeated opening of ciphertext matching pending intent never acknowledges the
earlier write. On a qualified provider the same installed executable runs actual
protected opening, provider/client closure and interrupted-setup cleanup. These
checks borrow the caller's recipient; lifecycle close never deletes its key.
The qualification report records opening separately from cold/save and overall
protected acceptance. No browser ceremony or live owner-service claim follows.

Reviewed authoring adds a seventh pinned oracle and an installed consumer for
immutable draft review, exact approval, client lifetime limits and preservation
of another operation's reviewed or uncertain ticket. Preparation sends no HTTP;
explicit caller commits are exercised separately and the maintained TypeScript
oracle opens their ciphertext. Host custody leases are not protected-key
qualification: authoring seals to public recipients without a private-key
operation. The report records authoring acceptance separately from protected
opening. No DOM activation or automatic persistence is inferred.

Historical contact acceptance adds an eighth pinned producer and an external
consumer for statement verification and field-only production. Its native URL
dependencies resolve through their ordinary public registries. Software controls
include canonical origins, historical scope and signed-byte tampering; three
produced fields are independently verified by the maintained SDK. On a qualified
Windows provider, the installed consumer creates its own dedicated contact key
with a durable pending receipt. A separate synthetic fixture signs enrollment
evidence through an exact borrowed OS handle; no setup-signing primitive is
exported by the installed SDK. The consumer reopens the dedicated capability,
refuses cancellation, closed providers, foreign scope and borrowed-key deletion,
then deletes its exact owned key. Interrupted setup also requires confirmed
deletion.

A separate installed mutation probe verifies signed mutations, retained-field
transitions and software production against the same pinned producer. Its
protected mode produces three fields and four mutations using ordinary public
custody APIs; the maintained SDK independently verifies the resulting transitions.
Each mutation also refuses cancelled, closed-provider and foreign-scope calls.
Successful and interrupted fixture setup require exact owned-key deletion.
The report tracks historical mutation integrity and protected production
separately. A further installed contact-history probe exercises bounded durable
metadata, independently signed root-history rechecks, exact session-bound CAS,
terminal local reduction, process restart and an interrupted SQLite writer.
It also checks post-commit reconciliation when root history changes during a
write. The report records local history separately from current permission;
metadata never recreates verified field or transition tokens. Whole-database
rollback protection requires an external checkpoint and is not claimed.

Workflow-context qualification adds a ninth pinned producer. Its installed
consumer selects owner role 2 and integration role 3 explicitly and checks
opaque ZTWC01 bytes, exact scope/domain binding, fresh encapsulation, size limits,
tampering and current-authority rechecks. The maintained SDK independently opens
software-produced ciphertext. Qualified protected opening exercises both roles
and requires exact owned-key deletion on success and interrupted setup. These
installed APIs also run actual ten-second deadline and cancellation controls:
four unresolved authority callbacks retain their slots, a fifth is refused
without invoking its callback, and admission returns after settlement. These
checks do not establish context persistence, a live integration grant or deployed
service acceptance; the report records those boundaries separately.

Owner-context persistence adds a tenth pinned maintained oracle and a separate
installed public consumer. Explicit prepare/review, POST commit, caller-owned
retry and GET reconciliation preserve exact ciphertext, request identity and CAS
revision. Equal GET bytes retain uncertainty until the request is acknowledged;
compatible newer content is classified separately after acknowledgement. Closure
and idle expiry preserve pending metadata and unknown outcomes. Real synthetic TLS
checks cover authentication, redirects, malformed/truncated/trickled responses,
current authority and all three context kinds. External blocked-callback controls
exercise the ten-second deadline, eight retained slots, ninth-call refusal and
recovery after actual settlement. The report distinguishes this candidate
persistence lifecycle from deployed owner-service acceptance.

`--owner-deadline-case-ms` records the declared caller deadline for the
post-handshake owner-template cases (default 100, allowed 100..2000). Hosted CI
explicitly selects 1000ms so cold TLS can reach the intended response/callback
phase; the fixture extends its delayed response accordingly and still requires
one request, no late success and a bounded return. The separate 100ms
pre-dispatch refusal remains unchanged. This option changes fixture call
parameters, not the library defaults, and never retries a failed test.

On qualified Windows PCP hardware the gate also runs both
profile readers and protected profile02/profile03 composition, current-state
replay and clock controls, with independent maintained TypeScript signature
verification and both recipient openings, plus selected original opening and
the final-proof TLS read checks over an enrolled protected recipient. Template
opening uses a fresh nonexportable recipient; its fixture contains only the
recipient public point. Successful completion and interrupted fixture setup
both require exact owned-key deletion. The existing protected-recipient probe
must qualify before these hardware checks run; no software fallback is used.
`--require-protected` fails when that
capability is unavailable. Hosted CI may report protected acceptance false;
software/archive success does not establish native hardware acceptance.

The companion's existing limitations remain: profile03 root transitions and
cross-root historical opening are unsupported, current service authorization is
external, and profile03 service/device integration remains tracked in #1054. Rust's
bundled SQLite 3.53.2 differs from Go's 3.53.4; this gate does not claim all SQLite
advisories resolved. No server deployment, live delivery, publication or stable
SDK replacement is performed.
