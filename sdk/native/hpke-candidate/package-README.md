# Experimental native companion archives

`package-native.py` builds the existing AGPL-3.0-only candidate library as
`zrotext-hpke-candidate` Rust `0.1.0` or the
`github.com/pboachie/zrotext/sdk/native/hpke-candidate/go` module `v0.1.0`.
These coordinates are experimental and are not published by this gate. They are
separate from Tungsten's generated HTTP SDK packages.

Run with Python 3.11+, Node, OpenSSL, Cargo/Rust 1.97.1 or Go 1.26.9 on PATH.
The signed TLS fixture producer additionally requires Python `cryptography`:

```sh
python sdk/native/hpke-candidate/package-native.py --language rust --archive PATH_TO_REVIEWED_PROFILE02_PRODUCER --election PATH_TO_REVIEWED_PROFILE03_PRODUCER --original PATH_TO_REVIEWED_ORIGINAL_PRODUCER --template PATH_TO_REVIEWED_TEMPLATE_PRODUCER --output NEW_OUTPUT_DIRECTORY --require-protected
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
root transition controls. Fifteen separately compiled consumer probes also
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
tampering and content-size limits must fail closed. These are cryptographic and
local-content APIs; owner template storage and HTTP operations remain separate.

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
