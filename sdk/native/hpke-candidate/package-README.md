# Experimental native companion archives

`package-native.py` builds the existing AGPL-3.0-only candidate library as
`zrotext-hpke-candidate` Rust `0.1.0` or the
`github.com/pboachie/zrotext/sdk/native/hpke-candidate/go` module `v0.1.0`.
These coordinates are experimental and are not published by this gate. They are
separate from Tungsten's generated HTTP SDK packages.

Run with Python 3.11+, Node, Cargo/Rust 1.97.1 or Go 1.26.9 on PATH:

```sh
python sdk/native/hpke-candidate/package-native.py --language rust --archive PATH_TO_REVIEWED_PROFILE02_PRODUCER --election PATH_TO_REVIEWED_PROFILE03_PRODUCER --output NEW_OUTPUT_DIRECTORY --require-protected
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
root transition controls. On qualified Windows PCP hardware it also runs both
profile readers and protected profile02/profile03 composition, current-state
replay and clock controls, with independent maintained TypeScript signature
verification and both recipient openings. `--require-protected` fails when that
capability is unavailable. Hosted CI may report protected acceptance false;
software/archive success does not establish native hardware acceptance.

The companion's existing limitations remain: profile03 root transitions and
cross-root historical opening are unsupported, current service authorization is
external, and profile03 observed-time parity remains tracked in #1226. Rust's
bundled SQLite 3.53.2 differs from Go's 3.53.4; this gate does not claim all SQLite
advisories resolved. No server deployment, live delivery, publication or stable
SDK replacement is performed.
