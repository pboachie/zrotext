# Experimental installed webhook archive

From the repository root, with Python 3.11+ and Rust/Cargo 1.88.0 on PATH:

```sh
python sdk/native/package-webhooks-native.py --language rust --vectors REVIEWED_VECTOR_CHECKOUT --output NEW_OUTPUT_DIRECTORY
```

The vector checkout must be the exact reviewed revision verified by the helper.
It supplies only the shared TSV; it is not a package dependency. The output
directory must be new and outside the public checkout. The gate builds `zrotext-webhook` `0.1.0` with six bounded
archive entries: runtime source, normalized/original Cargo manifest, lock,
README and AGPL license. Consumer tests are separate from the archive.

After removing staged sources and packaging caches, a fresh consumer resolves
the crate from an ordinary candidate sparse registry and public transitive
dependencies from crates.io. No path, workspace or dependency override is used.
Exact metadata source checks reject other dependency sources. The output
contains the archive, consumer lock and qualification metadata. No registry
publication occurs; these existing coordinates remain experimental.
The consumer lock records a temporary qualification registry and is not a
portable application lockfile. The crate itself declares ordinary public
crates.io `hmac 0.12` and `sha2 0.10` dependencies, with no Tungsten runtime.

Installed tests run the three existing native test groups and 16 shared raw-byte
signature/replay cases. The seventeenth shared case is a negative signed clock;
the public API takes `u64`, so the test explicitly checks parsing refusal at the
consumer boundary instead of claiming the verifier accepted a negative clock.
Existing tests exercise `u64::MAX`, inclusive symmetric replay boundaries,
wrong key/body/timestamp and malformed headers. Event-ID deduplication and
application authorization remain the receiver's responsibility.
