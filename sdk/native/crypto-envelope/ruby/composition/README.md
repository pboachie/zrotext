# Experimental Ruby protected profile03 composition

`ProtectedSigner` reuses the Windows PCP handle/receipt lifecycle with the ECDSA
algorithm and public-blob magic. Qualification combines provider hardware support,
zero export policy, export denial, valid public point and an independently
verified native signature. It signs exact profile03 domain/length-framed bytes
with low S and refuses recipient unwrapping. The composer requires the exact
qualified signer class, with no software fallback or new gem dependency.
This is local qualification, not remote attestation or protection against code
that compromises the Ruby process.

`Compose03.fresh` authorizes elected/current state and the complete intent before
randomness, creates native AES-GCM and RFC9180 P-256 ciphertext, verifies its native
signature, and rechecks authority before returning. `compose_or_replay` binds an
independently enrolled root and full canonical intent to a private application
journal. Exclusive file locking and flush/fsync precede exposure. Exact retries
revalidate authority and return stored bytes; conflicts, partial files and
corruption refuse. A checksummed, fsynced comparison-clock high-water mark refuses
clock rollback across reopen, including the final postcommit authority check.
A torn clock update fails closed. The versioned ZTJ4 journal refuses older ZTJ3
files; reconcile them explicitly rather than resetting storage. Limits are 256 records and 10 MB. Retain the same journal
across uncertain outcomes; never reset it to force a retry. Recovery requires
independent application reconciliation. This is not antirollback storage,
hostile-filesystem protection or a carrier-effect ledger.

Outbound profile03 requires every selected signer/recipient key to cover the
signed interval `[observed_ms, expires_ms)`, plus fresh current authorization.
Manifest issuance is not an additional observation lower bound; bounded future
issuance still follows manifest freshness. The shared signed policy cases and
cross-language alignment are tracked in [#1226](https://github.com/pboachie/zrotext/issues/1226).

```text
ruby sdk/native/crypto-envelope/ruby/composition/compose_test.rb PRODUCER_DIRECTORY PENDING_RECEIPT
```

Tests use the independently pinned maintained TypeScript producer/consumer,
which verify the native signature and open both intended recipients. Native
tests cover exact retries, separate-process reopen, concurrency, partial records,
authority loss after commit, restart clock rollback, torn clock records and owned cleanup. The existing protected recipient
and software suites are regression gates. A read-only unavailable capability
probe reports `UNQUALIFIED`; any subsequent failure fails. Failed cleanup keeps
its receipt. Owned working buffers are cleared where possible; immutable captured
intent strings and provider/runtime copies do not have guaranteed erasure.

Profile02 composition, root transitions and clean native package consumers
remain separate gates. No live transport or SMS is exercised.
