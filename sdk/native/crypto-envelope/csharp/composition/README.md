# Experimental protected profile03 composition

`ProtectedSigner` qualifies a Windows PCP ECDSA P-256 key using the hardware
provider bit, exact public blob, zero export policy, private-export rejection and
an independently verified native signature. It normalizes signatures to low S
and signs the exact profile03 domain/length-framed bytes. It grants neither
election authority nor permission to send SMS. Pending alias receipts, public
binding on reopen and created-instance-only deletion follow the recipient API.

`Compose03.Fresh` validates a verified manifest/election and freshly authenticated
authority, text, recipient set, signer and deadlines before generating randomness.
It creates native AES-GCM body ciphertext and RFC9180 P-256 wraps, verifies the
native signature, and rechecks authority before returning. Shared secrets and
owned text buffers are cleared where possible; immutable application strings and
runtime/provider copies do not have guaranteed erasure.

Outbound profile03 requires every selected signer/recipient key to cover the
signed interval `[observed_ms, expires_ms)`, plus fresh current authorization.
Manifest issuance is not an additional observation lower bound; bounded future
issuance still follows manifest freshness. The shared signed policy cases and
cross-language alignment are tracked in [#1226](https://github.com/pboachie/zrotext/issues/1226).

`ComposeOrReplay` requires an application-owned private directory and a retained
journal path. It binds the independently enrolled root and complete canonical
intent, obtains an exclusive file handle, verifies existing checksummed records,
and flushes exact ciphertext to disk before exposure. Matching retries revalidate
current authority and return stored bytes; conflicting requests refuse. A fresh
process can reopen the same journal. The journal is limited to 256 records and
10 MB; partial/truncated/corrupt files refuse. Never truncate or recreate it to
force a retry after an unknown transport outcome. Recovery requires independent
application reconciliation. The journal does not resist hostile filesystem
administrators, restored older backups or arbitrary process compromise, and is
not a transport/carrier-effect ledger.

```text
dotnet run --project sdk/native/crypto-envelope/csharp/composition/ComposeTest.csproj -- PRODUCER_DIRECTORY PENDING_RECEIPT
```

The independent pinned maintained TypeScript producer accepts only the fresh
native public signer point. Its consumer verifies the signed envelope and opens
both intended recipients. Tests cover authority/content refusals, fresh
randomness, durable retry, separate-process reopen, concurrent callers, partial
records and authority loss after commit. A read-only unavailable hardware probe
reports `UNQUALIFIED`; any failure after creation fails. The test deletes only
its owned native key. No publication, transport call or live SMS occurs.

Profile02 composition, Java/Ruby composition, root transitions and clean native
package consumption remain separate gates.

The ZTJ4 journal persists a root-bound checksummed comparison-clock high-water
mark under the exclusive lock. Every accepted authority comparison, including
the postcommit check, advances it durably before output. Reopening with a lower
clock, torn clock metadata, and older ZTJ3 files refuses. Reconcile old journals
explicitly; never reset uncertain state. This detects trusted clock regression
against retained storage, not malicious filesystem rollback. Tests exercise
separate-process clock rollback, later postcommit time, and torn/old metadata.
