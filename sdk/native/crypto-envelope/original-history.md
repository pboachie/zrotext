# Managed accepted original-reply history

`OriginalReplyCheckpoint` persists independently accepted profile02 manifest
history for one original-reply scope and externally enrolled root. Java, C# and
Ruby expose explicit `create`/`Create` and `open`/`Open` operations. Missing state
never initializes trust on reopen. Supply the independent root pin, compared
fingerprint and selected account/device/line/interval/connector/grant/reader/peer
scope on every open.

Creation and acceptance require a complete contiguous history from generation-one
genesis, with at most 64 signed manifests. Every restore re-verifies every
signature and predecessor link at its original accepted comparison time, then
checks the current manifest at the requested time. Acceptance permits only
extension of the accepted unsigned prefix and retains its original signed bytes
and times. Root rotations and profile03 history are refused by this bounded API.

For original-grant integration, authenticated server acceptance timestamps may
be up to 30 seconds ahead of the local comparison, matching the maintained
client. Private generation-one profile02 replay verifies each signature at its
own acceptance time, then rechecks currentness at local time. Server acceptance
does not become the durable local clock floor. Generic manifest APIs retain their
comparison guards; see [current proof integration](original-current.md).

`snapshot` (`ReadSnapshot` in C#) re-verifies without advancing durable time.
Its comparison field reports the persisted floor. Before exposing new plaintext
or effects, call `accept`/`Accept` with the expected revision, full accepted
history, comparison time and a trusted freshness callback. Under exclusive file
ownership, the implementation checks the revision and comparison floor, invokes
the callback with the verified current manifest and proposed time, rejects a
decreasing callback time, re-verifies at the returned time, and flushes history,
revision and clock as one append transaction. The callback must independently
recheck the intended grant; checkpoint bytes are not grant authority. Do not
reenter the same checkpoint from the callback.

This store contains public signed provenance and scope hashes, never plaintext,
recipient private keys or bearer credentials. Use a private trusted directory.
The versioned header binds the exact externally supplied root/fingerprint/scope;
each complete snapshot transaction is checksummed and monotonically ordered.
Checksums detect corruption, not hostile rewriting or restoration of an older
whole file. Transactions are bounded to 256 and the file to 16 MB. There is no
automatic compaction or trust reset.

An I/O or flush error can leave a complete committed transaction even when the
caller did not receive success. Reopen and inspect the revision before deciding
what to retry; never infer that an exception rolled the write back.

A torn append makes the store unavailable on reopen. The implementation never
silently drops a partial tail and rolls comparison time back. This differs from
the Rust/Go SQLite checkpoint's transaction rollback behavior; neither behavior
establishes hostile rollback resistance. Recover only through an independently
authorized state recovery process. The API does not implement that process,
HTTP proof validation, consume/status recovery or automatic grant-client wiring.

Run each language against a clean maintained producer checkout at
`72124e1a3ff28e782f870eeddbdc33cacf8ca3b4`, after building its TypeScript SDK:

```sh
python sdk/native/crypto-envelope/original-history-run.py --language java --producer PRODUCER
python sdk/native/crypto-envelope/original-history-run.py --language csharp --producer PRODUCER
python sdk/native/crypto-envelope/original-history-run.py --language ruby --producer PRODUCER
```

The tests reopen accepted history and decrypt real maintained role-3 ciphertext,
reject signed forks, shortened history, changed scope, stale revisions, reversed
time and failed freshness callbacks. Two independent native processes compete
for one revision; exactly one commits. A fresh process verifies the result. A
separate child flushes a partial append and exits abruptly; reopening must refuse.
These tests exercise software crypto and local durability, without live SMS or
network grant authority. This source module is separate from the installed
original-reply package gate; checkpoint package acceptance remains to be added.
