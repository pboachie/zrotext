# Native original-reply checkpoints

Experimental Rust and Go companions persist a complete, independently accepted
profile02 manifest history and comparison clock for one original-reply grant
scope. They reuse the existing SQLite dependencies and runtime requirements.
They store signed public evidence and grant identities, never grant credentials,
private keys, event ciphertext or plaintext.

Create explicitly from the independently compared generation-one root pin,
fingerprint, complete accepted history and selected scope. Reopen requires that
same independent root and scope. A missing file, foreign schema, invalid signed
history or changed scope refuses; reopening never resets trust. Root transitions
and profile03 evidence are unsupported in this checkpoint surface.

Snapshots cryptographically replay the ordered history and verify its current
head at the supplied trusted time. A snapshot checks the durable comparison floor
but does not advance it. Before exposing plaintext or effects, the authenticated
adapter must call `Accept` / `accept` with the snapshot revision, accepted history
and fresh comparison. This transaction retains the exact original signed bytes
and acceptance times, appends only verified successors and advances the clock
under revision CAS. An alternate valid signature over the same unsigned identity
does not replace previously stored evidence.

Stored manifest acceptance timestamps may be up to 30000 ms ahead of the local
comparison, matching the maintained original-reply client's server-clock
allowance. They do not advance or lower the separate durable local clock floor.
Every signed historical record is reverified at its acceptance time and the
current head is independently reverified at the current local comparison.

An optional Go fence or required Rust fence runs under the write lock after
cryptographic replay. It can recheck independently obtained current authority and
advance comparison, but cannot lower it. It is a trusted adapter callback, not a
source of network authentication. Avoid reentering the same checkpoint in that
callback. A revision conflict requires rereading and revalidating; it does not
authorize automatically retrying an external effect. A lost response after commit
may leave durable state advanced: reopen and recover explicitly.

Keep the database and parent directory private and trusted. WAL and full SQLite
synchronization provide local atomic durability, not protection against restoring
an old complete database or host compromise. At most 64 manifests are accepted;
there is no automatic compaction, migration, enrollment or root reset.

The pinned test runner executes fresh-process reopen, competing-connection CAS,
abrupt process exit with uncommitted history/clock changes, fence rollback, scope
and signed-history corruption controls. It opens actual maintained TypeScript
selected role3 ciphertext after restoring history and durably accepting both
reader comparisons. These tests use explicit synthetic software recipient custody;
the existing protected reader entry point and its independent hardware gate remain
separate. [Current HTTPS grant proofs](ORIGINAL-CURRENT.md) now integrate with
this checkpoint. [Verified reads](ORIGINAL-READ.md) also integrate software and
protected custody; page/consume/status operations remain pending.
