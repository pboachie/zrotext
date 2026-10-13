# Experimental managed root transition journals

Java/Csharp/Ruby `ManifestChain` can accept an explicit profile02 root transition
and its anchored new-root genesis as one verified result. The caller must supply
an independently approved new-root public point. Both low-S signatures bind the
old generation, next generation, exact root points, account and prior semantic
manifest digest. The new genesis must restart version1 in the next generation
with the unsigned transition digest as its predecessor anchor. Ordinary manifest
continuation cannot perform rotation, and generation2 pins cannot silently replace
the original generation1 enrollment.

`RootJournal` stores original signed evidence under the original root pin and
independently compared fingerprint. Its separately supplied approval map is keyed
by successor root generation, cloned at construction, and required again during
restore. Stored root points never become their own approvals. Each operation
replays every signature and binding at its recorded comparison time, checks CAS
revision, and holds exclusive file ownership through fsync and return. Snapshot
checks refresh the selected manifest and durably advance the comparison-clock
high-water mark, so a process restart cannot accept a lower retained clock.

The dependency-free store bounds history to256 records and3 MB. A transition
and new genesis share one checksummed record; no half-pair is returned. A partial
append or torn clock write fails closed on reopen. Unlike a transactional SQLite
store, this format does not automatically roll back to the last complete prefix
following a torn append. Preserve that file and reconcile externally; never reset
it to force acceptance. A crash after successful fsync but before return is an
uncertain result: reopen and inspect the verified revision before proceeding.
Checksums are accidental-corruption detection, not tamper authentication or
filesystem rollback resistance. Applications must own the private local path.

The acceptance runner uses the maintained public draft02 rotation corpus plus
independently pinned TypeScript-generated fresh rotations. All targets exercise
every transition/genesis byte mutation, high-S twins, missing/wrong external root
approval, separate-process restore, competing CAS writers, clock regression,
partial/corrupt storage and old enrollment preservation. Actual native readers
open a newly encrypted inbound after new-root genesis/successor restore and
suppress plaintext if the journal advances between the pre/post checks.
Cross-root historical ciphertext remains refused, even with an unchanged archive
key. Profile03 root transitions and durable election storage remain unsupported.

```text
python sdk/native/crypto-envelope/root-journal-run.py --language java --producer PRODUCER --controls CONTROLS
python sdk/native/crypto-envelope/root-journal-run.py --language csharp --producer PRODUCER --controls CONTROLS
python sdk/native/crypto-envelope/root-journal-run.py --language ruby --producer PRODUCER --controls CONTROLS
```

The runner verifies exact clean source pins: producer93a65d737dfb0de603c732241c667f90771f60dd
and controls26e73753c4ff5e3b27abdca6f5b67ed3ce5a0273. Build the producer's TypeScript
SDK first. Its ephemeral software recipient is test material, not a hardware
custody or live application authority claim. No transport or SMS is exercised.
