# Experimental managed durable election journals

Java/Csharp/Ruby `ElectionJournal` persists profile02 signed history, one accepted
profile03 election and subsequent profile03 manifests. The initial election
bundle and signed manifest share one checksummed record, selected with an exact
expected revision under exclusive ownership. The event comparison equals the
independently authenticated accepted-record timestamp. Ordinary manifest append
cannot upgrade profiles, repeat an election, downgrade, or perform a root
transition.

Construct `Expectations` from an independently authenticated expected core,
accepted record, device signing point and owner approval point. These values are
captured into owned immutable snapshots. They must be supplied again when
reopening elected history. Storage contains a deterministic digest of these
expectations alongside the bundle; that digest can detect a mismatch but cannot
authenticate expectations or authorize an application. Every restore replays
native manifest/election verification from the original independently compared
generation1 root pin. A stored point or accepted tuple never becomes its own
trust source. Returned proof tokens are historical evidence; current reader or
composer use still requires independently authenticated current authority.

Snapshots reverify the selected manifest at the requested comparison and persist
a monotonic comparison floor. Integrate the snapshot into both reader authority
callbacks: compare the selected manifest identity against the read's captured
identity and refuse if it changed. The acceptance tests exercise this application
boundary and suppress plaintext if a successor is selected between callbacks.
The journal does not query or grant remote service permission itself.

The dependency-free ZTE3 file format bounds history to256 records and3 MB. It
checks contiguous revisions, nondecreasing event times, exact closed record
lengths and checksums before returning a verified selection. Clock and append
writes are fsynced before exposure. A torn clock or incomplete append fails
closed; automatic recovery to a previous complete prefix is unsupported. A crash
after fsync but before return is uncertain: reopen with the same independent
expectations and inspect the verified revision. Never reset storage to force
acceptance. The caller must own the private local path; checksums do not provide
hostile filesystem rollback resistance or tamper authentication.

```text
python sdk/native/crypto-envelope/election-journal-run.py --language java --producer PRODUCER
python sdk/native/crypto-envelope/election-journal-run.py --language csharp --producer PRODUCER
python sdk/native/crypto-envelope/election-journal-run.py --language ruby --producer PRODUCER
```

Build the pinned producer checkout's TypeScript SDK first. The exact producer is
`304d512b7a420a3102278f32baed095f3e778989`. The local fixture adapter signs a fresh
successor with the producer's public synthetic test root and independently runs
the maintained TypeScript successor verifier. Acceptance includes all628 bundle
byte mutations, separately supplied expectation mismatch/missing refusal,
separate-process restore, native selected-envelope opening, competing CAS
writers, clock rollback, torn/empty storage, wrong profile/revision and selection
changes suppressing plaintext. Software recipient keys are ephemeral fixture
material; this journal test does not qualify hardware custody or transport.
Profile03 root transitions and cross-root historical readers remain unsupported.
Normal installed native package consumers are a separate gate.
