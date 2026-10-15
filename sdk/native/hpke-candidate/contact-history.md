# Local contact history

Go `OpenContactHistory` and Rust `contact::mutation::history::History::open`
persist bounded local acceptance metadata. Supply an independently compared
root pin and fingerprint, a canonical origin, capacity of 1–256 contacts,
and a separate existing native `Journal` containing signed root history.
Creation is explicit. Rust selects `OpenMode::Create`, `Existing`, or
`LocalReduction`; Go supplies explicit creation and reduction flags.

The signed journal must contain 1–64 exact generation-one profile02 manifests
with monotonically increasing comparisons. Every history check verifies the
chain from the caller's enrollment, then rechecks the selected manifest and
its account-archive/root-writer records at the accepted statement's issue time.
Profile03 elections and root transitions are refused by this adapter.

`Accept`/`accept` takes a genuine transition, its exact genuine statement, and
the expected local row token (or absence for a first record). SQLite uses an
immediate transaction, exact-row comparison, WAL, and full synchronous commits.
Initial rows require create or legacy conversion at revision one. Updates
require the exact predecessor, next revision, routing identity, and monotone
manifest/reader selection. Exact same-revision replay is idempotent; a different
signed identity is a fork.

`Lookup`/`lookup` returns copied metadata and an opaque session-bound token.
Another instance, replaced row, or previous process cannot supply that token.
Reopen and look up the row to obtain a new token. `MarkUnavailable`/
`mark_unavailable` records a terminal local stop. A reduction session can stop
rows without root history, but cannot accept or expose accepted evidence.

Results distinguish:

- `accepted_local_history`: metadata with separately rechecked signed root
  evidence, never permission or remote acknowledgement.
- `unavailable`: `unobserved`, `local_stop`, `reduction_only`, `root_mismatch`,
  or `history_missing`. Structural metadata corruption refuses the operation.
- `recorded_needs_recheck`: a committed write whose independent root history
  changed or could not be checked afterward. Look up again.
- `write_unknown`: a storage failure or close/deadline crossed the write
  boundary. Reconcile by lookup; there is no automatic retry or new identity.

Four live adapters are admitted per process, with one operation each and a
thirty-minute maximum lifetime. Operations check a ten-second budget; SQLite
lock waits have a five-second limit. Rust filesystem/SQLite calls are
synchronous: this does not promise interruption of stalled operating-system
I/O. Close suppresses publication and retains in-flight admission until actual
settlement. Go adapters must not be copied after first use. Close/drop owned
adapters when finished.

Both databases and their parent directories must remain application-private.
Metadata has an independently bound header and fixed-width rows (387 bytes
accepted, 17 bytes stopped). It is not signed transition evidence: arbitrary
modification of otherwise well-formed metadata by an attacker with write
access is outside this boundary. Lookup never recreates verified transition
or field tokens. Whole-database rollback cannot be detected without an
external checkpoint. No current grant, server acknowledgement, browser
visibility integration, publication, or installed-package qualification is
claimed.

`test-contact-history.py --producer <pinned-source> --binary <native-probe>`
uses maintained synthetic fixtures and real native SQLite/crypto. It covers
restart, exact CAS, genuine forks, altered/regressed signed history,
corruption, terminal reduction, capacity, a killed uncommitted SQLite writer,
and a root change while a metadata write waits. A trusted shell-free
`--command-file` argument array is also supported.
