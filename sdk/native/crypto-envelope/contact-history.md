# Managed contact local history

Java, C# and Ruby expose `ContactHistory` / `ContactLocalHistory` under
`crypto-envelope/{java,csharp,ruby}/contact-history` and `ruby/contact/`.
Current snapshots alone are insufficient provenance: every lookup and accept
independently re-verifies the stored generation-one profile02 manifest chain
at each manifest's original accepted comparison time, and every accepted row
must still bind to one manifest of that history by version, digest, active
reader record and root writer record, under the current head floor.

`create` initializes one file with the complete verified signed root history;
missing state never initializes on reopen. Tokens are session-bound: a token
from a closed or different session is refused. `accept` performs exact CAS
against the expected row, tolerates byte-identical replay, refuses forks
(revision jumps, prior-digest mismatch, manifest version or reader generation
regression), allows cold creation only for create/legacy operations at
revision one, enforces the maximum-record bound, and requires the supplied
history to extend the stored one by exact prefix. `markUnavailable` records
the terminal local stop; terminal rows stay terminal across restarts. The
reduction mode reads and terminates but never records positive history. At
most four sessions are admitted concurrently with a bounded lifetime.

Records append under an exclusive file lock with a chained digest; torn
appends refuse on reopen. Run
`contact-history-run.py --language <java|csharp|ruby> --producer <clean
maintained checkout> --origin-asset <trusted build output>` to exercise
restart, process CAS, replay, fork, terminal and reduction controls plus the
interrupted-append refusal; the maintained producer pin is
`ccf28fe445ba959aa01d99fed6bd9ee3188b749c`. Installed package qualification
stays with the package lanes; no current-authority, service or
protected-private-key claim is made.
