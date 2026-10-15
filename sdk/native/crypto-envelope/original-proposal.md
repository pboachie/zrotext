# Candidate managed saved typed proposals

Java, C#, and Ruby expose immutable workflow-action-01 canonical bindings and saved original-reply proposal intents. These APIs propose only: they do not approve an action, dispatch SMS, or establish workflow eligibility locally.

Use `WorkflowAction.parse` (Java/Ruby) or `WorkflowAction.Parse` (C#) to validate the closed 16-field descriptor and obtain canonical JSON and its SHA-256 binding digest. The canonical helper accepts bounded ASCII identifiers; preparing a production proposal additionally requires canonical nonzero UUID identifiers, revision 1..128, and account/line agreement with the independently enrolled original-read scope. Integral JSON numbers such as `1.0` normalize to decimal integers, consistent with the maintained JavaScript helper. Duplicate/unknown fields, unsafe numbers, non-ASCII strings, and invalid time intervals refuse.

Create `prepareProposal` / `PrepareProposal` / `prepare_proposal` with an event ID, stable caller-chosen request ID, required active request ID, and the descriptor. Persist and sync the exact returned bytes before calling consume. The library performs no intent-file persistence. The `ZTOP` version-1 record replaces the five-byte prefix of the existing 151-byte owner-review frame and appends the exact canonical descriptor. Restore binds the enrollment point, complete original-read scope, event, request, active request, account, and line. Noncanonical encodings refuse. Returned byte arrays are copies.

`consumeProposal` / `ConsumeProposalAsync` / `consume_proposal` takes a separate original-read `ztr_` grant and workflow-output `ztw_` credential. The output credential is attached only to that single consume request; current proofs and status requests receive only the read grant. The low-level Ruby `exchange_proposal` transport returns untrusted wire JSON; authentication and result correlation belong to the typed client, as with the internal Java/C# transport entrypoints. Both sides of the typed effect require fresh verified current proofs and durable checkpoint advancement. The server still decides recipient, purpose, routine, integration, source-grant, content, and permission eligibility. No credentials belong in saved intents.

The returned event, consumption ID, and active request must exactly match the intent. A proposal result must also match descriptor account/action/revision/digest. A correlated `owner_review` result with no action is a legitimate fallback. `action` / `Action` is null for that fallback; otherwise it is the immutable descriptor whose returned action identity was verified.

A consume failure after dispatch is an unknown outcome, including malformed or mismatched results and a failed final current proof. Restore the same saved intent and call `statusProposal` / `StatusProposalAsync` / `status_proposal`; status never consumes or needs the output credential. An unavailable status does not prove that the earlier effect did not happen. No retries are automatic. The existing trusted local checkpoint path, fsync uncertainty, and whole-file rollback limitations still apply.

## Qualification

Run `python sdk/native/crypto-envelope/original-proposal-run.py --language java --fixture <reviewed-native-fixture> --producer <reviewed-selected-reply-producer>`; substitute `csharp` or `ruby`, with optional `--ruby` executable. The runner checks an exact clean shared fixture revision and uses the independently signed selected-reply producer pinned by that fixture. It builds only candidate source, using the existing pinned Gson dependencies for Java and standard libraries for C#/Ruby.

The shared suite checks 46 canonical bindings and 76 synthetic HTTPS consumption/status cases, including complete descriptor mutations, separate credential routing, exact saved bytes, currentness failures, malformed/correlated results, owner-review fallback, lost responses, and separate-process status reconciliation. Dedicated Windows/Linux CI is configured. The installed-candidate acceptance suite also runs these controls through separate consumer command files. Local source execution remains separate from installed-package qualification, registry publication and live service authorization.

The semantic test drivers allow four seconds for normal transport work on a cold
managed runtime. Dedicated transport deadline controls and every signed-clock,
correlation, saved-identity and unknown-outcome assertion remain unchanged.
