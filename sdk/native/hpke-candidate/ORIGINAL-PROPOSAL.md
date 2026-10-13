# Saved original-reply proposals

The Rust and Go candidate clients can prepare, restore, consume and reconcile a
typed original-reply proposal. This creates a proposal or records owner review;
it does not approve, schedule, dispatch, or send an action. The service remains
responsible for current output-grant scope and contact/routine authorization.

`WorkflowAction` parses the complete closed workflow-action-01 descriptor and
owns its canonical bytes. Canonicalization matches the maintained TypeScript
helper and public vector: sorted fields, ordinary bounded integers, ASCII JSON
including control and DEL escapes, and SHA-256 of all fields. Integral JSON
number forms such as `1.0` and `1e0` normalize to `1`, matching JavaScript Number
semantics within its safe integer bound. The general helper
accepts opaque vector identifiers. Preparing a production proposal additionally
requires nonzero canonical UUID fields and revision 1 through 128. A digest is
an integrity binding, never permission.

Go provides `PrepareProposal`, `RestoreProposalIntent`, `ConsumeProposal`, and
`StatusProposal`. Rust provides the corresponding snake-case methods. The caller
supplies the event, consumption request and active request identities; none are
generated or replaced. The descriptor account and line must match independently
enrolled client scope. Persist and sync the intent bytes before calling consume.
Application persistence is mandatory but is not enforced by a library journal.

The saved format is `ZTOP` plus version byte 1, followed by the same root, scope,
event, request and active-request fields as the 151-byte owner-review frame.
The active flag must be 1. Exact canonical descriptor JSON immediately follows
byte 151; total size is at most 4096 bytes. Restore rejects noncanonical JSON,
wrong enrollment/scope, missing active identity and malformed descriptors.
Bytes are application-owned trusted storage, not a signature or authority token.
No read or output credential is persisted in the record.

Consume requires both an original read grant (`ztr_`) and a separately supplied
output grant (`ztw_`). Malformed or wrong-role credentials refuse before network.
The output header is attached only to the single descriptor-bearing consume
request; current and status requests carry only the read grant. The client checks
syntax and separation, while the service authenticates the output grant and its
current permissions. Redirects, automatic retries and automatic resubmission are
disabled. The public generic original transport still accepts no proposal grant.

Authenticated current proof and the durable accepted-history fence precede the
operation and are refreshed before returning success. Results must match the
saved event, consumption and active request. Proposal action account, ID, revision
and digest must exactly match the saved descriptor. The legitimate server
`owner_review` fallback has no action and conveys no proposal authority.

Any failure after consume dispatch, including invalid correlation or final proof
failure, is unknown. A pre-dispatch refusal means no attempt in this call, not
absence of prior effects for the saved identity. Status reuses the same saved
intent and never consumes, including after 404. Return values are historical
metadata accompanied by a current snapshot; they are not reusable send permits.

The dedicated workflow executes public canonical vectors and synthetic signed
TLS tests, including role separation, closed responses, malformed descriptors,
current-proof refusal, action correlation and a separate-process reconciliation
after a lost response. No production service or device effects are exercised.
Installed archive qualification for these new methods remains a separate gate.
