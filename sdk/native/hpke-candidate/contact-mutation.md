# Historical contact mutation and transition candidates

Rust `contact::mutation` and Go `ContactMutation` / `ContactTransition` add
signature provenance for ZTCM01 create, update, clear-through-slots, and legacy
conversion. This is historical integrity over already encrypted fields. It does
not establish a current contact grant, decrypt fields, write storage, or submit
a mutation. The caller separately reviews and persists the exact resulting bytes.

`verify_mutation01` / `VerifyContactMutation01` require a genuine verified reader
statement and independently expected account, origin, root fingerprint, contact,
routing digest and legacy generation. They enforce exact framing, signed integer
bounds, canonical slot sentinels, revision rules and low-S root signatures.
`verify_transition01` / `VerifyContactTransition01` then require the genuine prior
transition and exact replacement field tokens. No structural token restoration
or implicit stored-history lookup is accepted.

Updates match the prior signed mutation digest and revision. Enrollment, origin,
contact and routing remain bound; manifest versions and reader generations cannot
move backwards. Equal versions/generations must retain their exact identities.
Unchanged slots retain the original field token and its original statement, even
when the next mutation uses a newer statement. New slots require an exact new
field commitment, request ID and reader/root writer scope. Duplicate or unused
replacement fields are refused. Absent slots have zero revision and digest.

The software and Windows protected producer entrypoints are separate. Production
requires an independently supplied previous statement matching the prior token
exactly. All transition relations are checked before signing, and the resulting
signature and transition are independently verified before return. The dedicated
`ContactRootSigner` can produce only typed contact commitments and mutations; it
cannot sign manifests, reader statements, envelopes or caller-chosen domains.
The caller owns key closure and exact created-key deletion.

Field and mutation production share four outstanding worker slots and a fixed
ten-second outward deadline. Cancellation never releases an unresolved native
worker's slot. Provider lock acquisition and public-point inspection occur inside
the admitted work, with liveness checks before native signing and before result
publication. Rust owns zeroizing software-key copies; Go clears its copied scalar,
but native/runtime internal key objects do not promise physical secure erasure.

## Repeatable qualification

Build `go/cmd/contact-mutation` or Rust example `contact_mutation`, then run
`test-contact-mutation.py --producer <clean pinned source> --binary <probe>`.
The producer revision is `ccf28fe445ba959aa01d99fed6bd9ee3188b749c`; build its
TypeScript SDK first. A trusted shell-free `--command-file` JSON argument array
supports external installed consumers. The source gate runs on Windows and Linux
in the native contact workflow; no hosted protected capability is inferred.

The shared controls include all four mutations, every-byte corruption, equivalent
high-S signatures, genuinely signed invalid predecessor/slot/request relations,
exact retained fields, absent/duplicate/unused replacements, independently expected
legacy generation, prior-statement mismatch, wrong software key and cancellation.
Four newly produced native transitions are independently verified by the maintained
TypeScript implementation. The explicit existing protected contact test also
produces all four transitions with fresh synthetic PCP enrollment and verifies
them independently, then deletes only its owned key and refuses reopening.

Durable accepted-history storage, rollback-resistant installation, current grant
authority and complete installed contact mutation qualification remain separate
gates. No automatic retry, live service action, registry publication or stable
SDK replacement is provided by this candidate surface.
