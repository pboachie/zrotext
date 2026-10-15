# Native workflow-context candidate

The experimental Rust and Go companions implement maintained ZTWC01 encryption
and opening for opaque content of 1–32768 bytes. They preserve the 222-byte scope,
291-byte header, explicit kind 1/2/3, and P-256/HKDF-SHA256/AES-128-GCM HPKE suite.
Every seal generates a fresh encapsulation. Context content is not template JSON,
UTF-8 text, or a 32-byte recovered CEK. The existing CEK APIs remain unchanged.

Callers independently select owner/archive role 2 or integration role 3. The
verified profile02 manifest must bind the account, trust generation, version and
digest, authorize the selected active scope-8 reader, and contain the matching
active role-4 phone signer with exactly scope 2. The independently supplied clock
must be current and no earlier than the manifest comparison. Context expiry must
be later than that clock and at most 30 days away. As in the maintained primitive,
expiry is not clamped to manifest/key expiry: opening rechecks current authority.

## APIs and ownership

Go exposes `WorkflowContextScope.AAD`, `SealWorkflowContext`, and explicit
`OpenSoftwareWorkflowContext` / Windows `OpenProtectedWorkflowContext` primitives.
The `Current` variants request independently verified authority before crypto and
again before return, require the same enrollment/root and nondecreasing clock,
and discard plaintext on final refusal. Callback-owned manifest state and mutable
input buffers are captured rather than retained across callbacks. Protected
current opening also rechecks the borrowed provider's public point/liveness after
the final authority callback.

Rust exposes equivalent functions in `workflow_context`, with an explicit
`WorkflowContextRole`. Successful plaintext is `Zeroizing<Vec<u8>>`. Go returns
caller-owned bytes, which the caller should clear after use. Internal rejected
plaintext and copied scalar buffers are cleared; provider/library-internal or
caller-created copies are outside that guarantee.

Static primitives and `Current` wrappers are synchronous. For bounded foreground
waiting, use Go `SealBoundedWorkflowContext`, `OpenBoundedSoftwareWorkflowContext`,
or Windows `OpenBoundedProtectedWorkflowContext`; Rust uses `workflow_context::bounded`
with a one-way `Cancellation` and owned `Arc<Manifest>` callback results. Each
language admits at most four unresolved context workers and waits at most ten
seconds (or a shorter Go caller context). A hung callback/native operation keeps
its slot and owned buffers until it actually settles. Cancellation does not kill
native work; late results are withheld and cleared. Rust worker panic is reported
as refusal. Go callbacks must not panic, as with ordinary Go callback APIs.

Protected opening accepts only the existing qualified Windows PCP recipient.
Software custody is a distinct explicit API; unsupported platforms cannot silently
substitute it. These APIs borrow the provider and never delete the caller's key.
The caller owns provider lifetime, consent, review, foreground publication,
persistence, runtime grant checks and any server effects. A current-source callback
does not authenticate transport or persist a monotonic floor by itself.

## Qualification

`test-workflow-context.py` consumes the clean maintained TypeScript fixture at
`7e61c5b2461c82a5fbd05e62d06d14e34a0424d6`, independently verifies native seals with
the maintained reader, and exercises both distinct reader roles. Software controls
cover every wire byte, scope/currentness failures, opaque invalid-UTF8 content,
length boundaries, all kinds, fresh encapsulation and exact expiry semantics.
Protected mode injects only the provider public point into the signed fixture,
exercises both synchronous/bounded final-provider-close refusal, and verifies exact
owned-key deletion. Setup-failure mode checks EOF cleanup. Private key aliases and
ownership receipts remain outside the repository.

The dedicated read-only workflow runs software interop on Linux and Windows;
hosted execution does not establish TPM qualification. Local protected results,
source tests and subsequent clean installed-package qualification are separate
gates. This adds no context store, owner authoring/opening lifecycle, conversation
signing, live grant, production submission or stable-package readiness claim.
