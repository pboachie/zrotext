# Managed historical contact mutations

Java and C# expose `ContactField.Mutation`; Ruby exposes `ContactMutation`.
Verification accepts exact signed ZTCM01 bytes, a genuine verified statement,
independent expected contact scope and expected legacy generation. The resulting
immutable mutation token can enter transition verification with a genuine prior
transition and at most two genuine replacement field tokens.

Create and legacy conversion have no prior mutation. Updates bind the exact prior
digest and revision, root fingerprint, origin, account, contact and routing.
Manifest version and reader generation cannot regress, and equal values retain
their exact identities. Unchanged slots retain their original field token and
statement. New slots bind the exact mutation revision, request, reader and root
writer; absent, duplicate or unused replacements fail closed.

Separate software and protected producers accept canonical 304-byte unsigned
mutation input. They require the independently supplied previous statement to
match the prior transition exactly, validate all transition relations before
signing, and verify the signed result before returning a transition. Protected
production uses the existing qualified contact signer with a dedicated mutation
method. No arbitrary signing domain, manifest or envelope signing is exposed.

Field and mutation producers share four outstanding worker slots and a fixed
ten-second outward deadline. A cancelled caller does not free a slot until its
worker settles. Native public-point lookup and provider lock acquisition occur
inside that worker; liveness is checked again before native signing. The caller
continues to own key closure and deletion. Working byte buffers are cleared where
owned; runtime and provider internals do not promise physical zeroization.

Run `contact-mutation-run.py --language <java|csharp|ruby> --fixture <clean native
fixture checkout> --producer <clean maintained checkout> --origin-asset <trusted
build output>`. The native fixture pin is
`0381f71dc8a67d25562d5a6e23ac4ed50faeed4e`; the maintained producer pin is
`ccf28fe445ba959aa01d99fed6bd9ee3188b749c`. Build its TypeScript SDK first and
create the licensed origin asset with `contact-origin/build.py`. Missing parser
capability is an explicit failure, with no alternative parser fallback.

The shared suite exercises 1536 genuinely signed controls and independently
verifies four newly produced transitions in the maintained SDK. On Windows,
`--hardware --receipt <new private path>` additionally requires actual PCP
signing, twelve closed/cancelled/scope refusals, held-provider cancellation and
the shared admission/deadline regressions. Synthetic setup signing remains in
test-only helpers. Exact created-key deletion and refused reopening are required;
an unresolved cleanup receipt must be retained. Hosted software CI does not
qualify protected custody.

These tokens establish historical signature integrity only. They do not persist
accepted history, decrypt fields, authorize current contact access, submit a
mutation or install a root transition. Installed archive acceptance for these
new APIs remains a separate package gate.
