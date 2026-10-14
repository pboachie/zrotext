# Owner context authoring

Portable initial `kind1`/`revision1` owner workflow facts authoring for the native
Rust and Go candidates. The host independently supplies current owner authority,
an owner session, a draft lease and the exact pre-POST review; the lifecycle
never claims DOM presentation or protected private-key custody. Sealing uses the
authorized archive-reader public point only.

Behavior follows the maintained TypeScript `owner-context-authoring.ts` and the
sealed Python `context_authoring.py` portably: explicit exact review before any
POST, internal persistence client with an instance-bound ticket, acknowledged
saved source, explicit retry/verify reconciliation capped at three posts and
three checks, nonrenewing deadlines, and unknown-outcome identity retention.
`test-context-authoring.py` compares the native lifecycles against the
maintained state machine over actual synthetic TLS using the pinned maintained
context oracle checkout; installed archive qualification stays with the
package lane.
