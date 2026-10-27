# Ordinary owner authentication for profile integration

`auth::ordinary_owner03::authenticate` verifies an ordinary browser session
cookie and the existing origin/CSRF contract in a caller-owned primary
`READ COMMITTED` transaction. It uses the application's configured token hasher
and canonical HTTPS origin, not values selected by a request.

The initial session-token HMAC lookup is only an identity hint. The adapter
locks the actual ordinary owner records through `owner_records`, then checks
the same HMAC against that exact held session before verifying its stored CSRF
hash. A token rotation between lookup and locks refuses the old cookie. A final
record and primary-clock recheck precedes creation of the opaque, transaction-
borrowing `HeldOrdinaryOwner03` value. Later `revalidate` calls detect expiry,
revocation and changes made by trusted code within the holding transaction.

The adapter pins `pg_catalog`, qualifies application tables, bounds token
decoding, and retains the existing lock and statement deadlines. It performs
no activity refresh, credential creation, session revocation, MFA verification
or abuse-budget write. The HTTP caller must provide its own admission policy,
roll back on refusal, and revalidate immediately before later composition.

The proof exports canonical identity and configured-origin digests, not a
reusable unlocked `SessionPrincipal`. It is not fresh password/TOTP or root
authorization, isolated reviewer authentication, device authority, an accepted
profile election, a schema/state certificate, or permission to send a message.
This library prerequisite mounts no route and enables no runtime feature.

PostgreSQL tests use the actual numbered schema and separate ordinary owner and
non-owning runtime roles. Synthetic MFA/root prerequisite rows do not establish
a fresh MFA/root ceremony. Cookie/CSRF authentication, integrated application
acceptance, physical-device acceptance and release readiness remain distinct.

## Held password and factor step-up

The `auth::ordinary_owner03::step_up` adapter accepts only an already authenticated
held ordinary owner witness. It reads the current password verifier under those
locks and runs the bounded Argon2 worker. Before hashing, an exclusive NOWAIT MFA
row lock serializes the existing factor-failure budget, TOTP replay state and
recovery-code consumption. Incorrect passwords and factors share that durable
budget; a rejection returns no proof and the caller must commit only the budget
before reporting the refusal. No route is mounted by this component.

Successful TOTP verification decrypts the actual enabled owner secret with the
independently configured MFA cipher and identity-bound associated data, evaluates
the primary database clock, and consumes its exact step. Recovery consumes one
unused pepper-derived code. The opaque result borrows the same transaction and
retains the exact consumed step or recovery timestamp. Revalidation checks that
state, current factor window, bounded five-minute ceremony lifetime, all original
owner credential/role/session records and actual clock again. A later failure
must roll back factor use together with the election writes. The proof never
exports a password, factor, session principal or reusable freshness flag.

Endpoint admission, its separate request/management budgets, actual root/key
possession, schema and state qualification, durable election, device authority
and effect authorization remain additional obligations. This adapter does not
make any profile or messaging capability available.
