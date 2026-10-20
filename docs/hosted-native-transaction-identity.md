# Native hosted transaction identity

Migration116 adds native, transaction-bound entry to the protected hosted
runtime proof. It preserves migration106's HMAC domain, nonce, namespace,
policy revision, backend PID and one-use comparison. It does not provision a
namespace or key, activate hosted billing, or grant owner or message permission.

PostgreSQL restricts visibility of another role's backend statistics. Reading
`backend_start` inside a function running as the migration owner can therefore
return null for the ordinary application backend. The new fixed-path invoker
frontends let PostgreSQL evaluate that backend's own native defaults before a
protected trigger checks and records them. No caller-supplied timestamp,
settings flag, statistics role membership or copied verification Boolean is an
identity witness.

## Checkout and each business transaction

`hosted_runtime_challenge(namespace, revision)` and
`hosted_runtime_bind(namespace, revision, proof)` retain their existing signatures.
The challenge first withdraws this backend's previous trust. A valid, single-use
HMAC binds its actual PID and start time for the original 60-second lease.
Separate invoker autocommit challenge and bind statements are supported.

Each business transaction first calls `hosted_runtime_scope()` before reading
the namespace or taking root, account, device or billing locks. This holds the
existing configuration advisory shared lock and its actual stable row through
commit or rollback. Namespace transitions take the exclusive lock and version
that same row. An old repeatable-read or serializable snapshot therefore cannot
reuse historical namespace absence after a committed transition. Lock conflicts
refuse; there is no fallback to a manual path. The mandatory hosted marker also
takes this fence, including when the namespace is empty. The scope call returns
no identity or permission witness.

After bind, each protected hosted business transaction must execute
`hosted_runtime_enter(namespace, revision)` as the ordinary invoker before taking
root, account, device or billing locks. Entry records PostgreSQL's actual
top-level xid8 and returns the original backend proof expiry in milliseconds.
Repeated entry in that same transaction preserves the original expiry. Commit,
rollback, another backend or another transaction cannot reuse that entry.
Checkout does not prepare later transactions.

The first entry must precede savepoints. Its actual physical insert version must
belong to the current top-level transaction, in addition to the full xid8 and
native/HMAC checks. This extra provenance check refuses imported bookkeeping;
it is not an identity witness. First entry inside a savepoint fails closed.
Savepoints created after a genuine top-level entry remain supported.

`hosted_runtime_verified` requires the exact native transaction entry, same
backend start, current enabled namespace and policy revision, and original
verified, consumed, unexpired HMAC proof. The private expiry reader repeats those
checks under row locks. The profile03 grant billing predicate uses this exact
original expiry as an additional deadline; its independent protected projection,
current payment/risk policy and real usage reservation remain required.

The caller integration must cover raw clients, transaction builders and protected
autocommit paths as well as pooled clients. The storage primitive and schema
validator do not install those callers. A missing entry refuses protected work.
Manual self-hosted behavior without a hosted namespace uses the same actual
absence fence and remains separate from HMAC authentication.

## Storage and ordinary role capabilities

`hosted_runtime_requests` is transient staging. The runtime can insert only
operation, namespace, revision and proof, and read only the result needed by
`INSERT RETURNING`. PostgreSQL supplies native PID, self backend start, xid8 and
invoker role defaults. Explicit values and explicit `DEFAULT` in those protected
columns are denied, including through `COPY`. A protected before trigger checks
the closed installation before mutation; an after trigger removes the staging
row. Runtime callers cannot write native or result columns, or read native
columns directly.

`hosted_runtime_entries`, the existing session registry and runtime key have no
ordinary relation or column privileges. Expired transaction entries have bounded
protected cleanup; challenge and bind withdraw only their own backend's entries.
Both new tables participate in the existing explicit global backend-proof
writer class. They do not select an account payload profile or advance its epoch.

The stock provisioner resets relation, column and function privileges. The stock
verifier and shared Rust `hosted_runtime_identity::{optional, require}` pin exact
function declarations/bodies, owners, defaults, triggers, rules and the current
writer catalog. Unknown, partial, disabled or polluted installations refuse.
The server re-exports the single delivery-store validator; its readiness result
is schema capability only, never authentication or current content permission.

The focused public-schema tests use separate migration-owner and ordinary
runtime roles. Source review, SQL qualification, compiled Rust tests, real hosted
caller behavior and deployment remain separate acceptance steps.
