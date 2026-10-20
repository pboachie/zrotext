# Native hosted transaction entry

The optional native hosted installation separates connection initialization
from each business transaction. The server keeps the runtime HMAC key; the
delivery store never receives it. Pool checkout performs the genuine challenge
and bind on the actual client before retaining its namespace/revision candidate.
Those public arguments are configuration, not a backend or content capability.

`native_transaction` and `native_build_transaction` enter each actual transaction
before business locks. The database verifies the original HMAC-bound backend,
native backend start and current transaction identity, current namespace and
the original proof expiry. Entry never renews that expiry. A committed or rolled
back transaction cannot lend its entry to the next transaction. An explicitly
SQL read-only transaction refuses hosted entry because the native proof has its
own protected ephemeral database write, even when the content operation reads
data only.

The initialized pool-to-store factory passes the same actual client and only
its namespace/revision candidate. Every delivery-store-owned transaction enters
again before its existing account, customer, claim or evidence work. A raw
`Client` or ordinary `DeliveryStore::new` has no initialized hosted candidate;
it can use a genuinely unscoped manual database, and refuses hosted work. A
caller-provided candidate or trait implementation cannot replace the database's
native and HMAC checks. No secret or cached Boolean enters the store API.

The exact schema capability is followed by `hosted_runtime_scope` before reading
the namespace. It holds the actual stable configuration shared fence through
commit, including when the namespace is empty. Mandatory namespace transitions
take the opposing fence and version that stable tuple. An empty result alone is
never proof against a concurrent first namespace; stale repeatable/serializable
snapshots must serialize or refuse. The scope operation returns no identity or
permission Boolean and replaces no HMAC check.

The native installation is explicitly in `public`. Only after the exact closed
capability and actual entry succeed does the transaction select
`pg_catalog,public,pg_temp` for the existing unqualified store and hosted-worker
SQL. Operator session search paths do not redirect these business transactions;
temporary objects are last. New profile03 owner/current readers independently
restore `pg_catalog` before their held authentication and currentness checks.
The path setting itself supplies no identity. Genuinely absent pre-installation
manual fixtures preserve their existing path; a resolved old, partial or
polluted hosted graph refuses instead of selecting an older helper.
In particular, an existing public hosted schema needs the native migration
before these checked store paths can run, even if its namespace is empty. The
empty namespace manual path is supported after the exact native capability and
actual absence fence are installed, without requiring a hosted HMAC key.

The explicit callers cover profile03 owner HTTP and device socket transaction
builders, the grant/fetch helpers, hosted billing HTTP and worker transactions,
actual pairing approval/revocation, and the initialized delivery-store call
sites. Startup's namespace marker is read-only public metadata before bind;
it is compared with configured provider identity and does not confer paid or
content permission. Legacy TEST billing remains separately isolated and must
refuse a scoped database. This change does not convert dormant legacy candidate
or provider APIs into hosted profile03 paths.

The native schema capability must be installed and qualified separately. These
callers do not replace genuine owner authentication, fresh consent factors,
current root and manifest ancestry, physical selection, current billing or
one-use message fences. In particular, a new bind cannot renew an old grant or
rearm an unknown attempt. Default profile03 routers and sending gates remain
unchanged.
