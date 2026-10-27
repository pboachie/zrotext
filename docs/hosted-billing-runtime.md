# Isolated hosted billing runtime

`HOSTED_BILLING_MODE` selects `disabled` (the default), `test`, or `live` for
one process and database identity. It is independent of the legacy
`STRIPE_TEST_*` transport. The two configurations cannot be combined. A browser,
event, checkout return, or database customer ID cannot select a mode.

The source mounts the configured runtime at `/v1/billing`. It does not provision
a namespace, runtime key, price, credentials, or provider configuration. This
document describes code capability, not approval to activate a hosted service.

## Configuration and startup

All `HOSTED_BILLING_*` settings are listed in `.env.example`. Enabled modes need
an explicit namespace UUID, provider account, positive policy revision, one
fixed recurring licensed price, positive message/device allowances, grace
duration from zero through seven days, explicit automatic-tax choice, separate
restricted read and session credentials, webhook endpoint/signing secret,
portal configuration, and an independent random 32-byte runtime key.

Startup checks each credential's own `/v1/account` identity and `/v1/balance`
mode. A matching key prefix is insufficient. It validates the configured price
and portal metadata and the webhook endpoint's account scope, mode, API version,
URL and event subscription. Non-Connect events are retrieved with the verified
read credential before a new event can affect local state. Connected-account
events and other API dialects are refused. Provider requests are bounded, have
no redirects or retries, use the pinned API version, and have a capped circuit
pause after failures. Credentials and raw provider objects are not logged.

The read credential needs its own account/balance, prices, webhook endpoints,
events, subscriptions, invoices, charges and invoice payments read access. The
session credential needs its own account/balance and prices/portal configuration
read access, plus customers and Checkout/Portal session creation. Runtime code
never mutates provider prices, subscriptions, refunds, disputes or credentials.

Migration 106 creates empty namespace and protected runtime proof
tables. The database owner separately provisions the exact namespace, immutable
provider identity, policy revision, enabled/fenced state and runtime key.
Existing legacy TEST bindings prevent enabling this isolated namespace. A
different mode requires a separate database and deployment identity.

Use a dedicated ordinary application role through the existing role provisioner.
It must not own the database's paid admission tables, inherit the migration
owner, create objects in the installation schema, read the runtime key, modify
the protected session registry, or execute operator risk resolution. The role
provisioner explicitly removes the broad grants from these protected objects.

Every pooled checkout proves the runtime key using HMAC-SHA256 over a fresh
database nonce, namespace, policy revision and backend PID. The database binds
the proof to the backend start time. Nonces are single use and expire after
60 seconds; a fresh challenge first invalidates previous trust. Protected
functions fix their search path to `pg_catalog`, the exact installation schema,
then `pg_temp`. Custom settings are dispatch hints and confer no authority.
Migration116 adds native invoker defaults and an exact-transaction entry before
each protected business transaction. Checkout proof alone does not prepare a
later transaction. See [the storage and caller boundary](hosted-native-transaction-identity.md).

## Owner journey and interrupted checkout

`GET /v1/billing/plan` returns only provider-verified configured terms: mode,
currency, minor-unit amount, renewal interval/count, message/device allowances,
tax behavior, automatic-tax choice and `allowance_period: subscription_invoice`.
Public GETs perform no provider calls. Startup and the scheduled worker refresh
the verified snapshot, with a 30-second refresh interval and 120-second freshness
bound. Checkout independently rereads the current price before creating a
session. An inactive, unsupported or unavailable price has no fallback.

Owner reads require a current session cookie and matching CSRF cookie/header;
same-origin GETs do not require an Origin header. Mutations also require the
canonical Origin. Every owner operation fences its account/session again under
writer locks and checks session expiry immediately before commit.

`POST /v1/billing/checkout` and `/portal` accept an empty body or an empty
object. Customer, price, quantity, portal configuration and return destinations
come from authenticated server configuration. Provider IDs and URLs supplied by
a browser are rejected. Checkout/Portal URLs must use the exact trusted HTTPS
provider host.

Customer and Checkout operation IDs are durable before provider creation.
Unknown results preserve the same operation and a digest of its exact server
request. `POST /v1/billing/checkout/recover` accepts an empty body or object and
only replays that matching pending operation inside a 23-hour window, shorter
than provider idempotency retention. It cannot create a customer, allocate an
operation, replace an attempt, or select changed terms. Status reads and workers
never replay provider mutations. The recovery response is `{url}`: the same
confirmed open URL, or null if that same operation is already closed and needs
current reconciliation. Missing request provenance, changed configuration, known
open/closed sessions and risk latches refuse recovery. An unknown operation outside that window
requires operator reconciliation; it is never silently retried with a new key.

`GET /v1/billing/status` returns `account_id`, `session_id`, current observation
time, the authoritative `customer_bound` flag, entitlement and reconciliation
state, plus a Checkout observation:

| State | Meaning |
| --- | --- |
| `none` | No local attempt exists. |
| `pending` | The existing operation cannot be safely replayed, or billing needs review. |
| `recoverable` | An exact durable pending request remains inside its replay window; an explicit recovery action may replay only that operation. |
| `resumable` | The provider confirms the same open session; use its returned URL. |
| `reconciliation_required` | A closed attempt needs complete current subscription reconciliation. |
| `replaceable` | A closed attempt and complete reconciliation confirm no nonterminal subscription; a new explicit POST may replace it. |

Return query flags only select explanatory UI. They never settle an attempt,
create an entitlement, repeat a mutation or authorize another purchase.

## Reconciliation, risk and admission

The durable event inbox is keyed by namespace and event ID. Identical signed
bytes are a no-op, including during a provider outage. Changed bytes conflict.
Events cannot create customer bindings. Minimal pointers, hashes and state are
retained; raw event/provider JSON is not stored.

The worker claims a durable generation/lease before provider reads and commits
only against the same namespace, account, policy revision, lease and generation.
Complete bounded current subscription/invoice reads drive access. Partial lists,
unknown shapes/prices, multiple nonterminal subscriptions and expired grants
cannot produce new capacity. A subscription change archives the old immutable
scope before a fresh read can establish another projection.

The first trusted signed current-invoice failure anchors continuous delinquency.
Its event time is capped by receipt time. Duplicate/delayed events, invoice
changes and process restart cannot extend the original grace deadline. A
confirmed recovery establishes a boundary that excludes earlier failures. A
missing reliable failure anchor leaves access pending. Outage never creates or
renews access, extends grace or clears risk; durable work remains retryable.

Refund/dispute holds require current charge to paid invoice-payment to invoice
attribution under the bound customer/subscription. Unsupported risk is durably
latched for review before acknowledgment. If no owner can be attributed, a
namespace review latch blocks grants. An ordinary application role cannot clear
these latches. Only the database operator may call
`hosted_resolve_review(namespace, revision, event, reason)` with an explicit
supported reason; the authenticated database role, event and time are audited.
Resolution queues a fresh provider read and grants no access by itself.

Paid message admission reserves the existing `usage_ledger` in the same
transaction as message creation. Namespace/invoice attribution supplements
that ledger; it is not another usage ledger. Deferred checks repeat current
database time and authority before commit. Device enrollment similarly checks
the current paid device cap at commit. An older binary or forged custom
setting cannot bypass these database fences. Legacy TEST and self-hosted
admission retain their existing authority when no hosted namespace exists.

Hosted customer, payment-review, attribution and audit records block complete
account erasure until operator billing termination/retention handling is done.
Erasure cannot discard a customer binding while leaving an external subscription
unaccounted for.

The unchanged 100–104 predecessor migration train and its account/runtime-role
fences are required. Migration 105 adds pairing recovery; migration 106 adds
these explicit storage classifications:

| Relations | Ownership and writer boundary |
| --- | --- |
| `hosted_billing_customers`, `hosted_billing_projections`, `hosted_billing_history`, `hosted_billing_audit`, `hosted_billing_usage` | Immutable nonnull `account_id`; shared account fence and live anchor before writes; only reductions may follow an account tombstone. |
| `hosted_billing_events`, `hosted_billing_resolutions` | Immutable nullable `account_id`; bound rows use the same anchor guard, unbound rows remain deployment scoped and cannot later be assigned by update. |
| `hosted_billing_namespaces` | Operator provisioned deployment identity; immutable namespace/mode/account, explicit revision/fence, application can only latch review. |
| `hosted_runtime_secrets`, `hosted_runtime_sessions` | Owner-only proof state; no ordinary role relation or column privileges. |

The combined profile03 writer inventory evolves with each numbered schema;
migration116 also classifies its transient native requests and transaction entries
as global backend-proof state. These identity records do not grant payload
authority or advance selection epochs. A focused disposable fixture on an earlier
baseline is not whole-migrator qualification. Provider/account acceptance, physical phone/carrier
behavior, credentials, activation and deployment require separate authorized
validation; source tests do not establish them.
