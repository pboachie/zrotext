# TEST exposure reservation candidate

The unmounted `billing::exposure::TestExposure` library adds a conservative,
durable exposure prerequisite for synthetic provider and AI operations. Its
default constructor refuses requests. Explicit in-process TEST opt-in and
enabled immutable database policies are both required. It adds no HTTP route,
provider/model transport, payment operation, price mapping or runtime worker.
It does not change free/self-hosted startup, the existing Android quota, STOP,
authenticated billing, export or deletion access.

This is a source candidate, not hosted launch readiness. Actual provider
transport authority (#643), managed-reader/model authority (#644), runtime
integration (#641), charge reporting (#673), invoice eligibility/recovery
(#675) and the physical/core readiness gate (#622) remain independent
prerequisites. A budget receipt cannot approve an action, decrypt content,
grant a model reader or release a transport. The caller must separately retain
those permissions and the supported maximum-input/output transport contract.

## Authority and reservation

`reserve` takes the real authenticated owner principal and exact #638
`ActionKey`, including its complete binding digest. The transaction borrows
the actual `lock_approved` permit; historical actor IDs and caller approval
booleans cannot construct it. Current manifest, owner/session, device/line,
recipient-purpose consent, STOP/hold, context, routine generation and exact
action approval are checked by that permit again after budget-lock waits.
Existing TEST entitlement reconciliation, payment-risk holds and bounded grace
state are additional prerequisites for a bound billing customer. Missing or
dirty projection refuses new discretionary exposure. No remote meter summary
or browser estimate can grant entitlement.

The deployment row serializes all participating tenants before root,
billing-customer, account and action locks. Six sorted local dimensions then
constrain tenant, actual device, selected route policy, workflow context,
routine/campaign and exact action/turn. Tenant and workflow budgets are shared
across routes. Missing configuration or any exceeded hard cap rolls back every
counter and reservation. Soft thresholds return a warning without widening a
hard cap. A bounded outstanding-reservation count prevents unlimited dormant
work. Policies are immutable versions; disabling them cannot reactivate the
same row or silently change its rates, period or scope.

Exposure uses integer policy units, not floating point or public prices. For
model bounds, input and maximum output components are multiplied with checked
wide integers, each divided by one thousand with upward rounding, then added
to the fixed bound. Zero/unbounded output or overflow refuses admission. A
future adapter must actually enforce these server-selected maximums; that
adapter is unavailable here. Synthetic provider policies use the same
conservative component bound. Route changes cannot create another reservation
for the same action revision and operation.

## Intent, uncertainty and completion

The first synthetic intent requires a fresh exact owner permit and current
policy, entitlement, original period and not-before time. Final database time
checks every original policy period after the last authority/policy wait, and
the intent lease never extends beyond those period ends. It commits one
durable nonce and lease before returning a non-deserializable process-local
TEST settlement proof. No second intent can be minted from that action,
including after a process restart, expired lease, unknown result or changed
route. This library never starts an external call.

Lease expiration does not release any liability. Unknown outcomes retain the
entire maximum. A trusted in-process synthetic completion can settle at most
that maximum once, releasing only the unused remainder; a verified-not-started
observation can release the bound once. Conflicting or duplicate completions
cannot restore more budget. These are TEST observations, not a production
provider signature/reconciliation implementation. Recovery of production
terminal evidence remains unavailable; such started rows conservatively consume
their bound until review.

`cancel_unstarted` releases an abandoned reservation only when its durable state
is still `reserved` and no intent nonce or lease has ever been issued. It requires
a currently authenticated account owner, rechecked after the last database write.
Cleanup does not require renewed action approval, live route policies, invoice
eligibility or a current reader: those conditions grant no authority to start work
through this method. Expired actions and withdrawn policies can therefore be
cleaned up without reactivating them. The global deployment lock serializes
cancellation with the first intent; cancellation then locks the account/owner,
reservation and its six original sorted budget rows. It never acquires root or
action locks afterwards. An issued, expired, unknown or reviewed intent is refused.

The existing immutable `released` tombstone records zero actual units and a
domain-bound cancellation digest. All original scope and deployment outstanding
units decrease atomically; finalized units, Android quota and financial credits
are untouched. A trigger/storage failure or owner expiry rolls back the entire
release. Exact replay on another connection returns unchanged after fresh owner
authentication. The same reservation cannot obtain an intent or reserve again as
new work. There is no automatic expiry release, new public endpoint or provider
evidence claim.

Confirmed completion of an already-started synthetic effect remains
accountable after owner/action expiry or policy withdrawal. It grants no new
work. No exposure completion refunds the existing Android admission quota or
issues financial credits. Existing gateway reservation/refund and #673 charge
boundaries stay separate.

## Periods and privacy

Policies carry exact original UTC millisecond period bounds. A new policy
version sums finalized usage for that same period; recovery does not replenish
it. Every new period also sums all outstanding older liability. Overlapping
different intervals are refused, so moving a period boundary cannot reset
consumed budget. Current configuration is operator-supplied TEST policy, not
proof of a subscription invoice or renewal. The authoritative invoice-bound
eligibility bridge is pending #675.

The ledger contains opaque scope/action/actor identities, policy versions,
counts, times, digests and lifecycle state. It copies no recipient number,
message content, plaintext model input, credential or provider response body.
Context/action metadata retirement tombstones the separate live-action reference
without changing the immutable reservation identity, counters or settlement
proof. A tombstoned reservation cannot acquire an intent or restore authority;
already-issued TEST settlement still conserves liability.
Tenant erasure removes reservation mappings, reservations and local policies
before their workflow/device dependencies. Deployment aggregate units contain
no tenant identity and remain conservatively counted after erasure; deletion
cannot manufacture available exposure from an uncertain effect. Production
financial retention and reconciliation policy still require review. Owner
dashboard/export projection is pending #676; these library receipts are not
an account-wide public usage endpoint.

Stripe processes usage asynchronously, so external aggregates are unsuitable
as a real-time admission counter. This candidate uses the local transaction
ledger and makes no Stripe call. See the official [usage recording contract](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api)
and [subscription lifecycle documentation](https://docs.stripe.com/billing/subscriptions/webhooks).
