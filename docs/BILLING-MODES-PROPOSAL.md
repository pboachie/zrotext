# Explicit billing mode isolation (proposal)

Status: **PROPOSED, unavailable**. This contract settles the design scope of
issue #645; it adds no live configuration, migration, provider call or paid
entitlement. [Current billing](STRIPE-TEST-BILLING.md) remains TEST-only and
rejects live keys and events. Quota-only plans do not enable live payments.
Existing TEST checks must remain unchanged until a separate implementation is
reviewed. Commercial choices, credentials, customer records and activation
procedures belong in private operations.

## Configuration and authority

A future deployment selects exactly one immutable mode: disabled, test or live.
No default selects live. Disabled means no billing session, event or provider
worker capability; whether an application route requires billing is a separate
admission policy, never inferred as permission to send for free. A production
route requiring live payment must refuse test and disabled projections.

Test and live use separate deployment/database billing namespaces, endpoint
signing secrets, scoped session/reconciliation credentials, provider account
identity and price/quota policies. A signing-secret prefix alone does not prove
mode. Before serving billing traffic, credential validation must confirm both
provider account identity and mode against the selected namespace. Failure or
provider unavailability leaves startup unready. Credential rotation may overlap
signing secrets only within the same account and mode and for a bounded period.
No fallback from a missing live credential to a TEST or shared credential.

Startup fails closed for missing/empty credentials, opposite-mode credentials,
both modes enabled, wrong provider account, absent schema capabilities, database
mode/policy mismatch or removal of previously enabled caps. Switching a process
flag cannot relabel stored state. The namespace marker is checked by API,
workers, session routes, review tools and admission transactions; old binaries
must be fenced before live state exists. The generic names here are contract
fields, not environment variables accepted by the current server.

The authority key is `(mode, provider_account, owner_account, customer)`.
Customer binding is established by the authenticated owner session flow using
the selected provider account; event metadata and customer ID prefixes cannot
create a binding. A customer belongs to one owner in its namespace. Every
subscription, invoice, charge, payment, event, risk review, session, policy,
projection, audit and quota reservation carries or references that namespace.
Cross-mode/account references fail before mutation, even if opaque IDs collide.
Existing TEST customers and active subscriptions grant **no live entitlement**;
a new live binding and current live reconciliation are required.

## Event and reconciliation contract

Verify bounded raw bytes and signature with the endpoint's own secret before
parsing; retain the existing freshness limit. Require event mode, object mode
and all provider reads to equal the endpoint namespace and provider account.
Never accept a body-selected account or mode. Inbox uniqueness is
`(mode, provider_account, event_id)`: identical bytes are a no-op, different
bytes under that key conflict. A rejected foreign or stale event changes no
binding, quota, hold or grace deadline. A same-ID event in another isolated
namespace is independent, not a duplicate that can bypass verification.

Events request current-state reconciliation, never directly grant entitlement.
Read complete bounded subscription sets for the bound customer in the selected
namespace; pagination truncation and multiple nonterminal subscriptions pause
admission. Terminal subscriptions do not create ambiguity. Recognized active
prices project quota/device limits from the namespace's policy; unrecognized,
inactive, ambiguous and pending states project no new paid admission. Keep
account locking, exact replay behavior and policy-version fencing: one accepted
action reserves once; replay never consumes a second unit. A downgrade preserves
existing reservations and lowers future allowance. Restart preserves unchanged
policy projections; changed policy queues reconciliation and pauses old grants.

Preserve TEST grace semantics in live: seven days from the first trusted signed
matching current-invoice payment failure, with future event time capped at
receipt, and recovery boundaries excluding earlier cycles. Duplicates, delayed
events, invoice changes and restart never extend continuous delinquency. Check
the database clock under admission locks. Missing trusted failure time pauses
admission. Device-cap downgrades block new enrollment but do not automatically
revoke an existing device.

Refund/dispute evidence queues risk in its own namespace. Queue/review/hold
states block new paid reservations while the worker attributes the payment via
current charge, paid invoice payment and invoice evidence. Unsupported risk
shapes commit review-required state before acknowledgement. No automatic hold
clearance on subscription activity or provider outage; any resolution is an
authenticated, audited same-namespace operation with provider evidence. Do not
invent refund policy or pricing here.

Provider outage cannot create or renew a grant, extend grace or clear risk.
Pause unresolved reconciliation and new projections; an already confirmed
projection may remain usable only within its existing policy/grace boundaries,
with risk and caps still checked. Bounded retries retain inbox/risk state and
never acknowledge an event whose durable record failed. Projection, quota/cap
audit and queue completion commit atomically. A crash before commit retries;
a crash after commit is an idempotent no-op. Multi-worker fencing prevents an
older policy result overwriting a newer one.

## Migration, rollback and review slices

1. Add a new additive migration (never edit applied migrations) that explicitly
   labels legacy billing rows TEST. Inventory namespace coverage and add
   composite references/uniqueness across inbox, customer/session/subscription,
   risk/review, policy, quota/cap projection and reservation/audit state. Existing
   non-billing usage remains application usage and cannot become live payment
   evidence. Decide separate database deployment wiring before writing SQL.
2. Fence old writers/readers, drain in-flight jobs, and prove the marker rejects
   an old or wrong-mode binary. Implement mode validation and same-namespace
   readers without enabling live. Preserve the entire TEST regression suite.
3. Add isolated live sessions/events/reconciliation/admission with disposable
   fake-provider and PostgreSQL coverage. Review scoped permissions and startup
   account verification. Activation and provider/account choices require the
   private operations process; this document authorizes none.

Rollback first pauses live admission/session creation and drains workers.
Retain live inbox, risk holds, reservations and audit history; do not down-migrate
or relabel them as TEST. Only a binary that understands the namespace fence may
resume the database. An old TEST-only binary may use a separate TEST database,
never the live namespace. Restore must retain the marker and recompute pending
projections through current provider reads; neither backup age nor an old active
row proves payment. An interrupted migration remains unready until all required
constraints/markers exist. No reversal of external payments is implied.

## Synthetic contract verification

[Vectors](../protocol/v1/billing-mode-proposal-vectors.json) and
[reference tests](../scripts/test_billing_mode_proposal.py) are executable design
examples, not a runtime implementation or proof of provider readiness. They use
symbolic modes/account IDs and no credentials. The scripts discovery step in CI
runs them. They cover configuration refusal, foreign/mixed/stale events,
identity conflicts, replay conflicts, ambiguity, risk, grace, quota, outage and
atomic restart/rollback. Removing a fence changes the expected vector verdict.

Future integration tests must additionally use two isolated disposable
namespaces with colliding opaque IDs, signed fake-provider requests, complete
and truncated pagination, concurrent bind/reconcile/admission, duplicated and
out-of-order events, refunds with null charge pointers, and process termination
before/after each commit. Assert unchanged TEST behavior, zero live grants from
TEST fixtures, no extra reservation on replay, no grace extension, retained
holds, old-binary refusal and rollback without data loss. Full Rust checks and
disposable PostgreSQL tests are required for those runtime/migration slices;
the current proposal performs no real Stripe lifecycle or live payment test.
