# Hosted workflow engineering readiness

**Proposal; not a launch checklist completed by this document.** This is the
engineering dependency contract for [#672](https://github.com/pboachie/zrotext/issues/672).
It adds no paid entitlement, provider, billing worker, content reader, deployment
or activation. Current TEST billing and quota enforcement are groundwork.
Self-hosted software must remain usable without a hosted subscription or a
payment-provider connection.

The existing [canonical roadmap](ROADMAP.md) keeps its capability baseline.
This document decomposes the hosted capability's remaining work; it does not
promote any capability to a later readiness stage. Prices, service economics,
customer information, deployment details, operational evidence and private
sign-offs belong outside this public repository.

## Sequence and ownership

| Stage | Existing owners | Required result before the next stage |
| --- | --- | --- |
| Core source and acceptance | [#622](https://github.com/pboachie/zrotext/issues/622), #623–#632; interface acceptance #605/#612 | Scoped sealed admission/lifecycle and Android execution; QR pairing and trusted custody; conservative retry/delivery evidence; consent/STOP; integrated checks and controlled physical-device acceptance |
| Metering and reconciliation | [#673](https://github.com/pboachie/zrotext/issues/673), usage projection #631, interface summaries #608 | Atomic local billable facts, durable TEST-only outbox and reconciliation; explicit pending/failed/unknown results |
| Exposure reservations | [#674](https://github.com/pboachie/zrotext/issues/674), exact decisions #638, assistant #642, managed AI #644, provider transport #643 | Server-enforced scoped reservations before optional paid work; replay-safe settlement and bounded uncertainty |
| Billing lifecycle | [#675](https://github.com/pboachie/zrotext/issues/675), mode isolation #645 | Invoice/subscription-bound restrictions and recovery; duplicate and unordered events cannot grant unrelated access |
| Owner presentation | [#676](https://github.com/pboachie/zrotext/issues/676), #607/#608/#631 | Authenticated portal handoff and authoritative local usage; TEST, disabled, pending, restricted and unavailable states remain distinct |
| Separate activation | Existing runtime and operator approval boundaries | Accepted core and child evidence plus private support, retention, compliance and rollback sign-offs; explicit authorization for each optional service |

These are dependency stages, not assignments to start monetization ahead of
the core. Do not preempt the core release queue. A restricted source candidate,
merged source, simulator exchange, successful TEST payment or emulator run
does not by itself satisfy the next stage. Child implementation PRs retain
their own issue, branch, tests and review. Reuse the local ledger, quota
transactions, billing lifecycle and customer authority services rather than
creating parallel services.

## Local authority and mode isolation

The local ledger decides usage and entitlement outcomes. External meter
aggregation, a portal redirect, a payment UI success screen, or receipt of an
unverified webhook is not local authorization. Every provider event must
pass the existing signature, identity and current-mode checks before it can
affect local state. TEST and future live namespaces must not share customer,
subscription, invoice, meter-event or replay identities. A mode mismatch is
a refusal, never a fallback.

Hosted billing restrictions apply only to explicitly hosted paid capabilities.
Free/self-hosted mode must neither consult remote payment availability nor
acquire a paid entitlement as a side effect. Generic entitlement checks remain
server-side and tenant-scoped. Portal and usage routes must preserve owner,
observer, API-key and device-bound permissions; navigation never creates a
grant. A malicious foreign identity must produce the same safe result as an
absent identity.

Optional customer-controlled AI, managed AI and provider transport have
independent authority. A hosted subscription cannot grant content-reader or
signing roles, select a different transport, widen a line/conversation scope,
override consent or STOP, extend an approval's expiry, or approve exact message
content. Revocation prevents future work; it cannot erase content already read
by an authorized reader. Provider routing cannot convert an uncertain phone
submission into a second send.

## Child acceptance contracts

| Child | Required synthetic failure cases | Evidence and limits to report |
| --- | --- | --- |
| #673 outbox/reconciliation | Atomic ledger/outbox rollback; duplicate event identity; process restart; network timeout after remote acceptance; delayed aggregation; mismatched mode/account; bounded retry exhaustion | Disposable-database assertions for one durable billable fact and one replay identity; TEST-only transport fixtures; local versus remote disagreement stays visible. No live meter events |
| #674 reservations | Concurrent budget exhaustion; duplicate intent; failed/cancelled work; uncertain external result; expiry and revocation before work; foreign scope; independently disabled AI/provider services | Reservation/settlement transactions over existing authority; original units preserved across replay. Uncertainty does not release exposure and authorize a duplicate. No live model/provider requests |
| #675 lifecycle | Duplicate/unordered webhook events; stale invoice success; unrelated subscription/customer; unresolved invoice; grace/restriction/recovery; TEST/live mismatch; revoked/erased account | Signed synthetic webhook fixtures and disposable-database transitions. A successful event recovers only the matching local obligation; policy decisions are explicit. No payment or account creation |
| #676 portal/UI | Foreign customer/session; missing CSRF/origin; disabled provider; TEST-only mode; pending/held entitlement; portal return without authoritative change; stale/offline/partial usage | Existing owner/API authorization tests plus browser rendering and local ledger projections. Portal link status and local entitlement status are separate. No live portal session or deployment |

All new behavior needs a regression that fails without it. Use bounded workers,
payloads, pagination and retry policies, and state their limits. Database tests
must use isolated disposable schemas or unique identities and clean up. Run
the touched-area checks from [CONTRIBUTING.md](../CONTRIBUTING.md) and the agent
instructions. State omitted checks plainly, including missing physical device,
carrier delivery, PostgreSQL, provider mode or integrated acceptance.

## Closing the engineering gate

Core acceptance, each child contract, mode isolation, server entitlements and
independent optional-feature authority must all have accepted evidence before
activation is considered. Unfinished dependencies remain blocking, even if a
PR exists for a useful partial slice. Keep those limits in the child PR and
public documentation; do not infer readiness from issue or merge counts.

Public source may contain generic contracts, synthetic fixtures and durable
architecture decisions. Private operational sign-offs and dated evidence stay
in the operations repository. Completing this engineering record grants no
permission for purchases, new external accounts, live billing/AI/provider
calls, deployment, release publication or changes to existing safety gates.
