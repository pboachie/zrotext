<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Explicit TEST usage transport

The default-disabled `STRIPE_TEST_METER_FORWARD_ENABLED` worker forwards the
existing finalized device-execution outbox. It additionally requires
`STRIPE_BILLING_TEST_ENABLED` and a dedicated `STRIPE_TEST_METER_SECRET_KEY`
with TEST meter-event write permission. Live-mode credentials are refused.
Installation or migration does not enable forwarding or hosted billing.
No provider/AI charge unit or adjustment approval is created by this transport.

The destination is the fixed Stripe HTTPS meter-events endpoint, using the
existing `2025-07-30.basil` API pin, default `stripe_customer_id`/`value` payload
mapping and the stored event name. Meter configuration must match those names.
Credentials never come from a model, request or tenant routing pointer. The
transport does not follow redirects, use ambient proxies or automatically retry.
A four-second response/body deadline and sixteen-KiB response bound apply.

The existing worker first commits its durable claim and releases transaction
locks before HTTP. Its stable meter identifier is also the idempotency key;
the original reporting timestamp, bound customer and one logical charge remain
unchanged across attempts. One worker tick shares the existing billing concurrency
permit budget. Multiple replicas reuse the outbox customer single-flight fence.
There is no remote call inside admission or the successful radio callback transaction.

Acknowledgement requires the exact identifier, event name, original timestamp,
customer, one-unit value, meter-event object and explicit false livemode.
A foreign or live acknowledgement enters review. It never grants entitlement or
proves asynchronous validation. Malformed/oversized/interrupted responses and
timeouts remain unknown. Existing persisted retry rules keep the original identity,
use bounded backoff for unknown/429/5xx, and stop at seven attempts or the original
23-hour retry window. Permanent rejection and expired reporting/period windows
enter review rather than silently deleting usage or generating a new identifier.

Signed meter-error events and reviewed recovery continue through the existing
billing error/review APIs. Local dashboard totals remain the authoritative local
ledger projection and do not poll Stripe. Existing append-only provider snapshot
comparison uses a separate optional [read-only TEST worker](test-usage-reconciliation.md).
Forwarding itself does not fetch provider aggregates or invoice quantities,
approve corrections, or turn an acknowledgement into a reconciled invoice.
Broader charge-unit and adjustment policy requirements of #673 remain open.
Unknown delivery liability is not refunded here.

Synthetic tests use real loopback HTTPS and a separately trusted synthetic
certificate, plus isolated PostgreSQL finalized delivery/outbox fixtures. They
exercise exact wire identity, ACK substitution, refusal/redirect/timeout/body
bounds, response-loss recovery and one logical finalized charge. They do not call
Stripe, create an account, configure prices, charge money, execute AI/provider
traffic or prove physical/carrier delivery. Actual account permissions, meter
configuration, aggregate/invoice reconciliation and launch approval remain separate.

Primary contracts: [meter event creation](https://docs.stripe.com/api/billing/meter-event/create?api-version=2025-07-30.basil)
and [recording usage](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api).
