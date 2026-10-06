# Hosted billing portal scenario ledger

This ledger tracks the TEST scenarios named by issue #676 and says, for each,
what is checked today. It is a coverage record, not a claim that hosted billing
is ready. No row below was exercised against Stripe TEST by this ledger.

Status values:

- `source`: a named local test with synthetic fixtures and a mock provider
  covers the behavior. Mock providers do not prove Stripe's real behavior.
- `gap`: no local test was identified. The scenario remains open work.
- `live-unverified`: requires a deliberate run against Stripe TEST with
  synthetic objects and is not run by CI or by the default test commands.

`scripts/test_billing_portal_scenarios.py` fails when a `source` row names a
test or file that no longer exists, so the ledger cannot silently go stale.
Evidence is written `path::test name`.

| Scenario | Status | Evidence |
|---|---|---|
| Card update capability is required before a portal handoff | source | crates/server/src/billing/sessions/tests.rs::selected_portal_requires_all_capabilities_and_exact_active_test_identity |
| Invoice access capability is required before a portal handoff | source | crates/server/src/billing/sessions/tests.rs::selected_portal_requires_all_capabilities_and_exact_active_test_identity |
| Cancellation mode is required and the return does not prove cancellation | source | crates/server/src/billing/sessions/tests.rs::stripe_return_destinations_are_concrete_and_do_not_claim_access |
| Spoofed or non-exact hosted destination is refused | source | crates/server/src/billing/sessions/tests.rs::exact_hosted_url_and_retry_key_are_required |
| Unauthorized or cross-tenant owner cannot reach another tenant's session | source | crates/server/src/billing/sessions/tests.rs::owner_checkout_portal_bind_customer_and_reject_cross_tenant |
| Stale UI response cannot redirect or restore controls | source | web/owner/billing.test.js::older hosted responses cannot redirect or restore controls after session loss |
| Offline Stripe or changed configuration refuses handoff | source | crates/server/src/billing/sessions/tests.rs::portal_offline_or_changed_session_configuration_refuses_handoff |
| Offline handoff allows a deliberate single retry in the UI | source | web/owner/billing.test.js::a current offline handoff permits a deliberate retry without duplicate clicks |
| Retry budget is shared and rejections never reach the provider | source | crates/server/src/billing/sessions/tests.rs::owner_checkout_portal_bind_customer_and_reject_cross_tenant |
| Self-hosted or disabled configuration needs no Stripe and cannot advertise billing | source | crates/server/src/billing/availability.rs::self_hosted_configuration_is_independent_and_cannot_advertise_billing |
| Restricted account keeps billing status, portal and export access | gap | none identified |
| Selected portal configuration shows card update, invoices and cancellation in Stripe TEST | live-unverified | none |
| Real return from Stripe TEST Portal after cancellation | live-unverified | none |
