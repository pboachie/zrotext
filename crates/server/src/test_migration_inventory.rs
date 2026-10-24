// SPDX-License-Identifier: AGPL-3.0-only
//! Closed current source inventory and deliberately isolated legacy fixtures.
//!
//! New migrations starting at108 require the actual public installation and
//! ordinary runtime fixture. Replaying them inside arbitrary schemas is invalid.
macro_rules! migration {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!("../../../deploy/compose/migrations/", $name)),
        )
    };
}
const CURRENT: &[(&str, &str)] = &[
    migration!("001_foundation.sql"),
    migration!("002_auth.sql"),
    migration!("003_delivery.sql"),
    migration!("004_enrollment.sql"),
    migration!("005_verification_outbox.sql"),
    migration!("006_usage_metering.sql"),
    migration!("007_inbound_webhook_foundation.sql"),
    migration!("008_stripe_billing_foundation.sql"),
    migration!("009_webhook_manual_replay.sql"),
    migration!("010_billing_test_entitlement.sql"),
    migration!("011_billing_payment_holds.sql"),
    migration!("012_auth_abuse_limits.sql"),
    migration!("013_owner_mfa.sql"),
    migration!("014_owner_mfa_failure_budget.sql"),
    migration!("015_webhook_kek_commitments.sql"),
    migration!("016_auth_abuse_atomic.sql"),
    migration!("017_billing_device_caps.sql"),
    migration!("018_sealed_inbound_identity.sql"),
    migration!("019_line_activation_contract.sql"),
    migration!("020_enrollment_retention_indexes.sql"),
    migration!("021_billing_payment_grace.sql"),
    migration!("022_pending_owner_expiry.sql"),
    migration!("023_billing_py_charge_and_unsupported.sql"),
    migration!("024_billing_risk_operator_review.sql"),
    migration!("025_account_recovery.sql"),
    migration!("026_data_retention.sql"),
    migration!("027_billing_test_config.sql"),
    migration!("028_billing_provider_failures.sql"),
    migration!("029_webhook_dispatch_fairness.sql"),
    migration!("030_terminal_dispatch_jobs.sql"),
    migration!("031_recipient_suppression.sql"),
    migration!("032_line_opt_out_events.sql"),
    migration!("033_sms_line_binding_scope.sql"),
    migration!("034_delivery_sweep_index.sql"),
    migration!("035_sms_owner_key_ceremony.sql"),
    migration!("036_owner_opt_out_holds.sql"),
    migration!("037_sms_line_activation_exchange.sql"),
    migration!("038_owner_opt_out_hold_guards.sql"),
    migration!("039_inbound_device_clock_offset.sql"),
    migration!("040_radio_evidence_index.sql"),
    migration!("041_device_preconditions.sql"),
    migration!("042_sealed_manifest_authority.sql"),
    migration!("043_sealed_candidate_inbound.sql"),
    migration!("044_sealed_root_role_reservations.sql"),
    migration!("045_sealed_outbound_queue.sql"),
    migration!("046_sealed_root_ceremonies.sql"),
    migration!("047_device_network_service.sql"),
    migration!("048_observer_memberships.sql"),
    migration!("049_owner_queue_probe_indexes.sql"),
    migration!("050_message_attempts_recent_index.sql"),
    migration!("051_failover_controller_state.sql"),
    migration!("052_admission_pending_index.sql"),
    migration!("053_observer_seat_invitations.sql"),
    migration!("054_stateless_device_challenges.sql"),
    migration!("055_trusted_browser_epoch.sql"),
    migration!("056_usage_limit_plans.sql"),
    migration!("057_webhook_history_index.sql"),
    migration!("058_drop_abuse_counters_updated_index.sql"),
    migration!("059_erasure_fk_indexes.sql"),
    migration!("060_optout_review_indexes.sql"),
    migration!("061_inbound_events_attempt_fk_index.sql"),
    migration!("062_pending_recipient_index.sql"),
    migration!("063_retention_blocked_stamp.sql"),
    migration!("064_owner_conversation_consent.sql"),
    migration!("065_conversation_activation.sql"),
    migration!("066_conversation_interval_session_index.sql"),
    migration!("067_contacts_consent.sql"),
    migration!("068_connector_registration.sql"),
    migration!("069_sealed_root_custody.sql"),
    migration!("070_message_summary_metadata.sql"),
    migration!("071_sealed_grant_authority.sql"),
    migration!("072_conversation_confirmation_records.sql"),
    migration!("073_collaboration_drafts.sql"),
    migration!("074_agent_authority.sql"),
    migration!("075_workflow_context.sql"),
    migration!("076_workflow_decisions.sql"),
    migration!("077_encrypted_schedule.sql"),
    migration!("078_test_billable_usage.sql"),
    migration!("079_workflow_integration_authority.sql"),
    migration!("080_test_exposure_reservations.sql"),
    migration!("081_invoice_bound_test_billing.sql"),
    migration!("082_conversation_execution_records.sql"),
    migration!("083_encrypted_template_versions.sql"),
    migration!("084_sealed_event_deliveries.sql"),
    migration!("085_customer_routine_calls.sql"),
    migration!("086_sealed_line_key_registration.sql"),
    migration!("087_sealed_line_activation_exchanges.sql"),
    migration!("088_original_reply_readers.sql"),
    migration!("089_original_routine_sources.sql"),
    migration!("090_invoice_usage_observations.sql"),
    migration!("091_original_reply_origin_binding.sql"),
    migration!("092_provider_send_attempts.sql"),
    migration!("093_owner_opening_capacity.sql"),
    migration!("094_line_activation_protocol_version.sql"),
    migration!("095_device_session_line_activation_version.sql"),
    migration!("096_line_activation_v2_exchanges.sql"),
    migration!("097_owner_android_proposals.sql"),
    migration!("098_line_labels_and_not_ready_policy.sql"),
    migration!("099_line_readiness_observations.sql"),
    migration!("100_payload_profile_account_anchors.sql"),
    migration!("101_parent_account_mirrors.sql"),
    migration!("102_review_workspace_persistence.sql"),
    migration!("103_user_membership_freshness.sql"),
    migration!("104_review_root_access.sql"),
    migration!("105_device_pairing_bindings.sql"),
    migration!("106_hosted_runtime.sql"),
    migration!("107_registration_browser_intents.sql"),
    migration!("108_payload_profile_writer_fences.sql"),
    migration!("109_original_sealed_activation_receipts.sql"),
    migration!("110_payload_profile_elections.sql"),
    migration!("111_payload_profile_selection_refresh.sql"),
    migration!("112_payload_profile_manifest_successors.sql"),
    migration!("113_conversation_profile03_intervals.sql"),
    migration!("114_conversation_reviewed_sends03.sql"),
    migration!("115_conversation_profile03_grants.sql"),
    migration!("116_hosted_native_transaction_identity.sql"),
];

fn assert_current_inventory() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut actual = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .collect::<Vec<_>>();
    actual.sort();
    assert_eq!(
        actual.len(),
        CURRENT.len(),
        "evolve the closed current inventory for added/removed migrations"
    );
    for (path, (name, sql)) in actual.iter().zip(CURRENT) {
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            *name,
            "unknown or reordered numbered migration"
        );
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            *sql,
            "compiled current migration bytes differ from source"
        );
    }
}

pub(crate) fn assert_legacy107_fixture(embedded: &[(&str, &str)]) {
    assert_current_inventory();
    let numbered = embedded
        .iter()
        .filter(|(name, _)| !name.starts_with("../migration-candidates/"))
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(
        numbered.len(),
        107,
        "legacy fixture must retain its exact closed107 boundary"
    );
    assert_eq!(
        numbered.as_slice(),
        &CURRENT[..107],
        "legacy fixture names or SQL differ from the actual current prefix"
    );
}

#[test]
fn current_numbered_inventory_covers_exact_source_names_and_bytes() {
    assert_current_inventory();
}
