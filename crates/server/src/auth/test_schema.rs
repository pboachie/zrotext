// SPDX-License-Identifier: AGPL-3.0-only
use tokio_postgres::Client;

/// Apply actual migrations and their required autocommit index preparation.
/// The caller must provide a connection to a unique disposable schema.
pub(crate) async fn apply(db: &Client) {
    apply_selected(db, false).await;
}

/// Preserve the summary tests' explicit index and migration validation gates.
pub(crate) async fn apply_without_summary(db: &Client) {
    apply_selected(db, true).await;
}

// Compile trusted SQL into the test executable; directory names are inventory only.
const MIGRATIONS: &[(&str, &str)] = &[
    (
        "001_foundation.sql",
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
    ),
    (
        "002_auth.sql",
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
    ),
    (
        "003_delivery.sql",
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
    ),
    (
        "004_enrollment.sql",
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
    ),
    (
        "005_verification_outbox.sql",
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
    ),
    (
        "006_usage_metering.sql",
        include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
    ),
    (
        "007_inbound_webhook_foundation.sql",
        include_str!("../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
    ),
    (
        "008_stripe_billing_foundation.sql",
        include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
    ),
    (
        "009_webhook_manual_replay.sql",
        include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
    ),
    (
        "010_billing_test_entitlement.sql",
        include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
    ),
    (
        "011_billing_payment_holds.sql",
        include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
    ),
    (
        "012_auth_abuse_limits.sql",
        include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
    ),
    (
        "013_owner_mfa.sql",
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
    ),
    (
        "014_owner_mfa_failure_budget.sql",
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
    ),
    (
        "015_webhook_kek_commitments.sql",
        include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
    ),
    (
        "016_auth_abuse_atomic.sql",
        include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ),
    (
        "017_billing_device_caps.sql",
        include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
    ),
    (
        "018_sealed_inbound_identity.sql",
        include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
    ),
    (
        "019_line_activation_contract.sql",
        include_str!("../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
    ),
    (
        "020_enrollment_retention_indexes.sql",
        include_str!("../../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
    ),
    (
        "021_billing_payment_grace.sql",
        include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
    ),
    (
        "022_pending_owner_expiry.sql",
        include_str!("../../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
    ),
    (
        "023_billing_py_charge_and_unsupported.sql",
        include_str!(
            "../../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
    ),
    (
        "024_billing_risk_operator_review.sql",
        include_str!("../../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
    ),
    (
        "025_account_recovery.sql",
        include_str!("../../../../deploy/compose/migrations/025_account_recovery.sql"),
    ),
    (
        "026_data_retention.sql",
        include_str!("../../../../deploy/compose/migrations/026_data_retention.sql"),
    ),
    (
        "027_billing_test_config.sql",
        include_str!("../../../../deploy/compose/migrations/027_billing_test_config.sql"),
    ),
    (
        "028_billing_provider_failures.sql",
        include_str!("../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ),
    (
        "029_webhook_dispatch_fairness.sql",
        include_str!("../../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ),
    (
        "030_terminal_dispatch_jobs.sql",
        include_str!("../../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
    ),
    (
        "031_recipient_suppression.sql",
        include_str!("../../../../deploy/compose/migrations/031_recipient_suppression.sql"),
    ),
    (
        "032_line_opt_out_events.sql",
        include_str!("../../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
    ),
    (
        "033_sms_line_binding_scope.sql",
        include_str!("../../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
    ),
    (
        "034_delivery_sweep_index.sql",
        include_str!("../../../../deploy/compose/migrations/034_delivery_sweep_index.sql"),
    ),
    (
        "035_sms_owner_key_ceremony.sql",
        include_str!("../../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
    ),
    (
        "036_owner_opt_out_holds.sql",
        include_str!("../../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
    ),
    (
        "037_sms_line_activation_exchange.sql",
        include_str!("../../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"),
    ),
    (
        "038_owner_opt_out_hold_guards.sql",
        include_str!("../../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
    ),
    (
        "039_inbound_device_clock_offset.sql",
        include_str!("../../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ),
    (
        "040_radio_evidence_index.sql",
        include_str!("../../../../deploy/compose/migrations/040_radio_evidence_index.sql"),
    ),
    (
        "041_device_preconditions.sql",
        include_str!("../../../../deploy/compose/migrations/041_device_preconditions.sql"),
    ),
    (
        "042_sealed_manifest_authority.sql",
        include_str!("../../../../deploy/compose/migrations/042_sealed_manifest_authority.sql"),
    ),
    (
        "043_sealed_candidate_inbound.sql",
        include_str!("../../../../deploy/compose/migrations/043_sealed_candidate_inbound.sql"),
    ),
    (
        "044_sealed_root_role_reservations.sql",
        include_str!("../../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql"),
    ),
    (
        "045_sealed_outbound_queue.sql",
        include_str!("../../../../deploy/compose/migrations/045_sealed_outbound_queue.sql"),
    ),
    (
        "046_sealed_root_ceremonies.sql",
        include_str!("../../../../deploy/compose/migrations/046_sealed_root_ceremonies.sql"),
    ),
    (
        "047_device_network_service.sql",
        include_str!("../../../../deploy/compose/migrations/047_device_network_service.sql"),
    ),
    (
        "048_observer_memberships.sql",
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ),
    (
        "049_owner_queue_probe_indexes.sql",
        include_str!("../../../../deploy/compose/migrations/049_owner_queue_probe_indexes.sql"),
    ),
    (
        "050_message_attempts_recent_index.sql",
        include_str!("../../../../deploy/compose/migrations/050_message_attempts_recent_index.sql"),
    ),
    (
        "051_failover_controller_state.sql",
        include_str!("../../../../deploy/compose/migrations/051_failover_controller_state.sql"),
    ),
    (
        "052_admission_pending_index.sql",
        include_str!("../../../../deploy/compose/migrations/052_admission_pending_index.sql"),
    ),
    (
        "053_observer_seat_invitations.sql",
        include_str!("../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
    ),
    (
        "054_stateless_device_challenges.sql",
        include_str!("../../../../deploy/compose/migrations/054_stateless_device_challenges.sql"),
    ),
    (
        "055_trusted_browser_epoch.sql",
        include_str!("../../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
    ),
    (
        "056_usage_limit_plans.sql",
        include_str!("../../../../deploy/compose/migrations/056_usage_limit_plans.sql"),
    ),
    (
        "057_webhook_history_index.sql",
        include_str!("../../../../deploy/compose/migrations/057_webhook_history_index.sql"),
    ),
    (
        "058_drop_abuse_counters_updated_index.sql",
        include_str!(
            "../../../../deploy/compose/migrations/058_drop_abuse_counters_updated_index.sql"
        ),
    ),
    (
        "059_erasure_fk_indexes.sql",
        include_str!("../../../../deploy/compose/migrations/059_erasure_fk_indexes.sql"),
    ),
    (
        "060_optout_review_indexes.sql",
        include_str!("../../../../deploy/compose/migrations/060_optout_review_indexes.sql"),
    ),
    (
        "061_inbound_events_attempt_fk_index.sql",
        include_str!(
            "../../../../deploy/compose/migrations/061_inbound_events_attempt_fk_index.sql"
        ),
    ),
    (
        "062_pending_recipient_index.sql",
        include_str!("../../../../deploy/compose/migrations/062_pending_recipient_index.sql"),
    ),
    (
        "063_retention_blocked_stamp.sql",
        include_str!("../../../../deploy/compose/migrations/063_retention_blocked_stamp.sql"),
    ),
    (
        "064_owner_conversation_consent.sql",
        include_str!("../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"),
    ),
    (
        "065_conversation_activation.sql",
        include_str!("../../../../deploy/compose/migrations/065_conversation_activation.sql"),
    ),
    (
        "066_conversation_interval_session_index.sql",
        include_str!(
            "../../../../deploy/compose/migrations/066_conversation_interval_session_index.sql"
        ),
    ),
    (
        "067_contacts_consent.sql",
        include_str!("../../../../deploy/compose/migrations/067_contacts_consent.sql"),
    ),
    (
        "068_connector_registration.sql",
        include_str!("../../../../deploy/compose/migrations/068_connector_registration.sql"),
    ),
    (
        "069_sealed_root_custody.sql",
        include_str!("../../../../deploy/compose/migrations/069_sealed_root_custody.sql"),
    ),
    (
        "070_message_summary_metadata.sql",
        include_str!("../../../../deploy/compose/migrations/070_message_summary_metadata.sql"),
    ),
    (
        "071_sealed_grant_authority.sql",
        include_str!("../../../../deploy/compose/migrations/071_sealed_grant_authority.sql"),
    ),
    (
        "072_conversation_confirmation_records.sql",
        include_str!(
            "../../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
        ),
    ),
    (
        "073_collaboration_drafts.sql",
        include_str!("../../../../deploy/compose/migrations/073_collaboration_drafts.sql"),
    ),
    (
        "074_agent_authority.sql",
        include_str!("../../../../deploy/compose/migrations/074_agent_authority.sql"),
    ),
];

async fn apply_selected(db: &Client, skip_summary: bool) {
    for &(file, sql) in MIGRATIONS {
        if skip_summary && file.starts_with("070_") {
            continue;
        }
        prepare_indexes(db, file).await;
        let transaction = file.starts_with("070_");
        if transaction {
            db.batch_execute("BEGIN").await.unwrap();
        }
        let result = db.batch_execute(sql).await;
        if transaction {
            db.batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
        }
        result.unwrap();
    }
}

#[test]
fn agent_auth_schema_includes_every_checked_in_migration() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut files = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(
        files,
        MIGRATIONS
            .iter()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<_>>(),
        "update the compiled migration inventory"
    );
}

/// Mirror the migrator's autocommit preparation on this unique test schema.
/// The exact numbered validation files still run unchanged afterwards.
async fn prepare_indexes(db: &Client, file: &str) {
    let statements: &[&str] = match &file[..3] {
        "034" => &[
            "CREATE INDEX CONCURRENTLY messages_in_flight_updated ON messages(updated_at,id) WHERE state IN ('claimed','submitting','submitted')",
        ],
        "040" => &[
            "CREATE INDEX CONCURRENTLY message_events_attempt_evidence ON message_events(attempt_id,evidence_code)",
        ],
        "049" => &[
            "CREATE INDEX CONCURRENTLY messages_owner_pending_state ON messages(device_id,state,created_at) WHERE state IN ('accepted','queued','claimed')",
            "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state ON messages(device_id,state,created_at) WHERE state IN ('submitting','submitted')",
        ],
        "050" => &[
            "CREATE INDEX CONCURRENTLY message_attempts_device_created ON message_attempts(account_id,device_id,created_at)",
        ],
        "052" => &[
            "CREATE INDEX CONCURRENTLY messages_admission_pending ON messages(account_id,device_id) WHERE state IN ('queued','claimed')",
        ],
        "057" => &[
            "CREATE INDEX CONCURRENTLY webhook_deliveries_history ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)",
        ],
        "058" => &["DROP INDEX CONCURRENTLY auth_abuse_counters_stale"],
        "059" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id)",
            "CREATE INDEX CONCURRENTLY erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
            "CREATE INDEX CONCURRENTLY erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
        ],
        "060" => &[
            "CREATE INDEX CONCURRENTLY recipient_suppressions_review_queue ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) WHERE active AND source IN ('sms_review','sms_unsolicited_review')",
            "CREATE INDEX CONCURRENTLY recipient_suppressions_review_event ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) WHERE source IN ('sms_review','sms_unsolicited_review')",
            "DROP INDEX CONCURRENTLY IF EXISTS recipient_suppressions_active",
        ],
        "061" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_inbound_events_attempt ON inbound_events(account_id,device_id,message_id,attempt_id)",
        ],
        "062" => &[
            "CREATE INDEX CONCURRENTLY messages_pending_recipient ON messages(recipient_e164,account_id) WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL",
        ],
        "066" => &[
            "CREATE INDEX CONCURRENTLY erasure_fk_conversation_interval_session ON conversation_intervals(account_id,initiating_session_id)",
        ],
        "070" => &[
            "CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')",
        ],
        _ => &[],
    };
    for statement in statements {
        db.batch_execute(statement).await.unwrap();
    }
}
