use super::*;

// Keep the admission fixtures on the complete, reviewed schema. SQL is
// embedded at build time so tests never execute files discovered at runtime.
const TEST_MIGRATIONS: [(&str, &str); 79] = [
    (
        "001_foundation.sql",
        include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
    ),
    (
        "002_auth.sql",
        include_str!("../../../deploy/compose/migrations/002_auth.sql"),
    ),
    (
        "003_delivery.sql",
        include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
    ),
    (
        "004_enrollment.sql",
        include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
    ),
    (
        "005_verification_outbox.sql",
        include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
    ),
    (
        "006_usage_metering.sql",
        include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
    ),
    (
        "007_inbound_webhook_foundation.sql",
        include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
    ),
    (
        "008_stripe_billing_foundation.sql",
        include_str!("../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
    ),
    (
        "009_webhook_manual_replay.sql",
        include_str!("../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
    ),
    (
        "010_billing_test_entitlement.sql",
        include_str!("../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
    ),
    (
        "011_billing_payment_holds.sql",
        include_str!("../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
    ),
    (
        "012_auth_abuse_limits.sql",
        include_str!("../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
    ),
    (
        "013_owner_mfa.sql",
        include_str!("../../../deploy/compose/migrations/013_owner_mfa.sql"),
    ),
    (
        "014_owner_mfa_failure_budget.sql",
        include_str!("../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
    ),
    (
        "015_webhook_kek_commitments.sql",
        include_str!("../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
    ),
    (
        "016_auth_abuse_atomic.sql",
        include_str!("../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
    ),
    (
        "017_billing_device_caps.sql",
        include_str!("../../../deploy/compose/migrations/017_billing_device_caps.sql"),
    ),
    (
        "018_sealed_inbound_identity.sql",
        include_str!("../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
    ),
    (
        "019_line_activation_contract.sql",
        include_str!("../../../deploy/compose/migrations/019_line_activation_contract.sql"),
    ),
    (
        "020_enrollment_retention_indexes.sql",
        include_str!("../../../deploy/compose/migrations/020_enrollment_retention_indexes.sql"),
    ),
    (
        "021_billing_payment_grace.sql",
        include_str!("../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
    ),
    (
        "022_pending_owner_expiry.sql",
        include_str!("../../../deploy/compose/migrations/022_pending_owner_expiry.sql"),
    ),
    (
        "023_billing_py_charge_and_unsupported.sql",
        include_str!(
            "../../../deploy/compose/migrations/023_billing_py_charge_and_unsupported.sql"
        ),
    ),
    (
        "024_billing_risk_operator_review.sql",
        include_str!("../../../deploy/compose/migrations/024_billing_risk_operator_review.sql"),
    ),
    (
        "025_account_recovery.sql",
        include_str!("../../../deploy/compose/migrations/025_account_recovery.sql"),
    ),
    (
        "026_data_retention.sql",
        include_str!("../../../deploy/compose/migrations/026_data_retention.sql"),
    ),
    (
        "027_billing_test_config.sql",
        include_str!("../../../deploy/compose/migrations/027_billing_test_config.sql"),
    ),
    (
        "028_billing_provider_failures.sql",
        include_str!("../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ),
    (
        "029_webhook_dispatch_fairness.sql",
        include_str!("../../../deploy/compose/migrations/029_webhook_dispatch_fairness.sql"),
    ),
    (
        "030_terminal_dispatch_jobs.sql",
        include_str!("../../../deploy/compose/migrations/030_terminal_dispatch_jobs.sql"),
    ),
    (
        "031_recipient_suppression.sql",
        include_str!("../../../deploy/compose/migrations/031_recipient_suppression.sql"),
    ),
    (
        "032_line_opt_out_events.sql",
        include_str!("../../../deploy/compose/migrations/032_line_opt_out_events.sql"),
    ),
    (
        "033_sms_line_binding_scope.sql",
        include_str!("../../../deploy/compose/migrations/033_sms_line_binding_scope.sql"),
    ),
    (
        "034_delivery_sweep_index.sql",
        include_str!("../../../deploy/compose/migrations/034_delivery_sweep_index.sql"),
    ),
    (
        "035_sms_owner_key_ceremony.sql",
        include_str!("../../../deploy/compose/migrations/035_sms_owner_key_ceremony.sql"),
    ),
    (
        "036_owner_opt_out_holds.sql",
        include_str!("../../../deploy/compose/migrations/036_owner_opt_out_holds.sql"),
    ),
    (
        "037_sms_line_activation_exchange.sql",
        include_str!("../../../deploy/compose/migrations/037_sms_line_activation_exchange.sql"),
    ),
    (
        "038_owner_opt_out_hold_guards.sql",
        include_str!("../../../deploy/compose/migrations/038_owner_opt_out_hold_guards.sql"),
    ),
    (
        "039_inbound_device_clock_offset.sql",
        include_str!("../../../deploy/compose/migrations/039_inbound_device_clock_offset.sql"),
    ),
    (
        "040_radio_evidence_index.sql",
        include_str!("../../../deploy/compose/migrations/040_radio_evidence_index.sql"),
    ),
    (
        "041_device_preconditions.sql",
        include_str!("../../../deploy/compose/migrations/041_device_preconditions.sql"),
    ),
    (
        "042_sealed_manifest_authority.sql",
        include_str!("../../../deploy/compose/migrations/042_sealed_manifest_authority.sql"),
    ),
    (
        "043_sealed_candidate_inbound.sql",
        include_str!("../../../deploy/compose/migrations/043_sealed_candidate_inbound.sql"),
    ),
    (
        "044_sealed_root_role_reservations.sql",
        include_str!("../../../deploy/compose/migrations/044_sealed_root_role_reservations.sql"),
    ),
    (
        "045_sealed_outbound_queue.sql",
        include_str!("../../../deploy/compose/migrations/045_sealed_outbound_queue.sql"),
    ),
    (
        "046_sealed_root_ceremonies.sql",
        include_str!("../../../deploy/compose/migrations/046_sealed_root_ceremonies.sql"),
    ),
    (
        "047_device_network_service.sql",
        include_str!("../../../deploy/compose/migrations/047_device_network_service.sql"),
    ),
    (
        "048_observer_memberships.sql",
        include_str!("../../../deploy/compose/migrations/048_observer_memberships.sql"),
    ),
    (
        "049_owner_queue_probe_indexes.sql",
        include_str!("../../../deploy/compose/migrations/049_owner_queue_probe_indexes.sql"),
    ),
    (
        "050_message_attempts_recent_index.sql",
        include_str!("../../../deploy/compose/migrations/050_message_attempts_recent_index.sql"),
    ),
    (
        "051_failover_controller_state.sql",
        include_str!("../../../deploy/compose/migrations/051_failover_controller_state.sql"),
    ),
    (
        "052_admission_pending_index.sql",
        include_str!("../../../deploy/compose/migrations/052_admission_pending_index.sql"),
    ),
    (
        "053_observer_seat_invitations.sql",
        include_str!("../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
    ),
    (
        "054_stateless_device_challenges.sql",
        include_str!("../../../deploy/compose/migrations/054_stateless_device_challenges.sql"),
    ),
    (
        "055_trusted_browser_epoch.sql",
        include_str!("../../../deploy/compose/migrations/055_trusted_browser_epoch.sql"),
    ),
    (
        "056_usage_limit_plans.sql",
        include_str!("../../../deploy/compose/migrations/056_usage_limit_plans.sql"),
    ),
    (
        "057_webhook_history_index.sql",
        include_str!("../../../deploy/compose/migrations/057_webhook_history_index.sql"),
    ),
    (
        "058_drop_abuse_counters_updated_index.sql",
        include_str!(
            "../../../deploy/compose/migrations/058_drop_abuse_counters_updated_index.sql"
        ),
    ),
    (
        "059_erasure_fk_indexes.sql",
        include_str!("../../../deploy/compose/migrations/059_erasure_fk_indexes.sql"),
    ),
    (
        "060_optout_review_indexes.sql",
        include_str!("../../../deploy/compose/migrations/060_optout_review_indexes.sql"),
    ),
    (
        "061_inbound_events_attempt_fk_index.sql",
        include_str!("../../../deploy/compose/migrations/061_inbound_events_attempt_fk_index.sql"),
    ),
    (
        "062_pending_recipient_index.sql",
        include_str!("../../../deploy/compose/migrations/062_pending_recipient_index.sql"),
    ),
    (
        "063_retention_blocked_stamp.sql",
        include_str!("../../../deploy/compose/migrations/063_retention_blocked_stamp.sql"),
    ),
    (
        "064_owner_conversation_consent.sql",
        include_str!("../../../deploy/compose/migrations/064_owner_conversation_consent.sql"),
    ),
    (
        "065_conversation_activation.sql",
        include_str!("../../../deploy/compose/migrations/065_conversation_activation.sql"),
    ),
    (
        "066_conversation_interval_session_index.sql",
        include_str!(
            "../../../deploy/compose/migrations/066_conversation_interval_session_index.sql"
        ),
    ),
    (
        "067_contacts_consent.sql",
        include_str!("../../../deploy/compose/migrations/067_contacts_consent.sql"),
    ),
    (
        "068_connector_registration.sql",
        include_str!("../../../deploy/compose/migrations/068_connector_registration.sql"),
    ),
    (
        "069_sealed_root_custody.sql",
        include_str!("../../../deploy/compose/migrations/069_sealed_root_custody.sql"),
    ),
    (
        "070_message_summary_metadata.sql",
        include_str!("../../../deploy/compose/migrations/070_message_summary_metadata.sql"),
    ),
    (
        "071_sealed_grant_authority.sql",
        include_str!("../../../deploy/compose/migrations/071_sealed_grant_authority.sql"),
    ),
    (
        "072_conversation_confirmation_records.sql",
        include_str!(
            "../../../deploy/compose/migrations/072_conversation_confirmation_records.sql"
        ),
    ),
    (
        "073_collaboration_drafts.sql",
        include_str!("../../../deploy/compose/migrations/073_collaboration_drafts.sql"),
    ),
    (
        "074_agent_authority.sql",
        include_str!("../../../deploy/compose/migrations/074_agent_authority.sql"),
    ),
    (
        "075_workflow_context.sql",
        include_str!("../../../deploy/compose/migrations/075_workflow_context.sql"),
    ),
    (
        "076_workflow_decisions.sql",
        include_str!("../../../deploy/compose/migrations/076_workflow_decisions.sql"),
    ),
    (
        "077_encrypted_schedule.sql",
        include_str!("../../../deploy/compose/migrations/077_encrypted_schedule.sql"),
    ),
    (
        "078_test_billable_usage.sql",
        include_str!("../../../deploy/compose/migrations/078_test_billable_usage.sql"),
    ),
    (
        "079_workflow_integration_authority.sql",
        include_str!("../../../deploy/compose/migrations/079_workflow_integration_authority.sql"),
    ),
];

/// Applies every numbered migration in order. Shared by the PostgreSQL-backed
/// test modules so each one runs against the complete reviewed schema.
pub(crate) async fn apply_test_migrations(client: &Client) {
    for (name, migration) in TEST_MIGRATIONS {
        if name == "070_message_summary_metadata.sql" {
            client.batch_execute("CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')").await.unwrap();
            client.batch_execute("BEGIN").await.unwrap();
            let result = client.batch_execute(migration).await;
            client
                .batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
            result.unwrap();
            continue;
        }
        if name == "034_delivery_sweep_index.sql" {
            // Mirror the migrator's autocommit preparation before the
            // numbered, checksummed validation file.
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                     ON messages(updated_at,id) \
                     WHERE state IN ('claimed','submitting','submitted')",
                )
                .await
                .unwrap();
        }
        if name == "040_radio_evidence_index.sql" {
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY message_events_attempt_evidence \
                 ON message_events(attempt_id,evidence_code)",
                )
                .await
                .unwrap();
        }
        if name == "052_admission_pending_index.sql" {
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_admission_pending \
                     ON messages(account_id,device_id) \
                     WHERE state IN ('queued','claimed')",
                )
                .await
                .unwrap();
        }
        if name == "058_drop_abuse_counters_updated_index.sql" {
            client
                .batch_execute("DROP INDEX IF EXISTS auth_abuse_counters_stale")
                .await
                .unwrap();
        }
        if name == "059_erasure_fk_indexes.sql" {
            client
                .batch_execute(
                    "CREATE INDEX erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id); CREATE INDEX erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id); CREATE INDEX erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id); CREATE INDEX erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL; CREATE INDEX erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
                )
                .await
                .unwrap();
        }
        if name == "060_optout_review_indexes.sql" {
            client
                .batch_execute(
                    "CREATE INDEX recipient_suppressions_review_queue ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) WHERE active AND source IN ('sms_review','sms_unsolicited_review')"
                )
                .await
                .unwrap();
            client
                .batch_execute(
                    "CREATE INDEX recipient_suppressions_review_event ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) WHERE source IN ('sms_review','sms_unsolicited_review')"
                )
                .await
                .unwrap();
            client
                .batch_execute("DROP INDEX IF EXISTS recipient_suppressions_active")
                .await
                .unwrap();
        }
        if name == "061_inbound_events_attempt_fk_index.sql" {
            client.batch_execute("CREATE INDEX erasure_fk_inbound_events_attempt ON inbound_events(account_id,device_id,message_id,attempt_id)")
                .await
                .unwrap();
        }
        if name == "062_pending_recipient_index.sql" {
            client.batch_execute("CREATE INDEX messages_pending_recipient ON messages(recipient_e164,account_id) WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL")
                .await
                .unwrap();
        }
        if name == "066_conversation_interval_session_index.sql" {
            client.batch_execute("CREATE INDEX erasure_fk_conversation_interval_session ON conversation_intervals(account_id,initiating_session_id)")
                .await
                .unwrap();
        }
        if name == "049_owner_queue_probe_indexes.sql" {
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_owner_pending_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('accepted','queued','claimed')",
                )
                .await
                .unwrap();
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('submitting','submitted')",
                )
                .await
                .unwrap();
        }
        if name == "057_webhook_history_index.sql" {
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY webhook_deliveries_history \
                     ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)",
                )
                .await
                .unwrap();
        }
        if name == "050_message_attempts_recent_index.sql" {
            client
                .batch_execute(
                    "CREATE INDEX CONCURRENTLY message_attempts_device_created \
                 ON message_attempts(account_id,device_id,created_at)",
                )
                .await
                .unwrap();
        }
        client.batch_execute(migration).await.unwrap();
    }
}

#[test]
fn admission_fixture_tracks_numbered_migrations() {
    let migrations_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut discovered = std::fs::read_dir(migrations_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    discovered.sort();
    let embedded = TEST_MIGRATIONS
        .iter()
        .filter(|(name, _)| !name.starts_with("../migration-candidates/"))
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(discovered, embedded, "update the embedded migration list");
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn radio_timestamp_rejection_preserves_state_and_accepts_offline_evidence() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("radio_time_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    store
        .accept(NewMessage {
            account_id,
            device_id,
            client_message_id: message_id,
            idempotency_key: "radio-time",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic regression",
            expires_at_ms: now_ms() + 60_000,
        })
        .await
        .unwrap();
    let session = store
        .connect_session(account_id, device_id, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let attempt_id = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, attempt_id)
        .await
        .unwrap();
    let event = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id,
        device_id,
        message_id,
        attempt_id,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: now_ms(),
        segment_index: None,
        segment_count: None,
    };
    for observed_at_ms in [
        i64::MIN,
        0,
        1,
        now_ms() - 600_000,
        now_ms() + 600_000,
        i64::MAX,
    ] {
        assert!(
            matches!(
                store
                    .record_radio_event(RadioEvent {
                        observed_at_ms,
                        ..event
                    })
                    .await,
                Err(StoreError::InvalidInput)
            ),
            "timestamp {observed_at_ms}"
        );
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Claimed
    );
    let events: i64 = client
        .query_one(
            "SELECT count(*) FROM message_events WHERE attempt_id=$1",
            &[&attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 0);

    // A long-offline phone is bounded by its original attempt, not today's date.
    client
        .execute(
            "UPDATE message_attempts SET created_at=now()-interval '30 days' WHERE id=$1",
            &[&attempt_id],
        )
        .await
        .unwrap();
    let offline = RadioEvent {
        observed_at_ms: now_ms() - 29 * 24 * 60 * 60 * 1000,
        ..event
    };
    assert_eq!(
        DeliveryStore::new(&mut client)
            .record_radio_event(offline)
            .await
            .unwrap(),
        MessageState::Submitting
    );
    assert_eq!(
        DeliveryStore::new(&mut client)
            .record_radio_event(offline)
            .await
            .unwrap(),
        MessageState::Submitting
    );
    let events: i64 = client
        .query_one(
            "SELECT count(*) FROM message_events WHERE attempt_id=$1",
            &[&attempt_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(events, 1, "exact replay must not create another event");
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[test]
fn radio_timestamp_window_includes_both_clock_skew_boundaries() {
    let now = 1_700_000_000_000;
    let created = now - 60_000;
    let lower = created - RADIO_CLOCK_SKEW_MS;
    let upper = now + RADIO_CLOCK_SKEW_MS;
    for timestamp in [lower, created, now, upper] {
        assert!(validate_radio_timestamp(timestamp, created, now).is_ok());
    }
    for timestamp in [i64::MIN, 0, lower - 1, upper + 1, i64::MAX] {
        assert!(matches!(
            validate_radio_timestamp(timestamp, created, now),
            Err(StoreError::InvalidInput)
        ));
    }
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn released_attempt_cannot_change_a_new_grant() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("stale_attempt_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    store
        .accept(NewMessage {
            account_id,
            device_id,
            client_message_id: message_id,
            idempotency_key: "stale-attempt",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic regression",
            expires_at_ms: now_ms() + 60_000,
        })
        .await
        .unwrap();
    let session = store
        .connect_session(account_id, device_id, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let attempt_id = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, attempt_id)
        .await
        .unwrap();
    let event = |evidence| RadioEvent {
        event_id: Uuid::new_v4(),
        account_id,
        device_id,
        message_id,
        attempt_id,
        evidence,
        observed_at_ms: now_ms(),
        segment_index: None,
        segment_count: None,
    };
    let intent = event(Evidence::DurableSubmitIntent);
    store.record_radio_event(intent).await.unwrap();
    let proof = event(Evidence::ProvenNoSubmit);
    store.record_radio_event(proof).await.unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let fresh_attempt = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, fresh_attempt)
        .await
        .unwrap();
    // Exact receipts remain replayable without applying their state again.
    assert_eq!(
        store.record_radio_event(intent).await.unwrap(),
        MessageState::Submitting
    );
    assert_eq!(
        store.record_radio_event(proof).await.unwrap(),
        MessageState::Queued
    );
    for evidence in [Evidence::DurableSubmitIntent, Evidence::CallbackConflict] {
        assert!(matches!(
            store.record_radio_event(event(evidence)).await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Claimed
    );
    store
        .record_radio_event(RadioEvent {
            attempt_id: fresh_attempt,
            ..event(Evidence::DurableSubmitIntent)
        })
        .await
        .unwrap();
    for evidence in [Evidence::SentCallbackOk, Evidence::SentCallbackFailed] {
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    segment_index: Some(0),
                    segment_count: Some(1),
                    ..event(evidence)
                })
                .await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Submitting
    );
    store
        .record_radio_event(RadioEvent {
            attempt_id: fresh_attempt,
            segment_index: Some(0),
            segment_count: Some(1),
            ..event(Evidence::SentCallbackOk)
        })
        .await
        .unwrap();
    for evidence in [Evidence::DeliveryCallbackOk, Evidence::DeliveryTimeout] {
        assert!(matches!(
            store.record_radio_event(event(evidence)).await,
            Err(StoreError::StaleFence)
        ));
    }
    assert_eq!(
        store
            .status(account_id, message_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        MessageState::Submitted
    );
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn expired_message_replay_keeps_identity_without_new_dispatch() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("expired_replay_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    let expiry = now_ms() + 5_000;
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "expired-replay",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: expiry,
    };
    assert!(
        DeliveryStore::new(&mut client)
            .accept(input())
            .await
            .unwrap()
            .created
    );
    // Admission judges expiry by the wall clock (`now_ms`), which can step
    // backward under NTP or VM time sync while a monotonic sleep runs. Wait on
    // that same clock, with a margin for a step between here and the expired
    // admissions below, instead of trusting the sleep duration.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while now_ms() <= expiry + 1_000 {
        assert!(
            std::time::Instant::now() < deadline,
            "wall clock did not pass message expiry"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let replay = DeliveryStore::new(&mut client)
        .accept(input())
        .await
        .unwrap();
    assert_eq!(replay.message_id, message);
    assert!(!replay.created);
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                synthetic_payload: b"changed",
                ..input()
            })
            .await,
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                client_message_id: Uuid::new_v4(),
                idempotency_key: "expired-new",
                ..input()
            })
            .await,
        Err(StoreError::InvalidInput)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept(NewMessage {
                idempotency_key: "expired-new-same-id",
                ..input()
            })
            .await,
        Err(StoreError::InvalidInput)
    ));
    for table in ["messages", "dispatch_jobs", "idempotency_keys"] {
        let count: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "{table} changed after expired retry");
    }
    client.execute(
            "UPDATE idempotency_keys SET expires_at=now()-interval '1 second' WHERE account_id=$1 AND key='expired-replay'",
            &[&account],
        ).await.unwrap();
    let replacement_id = Uuid::new_v4();
    let replacement = DeliveryStore::with_idempotency_days(&mut client, 1)
        .accept(NewMessage {
            client_message_id: replacement_id,
            synthetic_payload: b"new request after key expiry",
            expires_at_ms: now_ms() + 60_000,
            ..input()
        })
        .await
        .unwrap();
    assert!(replacement.created);
    assert_eq!(replacement.message_id, replacement_id);
    let row = client.query_one(
            "SELECT message_id,expires_at>now()+interval '23 hours' AND expires_at<now()+interval '25 hours' \
             FROM idempotency_keys WHERE account_id=$1 AND key='expired-replay'",
            &[&account],
        ).await.unwrap();
    assert_eq!(row.get::<_, Uuid>(0), replacement_id);
    assert!(row.get::<_, bool>(1));
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn exact_alpha_replay_survives_customer_binding_without_new_work() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("alpha_replay_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    let expiry = now_ms() + 300_000;
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "before-binding",
        recipient_e164: "+15551234567",
        synthetic_payload: b"fixture",
        expires_at_ms: expiry,
    };
    let first = DeliveryStore::new(&mut client)
        .accept_alpha(input(), false)
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.message_id, alpha_message_id(account, message));
    client
        .execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) \
                 VALUES($1,'cus_alphareplayfixture')",
            &[&account],
        )
        .await
        .unwrap();
    for billing_enabled in [false, true] {
        let replay = DeliveryStore::new(&mut client)
            .accept_alpha(input(), billing_enabled)
            .await
            .unwrap();
        assert_eq!(replay.message_id, first.message_id);
        assert!(!replay.created);
    }
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    synthetic_payload: b"changed",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    idempotency_key: "alternate-key",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::MessageIdConflict | StoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        DeliveryStore::new(&mut client)
            .accept_alpha(
                NewMessage {
                    client_message_id: Uuid::new_v4(),
                    idempotency_key: "new-work",
                    ..input()
                },
                false,
            )
            .await,
        Err(StoreError::QuotaNotConfigured)
    ));
    for table in ["messages", "dispatch_jobs", "idempotency_keys"] {
        let count: i64 = client
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE account_id=$1"),
                &[&account],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 1, "{table} count changed after replay");
    }
    let reservations: i64 = client
        .query_one(
            "SELECT count(*) FROM usage_ledger WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reservations, 0);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn parallel_acceptance_respects_pending_queue_capacity() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("delivery_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    // Apply the complete numbered schema, including accept-time metering.
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
            &[&device, &account],
        )
        .await
        .unwrap();

    // Independent connections represent competing API instances. Only one
    // account-row lock holder can count and insert at a time.
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..32 {
        let url = url.clone();
        let schema = schema.clone();
        tasks.spawn(async move {
            let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
            tokio::spawn(async move { connection.await.unwrap() });
            client
                .batch_execute(&format!("SET search_path TO {schema}"))
                .await
                .unwrap();
            let id = Uuid::new_v4();
            let key = format!("parallel-{index}");
            let result = DeliveryStore::new(&mut client)
                .accept(NewMessage {
                    account_id: account,
                    client_message_id: id,
                    device_id: device,
                    idempotency_key: &key,
                    recipient_e164: "+15551234567",
                    synthetic_payload: b"test only",
                    expires_at_ms: now_ms() + 300_000,
                })
                .await;
            match result {
                Ok(outcome) => {
                    assert!(outcome.created);
                    Some((id, key))
                }
                Err(StoreError::QueueFull) => None,
                Err(error) => panic!("unexpected admission result: {error}"),
            }
        });
    }
    let mut accepted = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Some(item) = result.unwrap() {
            accepted.push(item);
        }
    }
    assert_eq!(accepted.len(), MAX_PENDING_PER_DEVICE as usize);
    let rows: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, MAX_PENDING_PER_DEVICE);
    // An exact replay still succeeds while the queue is full.
    let (id, key) = &accepted[0];
    let (mut replay_client, replay_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { replay_connection.await.unwrap() });
    replay_client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    // The original request deadline is read from its committed row so
    // the digest is identical to the first acceptance.
    let expiry: i64 = replay_client
        .query_one(
            "SELECT (extract(epoch FROM expires_at)*1000)::bigint FROM messages WHERE id=$1",
            &[id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !DeliveryStore::new(&mut replay_client)
            .accept(NewMessage {
                account_id: account,
                client_message_id: *id,
                device_id: device,
                idempotency_key: key,
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap()
            .created
    );

    // Fill other phones to the tenant-wide limit. A new device cannot
    // bypass account admission, and cancellation returns one slot.
    for ordinal in 0..7 {
        let another_device = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
                &[&another_device, &account],
            )
            .await
            .unwrap();
        for slot in 0..MAX_PENDING_PER_DEVICE {
            let key = format!("account-{ordinal}-{slot}");
            DeliveryStore::new(&mut replay_client)
                .accept(NewMessage {
                    account_id: account,
                    client_message_id: Uuid::new_v4(),
                    device_id: another_device,
                    idempotency_key: &key,
                    recipient_e164: "+15551234567",
                    synthetic_payload: b"test only",
                    expires_at_ms: now_ms() + 300_000,
                })
                .await
                .unwrap();
        }
    }
    let extra_device = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'queue phone')",
            &[&extra_device, &account],
        )
        .await
        .unwrap();
    let extra_id = Uuid::new_v4();
    let extra = || NewMessage {
        account_id: account,
        client_message_id: extra_id,
        device_id: extra_device,
        idempotency_key: "account-full",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: now_ms() + 300_000,
    };
    assert!(matches!(
        DeliveryStore::new(&mut replay_client).accept(extra()).await,
        Err(StoreError::QueueFull)
    ));
    assert!(
        DeliveryStore::new(&mut replay_client)
            .cancel(account, *id)
            .await
            .unwrap()
    );
    assert!(
        DeliveryStore::new(&mut replay_client)
            .accept(extra())
            .await
            .unwrap()
            .created
    );
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn postgres_fences_unknown_and_tenant_idempotency() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("delivery_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;

    let account = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let device = Uuid::new_v4();
    for id in [account, other_account] {
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
            .await
            .unwrap();
    }
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE deployment_authority SET dispatch_enabled=TRUE WHERE singleton=TRUE",
            &[],
        )
        .await
        .unwrap();

    let message = Uuid::new_v4();
    let expiry = now_ms() + 3_600_000;
    let input = || NewMessage {
        account_id: account,
        client_message_id: message,
        device_id: device,
        idempotency_key: "one",
        recipient_e164: "+15551234567",
        synthetic_payload: b"test only",
        expires_at_ms: expiry,
    };
    {
        let mut store = DeliveryStore::new(&mut client);
        assert!(store.accept(input()).await.unwrap().created);
        assert!(!store.accept(input()).await.unwrap().created);
        assert_eq!(
            store.status(account, message).await.unwrap().unwrap().state,
            MessageState::Queued
        );
        assert!(
            store
                .status(other_account, message)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .accept(NewMessage {
                    synthetic_payload: b"changed",
                    ..input()
                })
                .await,
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(matches!(
            store
                .accept(NewMessage {
                    idempotency_key: "different-key",
                    ..input()
                })
                .await,
            Err(StoreError::MessageIdConflict)
        ));
        assert!(matches!(
            store
                .connect_session(other_account, device, "a", "hub", 60)
                .await,
            Err(StoreError::NotFound)
        ));
        let session = store
            .connect_session(account, device, "a", "hub", 60)
            .await
            .unwrap();
        let (mut blocker, blocker_connection) =
            tokio_postgres::connect(&url, tokio_postgres::NoTls)
                .await
                .unwrap();
        tokio::spawn(async move { blocker_connection.await.unwrap() });
        blocker
            .batch_execute(&format!("SET search_path TO {schema}"))
            .await
            .unwrap();
        let locked = blocker.transaction().await.unwrap();
        locked
            .query_one(
                "SELECT message_id FROM dispatch_jobs WHERE message_id=$1 FOR UPDATE",
                &[&message],
            )
            .await
            .unwrap();
        assert!(store.claim_due("blocked-worker").await.unwrap().is_none());
        locked.rollback().await.unwrap();
        let claim = store.claim_due("worker-a").await.unwrap().unwrap();
        assert_eq!(claim.message_id, message);
        let attempt = Uuid::new_v4();
        let grant = store.issue_grant(&claim, &session, attempt).await.unwrap();
        let payload = store
            .synthetic_payload_for_grant(&grant, &session)
            .await
            .unwrap();
        assert_eq!(payload.recipient_e164, "+15551234567");
        assert_eq!(payload.body, "test only");
        store
            .confirm_synthetic_grant(&grant, &session)
            .await
            .unwrap();
        let event = |evidence, event_id| RadioEvent {
            event_id,
            account_id: account,
            device_id: device,
            message_id: message,
            attempt_id: attempt,
            evidence,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    device_id: Uuid::new_v4(),
                    ..event(Evidence::DurableSubmitIntent, Uuid::new_v4())
                })
                .await,
            Err(StoreError::StaleFence)
        ));
        assert_eq!(
            store
                .record_radio_event(event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        assert!(store.claim_due("worker-b").await.unwrap().is_none());
        let new_session = store
            .connect_session(account, device, "b", "hub-b", 60)
            .await
            .unwrap();
        assert!(matches!(
            store.synthetic_payload_for_grant(&grant, &session).await,
            Err(StoreError::StaleFence)
        ));
        // The content-free confirmation enforces the same fence.
        assert!(matches!(
            store.confirm_synthetic_grant(&grant, &session).await,
            Err(StoreError::StaleFence)
        ));
        assert!(matches!(
            store
                .issue_grant(&claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::StaleFence)
        ));

        let second_message = Uuid::new_v4();
        store
            .accept(NewMessage {
                client_message_id: second_message,
                idempotency_key: "two",
                ..input()
            })
            .await
            .unwrap();
        let second_claim = store.claim_due("worker-b").await.unwrap().unwrap();
        assert_eq!(second_claim.message_id, second_message);
        assert!(matches!(
            store
                .issue_grant(&second_claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::DeviceBusy)
        ));
        assert!(matches!(
            store.cancel(account, message).await,
            Err(StoreError::InvalidTransition)
        ));
        assert!(!store.cancel(other_account, second_message).await.unwrap());
        assert!(store.cancel(account, second_message).await.unwrap());
        assert!(store.claim_due("worker-d").await.unwrap().is_none());
    }
    let second_device = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'multipart phone')",
            &[&second_device, &account],
        )
        .await
        .unwrap();
    let third_message = Uuid::new_v4();
    let third_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                client_message_id: third_message,
                device_id: second_device,
                idempotency_key: "three",
                ..input()
            })
            .await
            .unwrap();
        assert!(
            store
                .claim_due_for_device("wrong-tenant", other_account, second_device)
                .await
                .unwrap()
                .is_none()
        );
        let third_claim = store
            .claim_due_for_device("worker-c", account, second_device)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(third_claim.message_id, third_message);
        let third_session = store
            .connect_session(account, second_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&third_claim, &third_session, third_attempt)
            .await
            .unwrap();
        let multipart = |evidence, index, event_id| RadioEvent {
            event_id,
            account_id: account,
            device_id: second_device,
            message_id: third_message,
            attempt_id: third_attempt,
            evidence,
            observed_at_ms: now_ms(),
            segment_index: index,
            segment_count: index.map(|_| 2),
        };
        assert_eq!(
            store
                .record_radio_event(multipart(
                    Evidence::DurableSubmitIntent,
                    None,
                    Uuid::new_v4()
                ))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        let first_segment = multipart(Evidence::SentCallbackOk, Some(0), Uuid::new_v4());
        assert_eq!(
            store.record_radio_event(first_segment).await.unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store.record_radio_event(first_segment).await.unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(multipart(Evidence::SentCallbackOk, Some(1), Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitted
        );
        assert!(matches!(
            store
                .record_radio_event(multipart(
                    Evidence::SentCallbackFailed,
                    Some(1),
                    Uuid::new_v4()
                ))
                .await,
            Err(StoreError::InvalidInput)
        ));
        store
            .accept(NewMessage {
                client_message_id: Uuid::from_u128(42),
                device_id: second_device,
                idempotency_key: "expires",
                ..input()
            })
            .await
            .unwrap();
    }
    let expiring_message = Uuid::from_u128(42);
    client
        .execute(
            "UPDATE messages SET expires_at=now()-interval '1 second' WHERE id=$1",
            &[&expiring_message],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.expire_due(10).await.unwrap(), 1);
        assert!(store.claim_due("worker-e").await.unwrap().is_none());
    }
    let state: String = client
        .query_one(
            "SELECT state FROM messages WHERE id=$1",
            &[&expiring_message],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "expired");

    assert_eq!(
        DeliveryStore::new(&mut client)
            .reconcile_delivery_timeouts(10)
            .await
            .unwrap(),
        0
    );
    client
        .execute(
            "UPDATE messages SET updated_at=now()-interval '25 hours' WHERE id=$1",
            &[&third_message],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_delivery_timeouts(10).await.unwrap(), 1);
        assert_eq!(store.reconcile_delivery_timeouts(10).await.unwrap(), 0);
        assert_eq!(
            store
                .status(account, third_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::DeliveryUnknown
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: second_device,
                    message_id: third_message,
                    attempt_id: third_attempt,
                    evidence: Evidence::DeliveryCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: None,
                    segment_count: None,
                })
                .await
                .unwrap(),
            MessageState::Delivered
        );
    }

    let silent_grant_message = Uuid::new_v4();
    let silent_grant_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: silent_grant_message,
                device_id: second_device,
                idempotency_key: "silent-grant",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("timeout-grant", account, second_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, second_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, silent_grant_attempt)
            .await
            .unwrap();
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 0);
    }
    client.execute(
            "UPDATE dispatch_fences SET grant_expires_at=now()-interval '1 second' WHERE attempt_id=$1",
            &[&silent_grant_attempt],
        ).await.unwrap();
    let (mut timeout_blocker, timeout_connection) =
        tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
    tokio::spawn(async move { timeout_connection.await.unwrap() });
    timeout_blocker
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let timeout_lock = timeout_blocker.transaction().await.unwrap();
    timeout_lock
        .query_one(
            "SELECT id FROM messages WHERE id=$1 FOR UPDATE",
            &[&silent_grant_message],
        )
        .await
        .unwrap();
    assert_eq!(
        DeliveryStore::new(&mut client)
            .reconcile_silent_attempts(10)
            .await
            .unwrap(),
        0
    );
    timeout_lock.rollback().await.unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 1);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 0);
        assert_eq!(
            store
                .status(account, silent_grant_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Unknown
        );
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: Uuid::new_v4(),
                device_id: second_device,
                idempotency_key: "blocked-after-timeout",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let blocked_claim = store
            .claim_due_for_device("again", account, second_device)
            .await
            .unwrap()
            .unwrap();
        let new_session = store
            .connect_session(account, second_device, "b", "hub", 60)
            .await
            .unwrap();
        assert!(matches!(
            store
                .issue_grant(&blocked_claim, &new_session, Uuid::new_v4())
                .await,
            Err(StoreError::DeviceBusy)
        ));
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: second_device,
                    message_id: silent_grant_message,
                    attempt_id: silent_grant_attempt,
                    evidence: Evidence::SentCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: Some(0),
                    segment_count: Some(1),
                })
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let timeout_evidence: String = client
        .query_one(
            "SELECT evidence_code FROM message_events WHERE attempt_id=$1",
            &[&silent_grant_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(timeout_evidence, "grant_timeout");

    let timeout_device = Uuid::new_v4();
    client.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'callback timeout phone')",
            &[&timeout_device, &account],
        ).await.unwrap();
    let silent_callback_message = Uuid::new_v4();
    let silent_callback_attempt = Uuid::new_v4();
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: silent_callback_message,
                device_id: timeout_device,
                idempotency_key: "silent-callback",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("timeout-callback", account, timeout_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, timeout_device, "a", "hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, silent_callback_attempt)
            .await
            .unwrap();
        store
            .record_radio_event(RadioEvent {
                event_id: Uuid::new_v4(),
                account_id: account,
                device_id: timeout_device,
                message_id: silent_callback_message,
                attempt_id: silent_callback_attempt,
                evidence: Evidence::DurableSubmitIntent,
                observed_at_ms: now_ms(),
                segment_index: None,
                segment_count: None,
            })
            .await
            .unwrap();
    }
    client
        .execute(
            "UPDATE message_attempts SET updated_at=now()-interval '3 minutes' WHERE id=$1",
            &[&silent_callback_attempt],
        )
        .await
        .unwrap();
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(store.reconcile_silent_attempts(10).await.unwrap(), 1);
        assert_eq!(
            store
                .status(account, silent_callback_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Unknown
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: timeout_device,
                    message_id: silent_callback_message,
                    attempt_id: silent_callback_attempt,
                    evidence: Evidence::SentCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: Some(0),
                    segment_count: Some(1),
                })
                .await
                .unwrap(),
            MessageState::Submitted
        );
    }
    let timeout_evidence: String = client.query_one(
            "SELECT evidence_code FROM message_events WHERE attempt_id=$1 AND evidence_code='sent_callback_timeout'",
            &[&silent_callback_attempt],
        ).await.unwrap().get(0);
    assert_eq!(timeout_evidence, "sent_callback_timeout");
    {
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    account_id: account,
                    device_id: timeout_device,
                    message_id: silent_callback_message,
                    attempt_id: silent_callback_attempt,
                    evidence: Evidence::DeliveryCallbackOk,
                    observed_at_ms: now_ms(),
                    segment_index: None,
                    segment_count: None,
                })
                .await
                .unwrap(),
            MessageState::Delivered
        );
        let conflict = RadioEvent {
            event_id: Uuid::new_v4(),
            account_id: account,
            device_id: timeout_device,
            message_id: silent_callback_message,
            attempt_id: silent_callback_attempt,
            evidence: Evidence::CallbackConflict,
            observed_at_ms: now_ms(),
            segment_index: None,
            segment_count: None,
        };
        assert_eq!(
            store.record_radio_event(conflict).await.unwrap(),
            MessageState::Unknown
        );
        assert_eq!(
            store.record_radio_event(conflict).await.unwrap(),
            MessageState::Unknown
        );
        assert!(matches!(
            store
                .record_radio_event(RadioEvent {
                    event_id: Uuid::new_v4(),
                    evidence: Evidence::DeliveryCallbackOk,
                    ..conflict
                })
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let fence: String = client
        .query_one(
            "SELECT outcome FROM dispatch_fences WHERE attempt_id=$1",
            &[&silent_callback_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(fence, "unknown");

    // A durable phone proof can release an ambiguous fence exactly once.
    // This uses a distinct device so the prior unknown attempt stays fenced.
    let proof_device = Uuid::new_v4();
    let proof_message = Uuid::new_v4();
    let proof_attempt = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'no radio phone')",
            &[&proof_device, &account],
        )
        .await
        .unwrap();
    let proof_event = |evidence, event_id| RadioEvent {
        event_id,
        account_id: account,
        device_id: proof_device,
        message_id: proof_message,
        attempt_id: proof_attempt,
        evidence,
        observed_at_ms: now_ms(),
        segment_index: None,
        segment_count: None,
    };
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id: account,
                client_message_id: proof_message,
                device_id: proof_device,
                idempotency_key: "proved-no-radio",
                recipient_e164: "+15551234567",
                synthetic_payload: b"test only",
                expires_at_ms: expiry,
            })
            .await
            .unwrap();
        let claim = store
            .claim_due_for_device("proof", account, proof_device)
            .await
            .unwrap()
            .unwrap();
        let session = store
            .connect_session(account, proof_device, "a", "proof-hub", 60)
            .await
            .unwrap();
        store
            .issue_grant(&claim, &session, proof_attempt)
            .await
            .unwrap();
        assert_eq!(
            store
                .record_radio_event(proof_event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(proof_event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        let no_radio = proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4());
        assert_eq!(
            store.record_radio_event(no_radio).await.unwrap(),
            MessageState::Queued
        );
        assert_eq!(
            store.record_radio_event(no_radio).await.unwrap(),
            MessageState::Queued
        );
        assert!(matches!(
            store
                .record_radio_event(proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::StaleFence)
        ));
        let replay_claim = store
            .claim_due_for_device("proof-retry", account, proof_device)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replay_claim.message_id, proof_message);
        let fresh_session = store
            .connect_session(account, proof_device, "b", "proof-hub", 60)
            .await
            .unwrap();
        let fresh_attempt = Uuid::new_v4();
        assert!(
            store
                .issue_grant(&replay_claim, &fresh_session, fresh_attempt)
                .await
                .is_ok()
        );
        assert!(matches!(
            store
                .record_radio_event(proof_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::StaleFence)
        ));
        assert_eq!(
            store
                .status(account, proof_message)
                .await
                .unwrap()
                .unwrap()
                .state,
            MessageState::Claimed
        );
        let fresh_event = |evidence, event_id| RadioEvent {
            attempt_id: fresh_attempt,
            evidence,
            event_id,
            ..no_radio
        };
        assert_eq!(
            store
                .record_radio_event(fresh_event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(RadioEvent {
                    segment_index: Some(0),
                    segment_count: Some(2),
                    ..fresh_event(Evidence::SentCallbackOk, Uuid::new_v4())
                })
                .await
                .unwrap(),
            MessageState::Submitting
        );
        assert_eq!(
            store
                .record_radio_event(fresh_event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                .await
                .unwrap(),
            MessageState::Unknown
        );
        assert!(matches!(
            store
                .record_radio_event(fresh_event(Evidence::ProvenNoSubmit, Uuid::new_v4()))
                .await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let old_fence_count: i64 = client
        .query_one(
            "SELECT COUNT(*) FROM dispatch_fences WHERE attempt_id=$1",
            &[&proof_attempt],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(old_fence_count, 0);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn terminal_dispatch_backfill_and_live_claims_ignore_large_history() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("terminal_dispatch_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    for (_, migration) in TEST_MIGRATIONS.iter().take(29) {
        client.batch_execute(migration).await.unwrap();
    }
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let due = Uuid::new_v4();
    let expiring = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'virtual phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    // This is the historical shape left by old cancel/expiry code: terminal
    // messages, pre-grant jobs and old next-attempt times still indexed.
    client
        .execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
             transport_mode,transport_payload,request_digest,state,expires_at,updated_at) \
             SELECT md5('terminal-'||g::text)::uuid,$1,$2,'+15551234567', \
               decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'), \
               decode(repeat('22',32),'hex'), \
               CASE WHEN g%2=0 THEN 'cancelled' ELSE 'expired' END, \
               now()-interval '1 day',now()-interval '1 day' \
             FROM generate_series(1,8000) g",
            &[&account, &device],
        )
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id,next_attempt_at, \
             generation,lease_owner,lease_until) \
             SELECT id,account_id,device_id,now()-interval '1 day',3,'old-worker', \
               now()-interval '1 hour' FROM messages WHERE account_id=$1",
            &[&account],
        )
        .await
        .unwrap();
    for (id, expiry) in [(due, "10 minutes"), (expiring, "-1 minute")] {
        client
            .execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
                 transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',decode(repeat('11',32),'hex'), \
                 'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'), \
                 'queued',now()+$4::text::interval)",
                &[&id, &account, &device, &expiry],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO dispatch_jobs(message_id,account_id,device_id,next_attempt_at) \
                 VALUES($1,$2,$3,now()-interval '1 minute')",
                &[&id, &account, &device],
            )
            .await
            .unwrap();
    }
    client.batch_execute(TEST_MIGRATIONS[29].1).await.unwrap();
    let counts = client
        .query_one(
            "SELECT count(*) FILTER (WHERE finished_at IS NOT NULL), \
             count(*) FILTER (WHERE finished_at IS NULL AND grant_issued_at IS NULL), \
             count(*) FILTER (WHERE finished_at IS NOT NULL AND \
               (generation<>3 OR lease_owner IS NOT NULL OR lease_until IS NOT NULL)) \
             FROM dispatch_jobs",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 8000);
    assert_eq!(counts.get::<_, i64>(1), 2);
    assert_eq!(counts.get::<_, i64>(2), 0);
    let wrong_backfill_time: i64 = client.query_one(
            "SELECT count(*) FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
             WHERE m.state IN ('cancelled','expired') AND j.finished_at IS DISTINCT FROM m.updated_at",
            &[],
        ).await.unwrap().get(0);
    assert_eq!(wrong_backfill_time, 0);
    let index: String = client
        .query_one(
            "SELECT indexdef FROM pg_indexes WHERE schemaname=current_schema() \
             AND indexname='dispatch_jobs_due'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(index.contains("finished_at IS NULL"), "{index}");

    client
        .batch_execute("ANALYZE messages; ANALYZE dispatch_jobs; ANALYZE devices")
        .await
        .unwrap();
    let claim_plan = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS) \
             SELECT j.message_id FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
             JOIN devices d ON d.id=j.device_id AND d.account_id=j.account_id \
             WHERE j.next_attempt_at<=now() AND (j.lease_until IS NULL OR j.lease_until<now()) \
             AND j.grant_issued_at IS NULL AND j.finished_at IS NULL \
             AND m.state IN ('queued','claimed') AND m.expires_at>now() \
             AND d.revoked_at IS NULL \
             ORDER BY j.next_attempt_at,j.message_id FOR UPDATE OF j SKIP LOCKED LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !claim_plan.contains("Seq Scan on dispatch_jobs"),
        "{claim_plan}"
    );
    assert!(!claim_plan.contains("Seq Scan on messages"), "{claim_plan}");
    let expiry_plan = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS) \
             SELECT j.account_id,j.message_id FROM dispatch_jobs j \
             JOIN messages m ON m.id=j.message_id \
             WHERE j.grant_issued_at IS NULL AND j.finished_at IS NULL \
             AND m.expires_at<=now() AND m.state IN ('queued','claimed') \
             ORDER BY m.expires_at,m.id FOR UPDATE OF j SKIP LOCKED LIMIT 10",
            &[],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !expiry_plan.contains("Seq Scan on dispatch_jobs"),
        "{expiry_plan}"
    );
    assert!(
        !expiry_plan.contains("Seq Scan on messages"),
        "{expiry_plan}"
    );

    // Both transitions commit the message state and index exclusion together.
    let mut store = DeliveryStore::new(&mut client);
    assert!(store.cancel(account, due).await.unwrap());
    assert_eq!(store.expire_due(10).await.unwrap(), 1);
    let terminal = client
        .query(
            "SELECT m.id,m.state,j.finished_at IS NOT NULL \
             FROM messages m JOIN dispatch_jobs j ON j.message_id=m.id \
             WHERE m.id=$1 OR m.id=$2 ORDER BY m.id",
            &[&due, &expiring],
        )
        .await
        .unwrap();
    assert_eq!(terminal.len(), 2);
    for row in terminal {
        let id: Uuid = row.get(0);
        let state: String = row.get(1);
        assert_eq!(state, if id == due { "cancelled" } else { "expired" });
        assert!(row.get::<_, bool>(2));
    }
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn recent_grant_precheck_is_one_bounded_index_probe() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("recent_grant_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let epoch: i64 = client
        .query_one("SELECT epoch FROM deployment_authority", &[])
        .await
        .unwrap()
        .get(0);
    {
        let mut store = DeliveryStore::new(&mut client);
        store
            .accept(NewMessage {
                account_id,
                device_id,
                client_message_id: message_id,
                idempotency_key: "recent-grant",
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic regression",
                expires_at_ms: now_ms() + 60_000,
            })
            .await
            .unwrap();
        assert!(
            store
                .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
                .await
                .unwrap()
        );
    }
    // A long-lived device: thousands of old attempts, none in the last minute.
    client
        .execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,\
              deployment_epoch,status,created_at,updated_at) \
             SELECT gen_random_uuid(),$1,$2,$3,g,1,$4,'failed',now()-interval '1 day'-g*interval '1 second',now() \
             FROM generate_series(1000,4999) g",
            &[&account_id, &message_id, &device_id, &epoch],
        )
        .await
        .unwrap();
    client
        .batch_execute("ANALYZE message_attempts")
        .await
        .unwrap();
    let plan: Vec<String> = client
        .query(
            &format!("EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) {SYNTHETIC_GRANT_PRECHECK}"),
            &[&account_id, &device_id, &epoch, &60i32],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let shown = plan.join("\n");
    // Exactly one access to message_attempts, through the new index, and it
    // returns nothing without filtering the old history out of the heap.
    let accesses: Vec<usize> = plan
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(" on message_attempts"))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(accesses.len(), 1, "{shown}");
    let node = &plan[accesses[0]];
    assert!(
        node.contains("Index Only Scan using message_attempts_device_created")
            || node.contains("Index Scan using message_attempts_device_created"),
        "{shown}"
    );
    // PostgreSQL 18 prints fractional row counts ("rows=0.00").
    assert!(
        node.contains("rows=0 ") || node.contains("rows=0.00 "),
        "{shown}"
    );
    let depth = node.len() - node.trim_start().len();
    let details: Vec<&String> = plan[accesses[0] + 1..]
        .iter()
        .take_while(|line| {
            let indent = line.len() - line.trim_start().len();
            indent > depth && !line.trim_start().starts_with("->")
        })
        .collect();
    assert!(
        details
            .iter()
            .all(|line| !line.contains("Rows Removed by Filter")),
        "{shown}"
    );
    let blocks: u64 = details
        .iter()
        .filter_map(|line| line.trim().strip_prefix("Buffers: shared "))
        .flat_map(|rest| rest.split(' '))
        .filter_map(|part| {
            part.split_once('=')
                .and_then(|(_, n)| n.parse::<u64>().ok())
        })
        .sum();
    assert!(blocks <= 4, "probe touched {blocks} blocks: {shown}");
    let mut store = DeliveryStore::new(&mut client);
    assert!(
        store
            .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
            .await
            .unwrap()
    );
    // A stale epoch or paused dispatch refuses before any claim.
    assert!(
        !store
            .synthetic_grant_may_be_due(account_id, device_id, epoch + 1, 60)
            .await
            .unwrap()
    );
    // A fresh grant: its fence and its attempt each refuse on their own.
    let session = store
        .connect_session(account_id, device_id, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account_id, device_id)
        .await
        .unwrap()
        .unwrap();
    let attempt_id = Uuid::new_v4();
    store
        .issue_grant(&claim, &session, attempt_id)
        .await
        .unwrap();
    assert!(
        !store
            .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
            .await
            .unwrap()
    );
    client
        .execute(
            "UPDATE dispatch_fences SET outcome='submitted' WHERE attempt_id=$1",
            &[&attempt_id],
        )
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    assert!(
        !store
            .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
            .await
            .unwrap(),
        "an attempt from the last minute must still refuse"
    );
    client
        .execute(
            "UPDATE message_attempts SET created_at=now()-interval '2 minutes' WHERE id=$1",
            &[&attempt_id],
        )
        .await
        .unwrap();
    client
        .execute(
            "UPDATE deployment_authority SET dispatch_enabled=FALSE",
            &[],
        )
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    assert!(
        !store
            .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
            .await
            .unwrap()
    );
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    assert!(
        store
            .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
            .await
            .unwrap()
    );

    // Fence outcomes: granted, submitting and unknown are active and refuse;
    // resolved outcomes do not.
    for (outcome, due) in [
        ("granted", false),
        ("submitting", false),
        ("unknown", false),
        ("submitted", true),
        ("failed", true),
    ] {
        client
            .execute(
                "UPDATE dispatch_fences SET outcome=$2 WHERE attempt_id=$1",
                &[&attempt_id, &outcome],
            )
            .await
            .unwrap();
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(
            store
                .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
                .await
                .unwrap(),
            due,
            "fence outcome {outcome}"
        );
    }

    // The spacing boundary is exclusive: inside one transaction now() is
    // fixed, so an attempt exactly 60 s old no longer refuses and one 59 s
    // old still does.
    for (age, due) in [("60 seconds", true), ("59 seconds", false)] {
        client.batch_execute("BEGIN").await.unwrap();
        client
            .execute(
                "UPDATE message_attempts SET created_at=now()-($2::text)::interval WHERE id=$1",
                &[&attempt_id, &age],
            )
            .await
            .unwrap();
        let mut store = DeliveryStore::new(&mut client);
        assert_eq!(
            store
                .synthetic_grant_may_be_due(account_id, device_id, epoch, 60)
                .await
                .unwrap(),
            due,
            "attempt aged {age}"
        );
        client.batch_execute("ROLLBACK").await.unwrap();
    }
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

/// A byte-pipe between the client and PostgreSQL that counts Sync-terminated
/// batches the client sends. Every extended-protocol round trip ends with a
/// Sync message, so the count is the number of client waits per operation:
/// the legacy `query(&str)` path needs a Parse/Describe wait before each
/// Bind/Execute, while the typed API sends Parse+Bind+Execute in one flight.
struct DescribeCountingProxy {
    url: String,
    round_trips: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl DescribeCountingProxy {
    /// Forwards one client connection to `target` and reports its URL plus the
    /// shared round-trip counter.
    async fn start(target: &str) -> (Self, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        let (authority, rest) = target
            .split_once("://")
            .expect("database URL with scheme")
            .1
            .split_once('/')
            .expect("database URL with a path");
        let userinfo = match authority.rsplit_once('@') {
            Some((userinfo, _)) => format!("{userinfo}@"),
            None => String::new(),
        };
        let upstream = authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
            .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let url = format!("postgres://{userinfo}127.0.0.1:{port}/{rest}");
        let round_trips = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = round_trips.clone();
        let task = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut server = TcpStream::connect(upstream).await.unwrap();
            // The counting direction is client to server. The first message
            // is the untagged startup frame; every later one is a one-byte
            // tag followed by a big-endian length that counts itself.
            let mut from_client = Vec::new();
            let mut startup_skipped = false;
            let mut client_buf = [0u8; 8192];
            let mut server_buf = [0u8; 8192];
            loop {
                tokio::select! {
                    read = client.read(&mut client_buf) => {
                        let read = match read { Ok(0) | Err(_) => break, Ok(read) => read };
                        from_client.extend_from_slice(&client_buf[..read]);
                        let mut cursor = 0;
                        if !startup_skipped {
                            let startup = from_client
                                .get(..4)
                                .map(|prefix| u32::from_be_bytes(prefix.try_into().unwrap()) as usize);
                            match startup {
                                Some(length) if from_client.len() >= length && length >= 8 => {
                                    cursor = length;
                                    startup_skipped = true;
                                }
                                // The rest of the startup frame has not
                                // arrived yet; nothing is countable so far.
                                _ => cursor = 0,
                            }
                        }
                        while from_client.len() - cursor >= 5 {
                            let length =
                                u32::from_be_bytes(from_client[cursor + 1..cursor + 5].try_into().unwrap())
                                    as usize;
                            if from_client.len() - cursor < 1 + length {
                                break;
                            }
                            if from_client[cursor] == b'S' {
                                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            cursor += 1 + length;
                        }
                        from_client.drain(..cursor);
                        if server.write_all(&client_buf[..read]).await.is_err() {
                            break;
                        }
                    }
                    read = server.read(&mut server_buf) => {
                        let read = match read { Ok(0) | Err(_) => break, Ok(read) => read };
                        if client.write_all(&server_buf[..read]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = client.shutdown().await;
            let _ = server.shutdown().await;
        });
        (Self { url, round_trips }, task)
    }
}

/// The admission transaction must pay exactly one round trip per statement:
/// six extended-protocol statements for a fresh unmetered accept, and the
/// control query shows the legacy path pays two (#476).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn admission_pending_count_reads_the_account_pending_index_only() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("admission_pending_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    let device = Uuid::new_v4();
    let other_account = Uuid::new_v4();
    let other_device = Uuid::new_v4();
    for id in [&account, &other_account] {
        client
            .execute("INSERT INTO accounts(id) VALUES($1)", &[id])
            .await
            .unwrap();
    }
    for (id, owner) in [(&device, &account), (&other_device, &other_account)] {
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
                &[id, owner],
            )
            .await
            .unwrap();
    }
    // The counted tenant keeps a large terminal history. Retention only redacts
    // content, so these rows stay forever and must never feed the count.
    client
        .execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             SELECT gen_random_uuid(),$1,$2,'+15551234567',decode(repeat('11',32),'hex'),\
             'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),\
             'delivered',now()-interval '1 day' FROM generate_series(1,8000)",
            &[&account, &device],
        )
        .await
        .unwrap();
    // Two live pending messages for the counted device.
    for _ in 0..2 {
        client
            .execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES(gen_random_uuid(),$1,$2,'+15551234567',decode(repeat('11',32),'hex'),\
                 'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),\
                 'queued',now()+interval '1 hour')",
                &[&account, &device],
            )
            .await
            .unwrap();
    }
    // Other tenants hold large live queues. A global pending walk, the plan the
    // expiry-keyed index serves, would visit all of their rows.
    client
        .execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             SELECT gen_random_uuid(),$1,$2,'+15551234567',decode(repeat('11',32),'hex'),\
             'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),\
             'queued',now()+interval '1 hour' FROM generate_series(1,16000)",
            &[&other_account, &other_device],
        )
        .await
        .unwrap();
    client.batch_execute("ANALYZE messages").await.unwrap();

    let counts = client
        .query_one(
            "SELECT COUNT(*) FILTER (WHERE device_id=$2), COUNT(*) FROM messages \
             WHERE account_id=$1 AND state IN ('queued','claimed') AND expires_at>now()",
            &[&account, &device],
        )
        .await
        .unwrap();
    assert_eq!(counts.get::<_, i64>(0), 2);
    assert_eq!(counts.get::<_, i64>(1), 2);

    // The admission count is the exact accept_inner query, run inside the
    // account-locked admission transaction on every accept.
    let plan: Vec<String> = client
        .query(
            "EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) \
             SELECT COUNT(*) FILTER (WHERE device_id=$2), COUNT(*) FROM messages \
             WHERE account_id=$1 AND state IN ('queued','claimed') AND expires_at>now()",
            &[&account, &device],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect();
    let shown = plan.join("\n");
    // The scan must go through the account-keyed partial index and none of the
    // history, expiry-keyed, or device-keyed alternatives.
    assert!(shown.contains("messages_admission_pending"), "{shown}");
    for wrong in [
        "Seq Scan on messages",
        "messages_account_created",
        "messages_pending_expiry",
        "messages_owner_pending_state",
    ] {
        assert!(!shown.contains(wrong), "{wrong} in: {shown}");
    }
    // Neither the tenant's terminal history nor other tenants' queues were
    // fetched and filtered away: the heap saw only the account's pending rows.
    for line in &plan {
        if let Some(rest) = line.trim().strip_prefix("Rows Removed by Filter: ") {
            let removed: i64 = rest.trim().parse().unwrap_or(0);
            assert_eq!(removed, 0, "{shown}");
        }
    }
    let blocks: u64 = plan
        .iter()
        .filter_map(|line| line.trim().strip_prefix("Buffers: shared "))
        .flat_map(|rest| rest.split(' '))
        .filter_map(|part| {
            part.split_once('=')
                .and_then(|(_, n)| n.parse::<u64>().ok())
        })
        .sum();
    assert!(blocks <= 16, "count touched {blocks} blocks: {shown}");
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn admission_pays_one_round_trip_per_statement() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("round_trip_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&setup).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    setup
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    setup
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'wire fixture')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();

    let (proxy, proxy_task) = DescribeCountingProxy::start(&url).await;
    let (mut client, connection) = tokio_postgres::connect(&proxy.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let before = proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(before, 0, "setup runs outside the proxied connection");
    let mut store = DeliveryStore::new(&mut client);
    store
        .accept(NewMessage {
            account_id,
            device_id,
            client_message_id: Uuid::new_v4(),
            idempotency_key: "round-trip",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic wire count",
            expires_at_ms: now_ms() + 60_000,
        })
        .await
        .unwrap();
    // One Sync-terminated batch per statement: account lock, suppression
    // check, idempotency insert, pending counts, message insert, dispatch job
    // insert. BEGIN/COMMIT use the simple protocol and add none.
    let after_accept = proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        after_accept, 6,
        "fresh unmetered admission must pay exactly one round trip per statement"
    );
    // A billed alpha admission adds the billing statements: the tenant is
    // bound, its reconciliation is done, it has no risk event or past-due
    // subscription (so the conditional grace read is skipped), and its
    // stripe_test policy has room.
    let billed_account = Uuid::new_v4();
    let billed_device = Uuid::new_v4();
    setup
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&billed_account])
        .await
        .unwrap();
    setup
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'billed wire fixture')",
            &[&billed_device, &billed_account],
        )
        .await
        .unwrap();
    for statement in [
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_roundtrip')",
        "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id, \
         dirty_generation,processed_generation) VALUES('sub_roundtrip',$1,'cus_roundtrip',1,1)",
        "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) \
         VALUES($1,'outbound_message',10,'stripe_test')",
    ] {
        setup.execute(statement, &[&billed_account]).await.unwrap();
    }
    DeliveryStore::new(&mut client)
        .accept_alpha(
            NewMessage {
                account_id: billed_account,
                device_id: billed_device,
                client_message_id: Uuid::new_v4(),
                idempotency_key: "billed-round-trip",
                recipient_e164: "+15551234567",
                synthetic_payload: b"synthetic billed wire count",
                expires_at_ms: now_ms() + 60_000,
            },
            true,
        )
        .await
        .unwrap();
    // Customer binding FOR SHARE, account lock, suppression check,
    // idempotency insert, pending counts, message insert, billing guards,
    // period upsert with its ledger entry, dispatch job insert.
    let after_billed = proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        after_billed - after_accept,
        9,
        "fresh billed admission must pay exactly one round trip per statement"
    );
    let reserved: i64 = setup
        .query_one(
            "SELECT reserved_units FROM usage_periods WHERE account_id=$1",
            &[&billed_account],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(reserved, 1, "the billed admission must reserve its unit");
    // Control: the legacy `query(&str)` path waits on Parse/Describe before
    // Bind/Execute, so the same single statement costs at least two batches.
    client
        .query_opt("SELECT $1::text", &[&"legacy-control"])
        .await
        .unwrap();
    let after_control = proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        after_control >= after_billed + 2,
        "legacy query(&str) must still pay a separate prepare round trip"
    );
    proxy_task.abort();
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn one_evidence_aggregate_keeps_conflict_segment_and_proof_rules() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("evidence_aggregate_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account_id])
        .await
        .unwrap();
    client
        .execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
            &[&device_id, &account_id],
        )
        .await
        .unwrap();
    client
        .execute("UPDATE deployment_authority SET dispatch_enabled=TRUE", &[])
        .await
        .unwrap();
    let mut store = DeliveryStore::new(&mut client);
    store
        .accept(NewMessage {
            account_id,
            device_id,
            client_message_id: message_id,
            idempotency_key: "evidence-aggregate",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic regression",
            expires_at_ms: now_ms() + 60_000,
        })
        .await
        .unwrap();
    let session = store
        .connect_session(account_id, device_id, "test", "test", 60)
        .await
        .unwrap();
    let digest: [u8; 32] = Sha256::digest(b"+15551234567").into();
    // The synthetic claim returns the message content from its own
    // transaction, so the socket never reads it separately.
    let (claim, content) = store
        .claim_synthetic_for_device_and_recipient("test", account_id, device_id, &digest)
        .await
        .unwrap()
        .unwrap();
    let content = content.unwrap();
    assert_eq!(content.recipient_e164, "+15551234567");
    assert_eq!(content.transport_payload, b"synthetic regression");
    assert_eq!(content.transport_mode, "synthetic_alpha");
    let attempt_id = Uuid::new_v4();
    let grant = store
        .issue_grant(&claim, &session, attempt_id)
        .await
        .unwrap();
    store
        .confirm_synthetic_grant(&grant, &session)
        .await
        .unwrap();
    let event = |evidence, segment: Option<(i32, i32)>| RadioEvent {
        event_id: Uuid::new_v4(),
        account_id,
        device_id,
        message_id,
        attempt_id,
        evidence,
        observed_at_ms: now_ms(),
        segment_index: segment.map(|(index, _)| index),
        segment_count: segment.map(|(_, count)| count),
    };
    // A sent callback needs a durable intent first.
    assert!(matches!(
        store
            .record_radio_event(event(Evidence::SentCallbackOk, Some((0, 3))))
            .await,
        Err(StoreError::InvalidTransition)
    ));
    store
        .record_radio_event(event(Evidence::DurableSubmitIntent, None))
        .await
        .unwrap();
    assert_eq!(
        store
            .record_radio_event(event(Evidence::SentCallbackOk, Some((0, 3))))
            .await
            .unwrap(),
        MessageState::Submitting
    );
    // A later segment must declare the same count as the first.
    assert!(matches!(
        store
            .record_radio_event(event(Evidence::SentCallbackOk, Some((1, 2))))
            .await,
        Err(StoreError::InvalidInput)
    ));
    // A radio callback on the attempt forbids a no-submit proof.
    assert!(matches!(
        store
            .record_radio_event(event(Evidence::ProvenNoSubmit, None))
            .await,
        Err(StoreError::InvalidTransition)
    ));
    // The same aggregate also sees the intent a conflict requires, and the
    // conflict then refuses every later callback on this attempt.
    assert_eq!(
        store
            .record_radio_event(event(Evidence::CallbackConflict, None))
            .await
            .unwrap(),
        MessageState::Unknown
    );
    for (evidence, segment) in [
        (Evidence::SentCallbackOk, Some((1, 3))),
        (Evidence::DeliveryCallbackOk, None),
        (Evidence::ProvenNoSubmit, None),
    ] {
        assert!(matches!(
            store.record_radio_event(event(evidence, segment)).await,
            Err(StoreError::InvalidTransition)
        ));
    }
    let recorded: Vec<String> = client
        .query(
            "SELECT evidence_code FROM message_events WHERE attempt_id=$1 ORDER BY observed_at,id",
            &[&attempt_id],
        )
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(recorded.len(), 3);
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

/// The folded billing guard statement must keep every FOR SHARE lock the
/// sequential reads took: while an admission holds them, billing ingress and
/// reconciliation cannot change the risk event, the unfinished
/// reconciliation, the past-due subscription or the policy row it just read.
/// Each row is set up so only the guard statement locks it (the
/// reconciliation is not done, so `recon_done_lock` does not cover it).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn billed_admission_guard_share_locks_every_row_it_reads() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_guard_lock_test_{}", Uuid::new_v4().simple());
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&client).await;
    let account = Uuid::new_v4();
    client
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    for statement in [
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_guardlock')",
        "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id, \
         dirty_generation,processed_generation) VALUES('sub_guardlock',$1,'cus_guardlock',2,1)",
        "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status) \
         VALUES('sub_guardlock',$1,'cus_guardlock','past_due')",
        "INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) \
         VALUES('evt_guardlock','charge.refunded',$1,decode(repeat('ab',32),'hex'),'queued')",
        "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
         VALUES('evt_guardlock','ch_guardlock','refund',$1)",
        "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) \
         VALUES($1,'outbound_message',10,'stripe_test')",
    ] {
        client.execute(statement, &[&account]).await.unwrap();
    }
    let (mut peer, peer_connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { peer_connection.await.unwrap() });
    peer.batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let guarded = [
        "SELECT 1 FROM billing_risk_events WHERE account_id=$1 FOR UPDATE NOWAIT",
        "SELECT 1 FROM billing_reconciliations WHERE account_id=$1 FOR UPDATE NOWAIT",
        "SELECT 1 FROM billing_subscriptions WHERE account_id=$1 FOR UPDATE NOWAIT",
        "SELECT 1 FROM usage_quota_policies WHERE account_id=$1 FOR UPDATE NOWAIT",
    ];
    // Nothing holds the rows yet: the peer's probe itself is lockable.
    for statement in guarded {
        let probe = peer.transaction().await.unwrap();
        assert_eq!(probe.query(statement, &[&account]).await.unwrap().len(), 1);
        probe.rollback().await.unwrap();
    }
    let tx = client.transaction().await.unwrap();
    let (_, bound) = lock_billing_account(&tx, account, true).await.unwrap();
    assert_eq!(bound, Some(true));
    // The queued risk event makes this admission a payment hold, but only
    // after the guard statement has read, and locked, all four rows.
    assert!(matches!(
        reserve_outbound(&tx, account, Uuid::new_v4(), None, bound).await,
        Err(StoreError::PaymentHold)
    ));
    for statement in guarded {
        let error = peer
            .query(statement, &[&account])
            .await
            .expect_err(statement);
        assert_eq!(
            error.code(),
            Some(&SqlState::LOCK_NOT_AVAILABLE),
            "{statement}: {error:?}"
        );
    }
    tx.rollback().await.unwrap();
    client
        .batch_execute(&format!(
            "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
        ))
        .await
        .unwrap();
}

/// Each sweep pays a constant number of round trips per batch: one statement
/// for any batch size, where the per-row loop paid four per row (#508).
#[tokio::test]
#[ignore = "requires ZT_DELIVERY_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn recovery_sweeps_pay_one_round_trip_per_batch() {
    let url = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL")
        .expect("set ZT_DELIVERY_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("sweep_wire_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!(
            "CREATE SCHEMA {schema}; SET search_path TO {schema}"
        ))
        .await
        .unwrap();
    apply_test_migrations(&setup).await;
    let account = Uuid::new_v4();
    setup
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
        .await
        .unwrap();
    setup
        .execute(
            "INSERT INTO devices(id,account_id,display_name) \
             SELECT gen_random_uuid(),$1,'wire sweep' FROM generate_series(1,30)",
            &[&account],
        )
        .await
        .unwrap();
    setup
        .execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest, \
             transport_mode,transport_payload,request_digest,state,expires_at) \
             SELECT gen_random_uuid(),$1,(SELECT d.id FROM devices d WHERE d.account_id=$1 \
               ORDER BY d.id LIMIT 1 OFFSET (n-1)),'+15551234567',$2,'synthetic_alpha',$3,$4,'queued', \
             now()-interval '1 second' FROM generate_series(1,30::bigint) n",
            &[&account, &vec![1_u8; 32], &b"wire".as_slice(), &vec![2_u8; 32]],
        )
        .await
        .unwrap();
    setup
        .execute(
            "INSERT INTO dispatch_jobs(message_id,account_id,device_id) \
             SELECT m.id,$1,m.device_id FROM messages m WHERE m.account_id=$1",
            &[&account],
        )
        .await
        .unwrap();

    let (proxy, proxy_task) = DescribeCountingProxy::start(&url).await;
    let (mut client, connection) = tokio_postgres::connect(&proxy.url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    client
        .batch_execute(&format!("SET search_path TO {schema}"))
        .await
        .unwrap();
    let before = proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(before, 0);
    let expired = DeliveryStore::new(&mut client)
        .expire_due(30)
        .await
        .unwrap();
    assert_eq!(expired, 30);
    assert_eq!(
        proxy.round_trips.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a full batch must be exactly one statement, not one per row"
    );
    proxy_task.abort();
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
