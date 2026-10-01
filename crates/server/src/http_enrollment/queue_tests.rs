// SPDX-License-Identifier: AGPL-3.0-only
use super::tests::{json_response, request};
use super::*;
use crate::auth::{login, register, verify_email};
use axum::http::Method;
use p256::{ecdsa::SigningKey, elliptic_curve::Generate};
use rand::rng;
use serde_json::json;
use tower::ServiceExt;

#[path = "queue_plan_tests.rs"]
mod queue_plan_tests;
use queue_plan_tests::{explain_queue, validate_queue_plan, validate_sparse_history_plan};

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_queue_counts_are_bounded_tenant_scoped_and_preserve_writer_states() {
    let base = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_queue_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    apply_queue_schema(&db).await;
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let mut owners = Vec::new();
    for label in ["queue-a", "queue-b"] {
        let email = format!("{label}@example.test");
        let password = format!("synthetic-{}", Uuid::new_v4());
        let signup = register(&mut db, &hasher, &email, &password).await.unwrap();
        verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let session = login(&db, &hasher, &email, &password).await.unwrap();
        let device = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic gateway')",
            &[&device, &signup.account_id],
        )
        .await
        .unwrap();
        let signing = SigningKey::generate_from_rng(&mut rng());
        let key = signing.verifying_key().to_sec1_point(false);
        let fingerprint = rand::random::<[u8; 32]>();
        db.execute("INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)", &[&device, &signup.account_id, &key.as_bytes(), &&fingerprint[..]]).await.unwrap();
        owners.push((signup.account_id, device, session));
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    let app = router(EnrollmentHttpState::new(
        format!("{base}{sep}options=-csearch_path%3D{schema}"),
        hasher,
        Arc::new(EnrollmentHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap()),
        "https://test.example".into(),
    ));
    let (account, device, session) = &owners[0];
    let get = || {
        request(
            Method::GET,
            "/devices",
            json!({}),
            Some((&session.token, &session.csrf_token)),
        )
    };
    let empty = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(empty["devices"][0]["pending_messages"], 0);
    assert_eq!(empty["devices"][0]["in_flight_messages"], 0);
    for (tenant, phone, _) in &owners {
        for state in [
            "accepted",
            "queued",
            "claimed",
            "submitting",
            "submitted",
            "delivered",
            "delivery_unknown",
            "unknown",
            "failed",
            "cancelled",
            "expired",
        ] {
            db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),$4,now()-interval '1 hour')", &[&Uuid::new_v4(), tenant, phone, &state]).await.unwrap();
        }
    }
    let response = app.clone().oneshot(get()).await.unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let page = json_response(response).await;
    let status = &page["devices"][0];
    assert_eq!(page["devices"].as_array().unwrap().len(), 1);
    assert_eq!(status["pending_messages"], 3);
    assert_eq!(status["in_flight_messages"], 2);
    assert_eq!(status["active_socket_lease"], false);
    assert!(
        status["status_observed_at_ms"].as_i64().unwrap()
            >= empty["devices"][0]["status_observed_at_ms"]
                .as_i64()
                .unwrap()
    );
    for private in [
        "recipient_e164",
        "transport_payload",
        "sim_id",
        "sms_ready",
        "radio_ready",
    ] {
        assert!(status.get(private).is_none());
    }
    // A large final history must not make these active-state probes scan it.
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('history-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'delivered',now() FROM generate_series(1,200000) g", &[account, device]).await.unwrap();
    db.batch_execute("ANALYZE messages; ANALYZE devices")
        .await
        .unwrap();
    // The sparse partial-index plan may filter other active entries, but its
    // entire index contains only six. Keep that fixture-specific budget honest.
    let active: i64 = db
        .query_one(
            "SELECT count(*) FROM messages WHERE state IN ('claimed','submitting','submitted')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 6);
    let plan = explain_queue(&db, *account).await;
    validate_sparse_history_plan(&plan).unwrap_or_else(|reason| panic!("{reason}: {plan}"));
    // The two categories are capped independently; final/uncertain states do
    // not contribute. A revoked device retains its observed state counts.
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('in-flight-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'submitted',now() FROM generate_series(1,100000) g", &[account, device]).await.unwrap();
    db.execute("UPDATE devices SET revoked_at=now() WHERE id=$1", &[device])
        .await
        .unwrap();
    let capped = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(capped["devices"][0]["pending_messages"], 3);
    assert_eq!(capped["devices"][0]["in_flight_messages"], 1_000);
    assert_eq!(capped["devices"][0]["revoked"], true);
    db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) SELECT md5('pending-'||g)::uuid,$1,$2,'+15551234567',decode(repeat('11',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('22',32),'hex'),'queued',now() FROM generate_series(1,100000) g", &[account, device]).await.unwrap();
    let both_capped = json_response(app.clone().oneshot(get()).await.unwrap()).await;
    assert_eq!(both_capped["devices"][0]["pending_messages"], 1_000);
    assert_eq!(both_capped["devices"][0]["in_flight_messages"], 1_000);
    db.batch_execute("ANALYZE messages").await.unwrap();
    let capped_plan = explain_queue(&db, *account).await;
    validate_queue_plan(&capped_plan, &[1_000.0, 1_000.0])
        .unwrap_or_else(|reason| panic!("{reason}: {capped_plan}"));
    let other = &owners[1].2;
    let page = json_response(
        app.clone()
            .oneshot(request(
                Method::GET,
                "/devices",
                json!({}),
                Some((&other.token, &other.csrf_token)),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(page["devices"][0]["pending_messages"], 3);
    assert_eq!(page["devices"][0]["in_flight_messages"], 2);
    db.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1",
        &[account],
    )
    .await
    .unwrap();
    assert_eq!(
        app.oneshot(get()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}

// Compile-time SQL keeps the fixture independent of runtime file content. The
// separate inventory assertion makes newly added migrations fail closed until
// this explicit list is updated.
macro_rules! queue_schema {
    ($($name:literal),+ $(,)?) => {
        [$(($name, include_str!(concat!("../../../../deploy/compose/migrations/", $name)))),+]
    };
}
const QUEUE_SCHEMA: [(&str, &str); 77] = queue_schema!(
    "001_foundation.sql",
    "002_auth.sql",
    "003_delivery.sql",
    "004_enrollment.sql",
    "005_verification_outbox.sql",
    "006_usage_metering.sql",
    "007_inbound_webhook_foundation.sql",
    "008_stripe_billing_foundation.sql",
    "009_webhook_manual_replay.sql",
    "010_billing_test_entitlement.sql",
    "011_billing_payment_holds.sql",
    "012_auth_abuse_limits.sql",
    "013_owner_mfa.sql",
    "014_owner_mfa_failure_budget.sql",
    "015_webhook_kek_commitments.sql",
    "016_auth_abuse_atomic.sql",
    "017_billing_device_caps.sql",
    "018_sealed_inbound_identity.sql",
    "019_line_activation_contract.sql",
    "020_enrollment_retention_indexes.sql",
    "021_billing_payment_grace.sql",
    "022_pending_owner_expiry.sql",
    "023_billing_py_charge_and_unsupported.sql",
    "024_billing_risk_operator_review.sql",
    "025_account_recovery.sql",
    "026_data_retention.sql",
    "027_billing_test_config.sql",
    "028_billing_provider_failures.sql",
    "029_webhook_dispatch_fairness.sql",
    "030_terminal_dispatch_jobs.sql",
    "031_recipient_suppression.sql",
    "032_line_opt_out_events.sql",
    "033_sms_line_binding_scope.sql",
    "034_delivery_sweep_index.sql",
    "035_sms_owner_key_ceremony.sql",
    "036_owner_opt_out_holds.sql",
    "037_sms_line_activation_exchange.sql",
    "038_owner_opt_out_hold_guards.sql",
    "039_inbound_device_clock_offset.sql",
    "040_radio_evidence_index.sql",
    "041_device_preconditions.sql",
    "042_sealed_manifest_authority.sql",
    "043_sealed_candidate_inbound.sql",
    "044_sealed_root_role_reservations.sql",
    "045_sealed_outbound_queue.sql",
    "046_sealed_root_ceremonies.sql",
    "047_device_network_service.sql",
    "048_observer_memberships.sql",
    "049_owner_queue_probe_indexes.sql",
    "050_message_attempts_recent_index.sql",
    "051_failover_controller_state.sql",
    "052_admission_pending_index.sql",
    "053_observer_seat_invitations.sql",
    "054_stateless_device_challenges.sql",
    "055_trusted_browser_epoch.sql",
    "056_usage_limit_plans.sql",
    "057_webhook_history_index.sql",
    "058_drop_abuse_counters_updated_index.sql",
    "059_erasure_fk_indexes.sql",
    "060_optout_review_indexes.sql",
    "061_inbound_events_attempt_fk_index.sql",
    "062_pending_recipient_index.sql",
    "063_retention_blocked_stamp.sql",
    "064_owner_conversation_consent.sql",
    "065_conversation_activation.sql",
    "066_conversation_interval_session_index.sql",
    "067_contacts_consent.sql",
    "068_connector_registration.sql",
    "069_sealed_root_custody.sql",
    "070_message_summary_metadata.sql",
    "071_sealed_grant_authority.sql",
    "072_conversation_confirmation_records.sql",
    "073_collaboration_drafts.sql",
    "074_agent_authority.sql",
    "075_workflow_context.sql",
    "076_workflow_decisions.sql",
    "077_encrypted_schedule.sql",
);
#[test]
fn queue_fixture_includes_every_checked_in_migration() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut names = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, QUEUE_SCHEMA.map(|(name, _)| name));
}

// Exercise production index choices, including online preparation.
async fn apply_queue_schema(db: &Client) {
    for (name, sql) in QUEUE_SCHEMA {
        if name == "070_message_summary_metadata.sql" {
            db.batch_execute("CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')").await.unwrap();
            db.batch_execute("BEGIN").await.unwrap();
            let result = db.batch_execute(sql).await;
            db.batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
            result.unwrap();
            continue;
        }
        match name {
            "034_delivery_sweep_index.sql" => {
                db.batch_execute("CREATE INDEX messages_in_flight_updated ON messages(updated_at,id) WHERE state IN ('claimed','submitting','submitted')").await.unwrap();
            }
            "040_radio_evidence_index.sql" => {
                db.batch_execute("CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code)").await.unwrap();
            }
            "049_owner_queue_probe_indexes.sql" => {
                db.batch_execute("CREATE INDEX messages_owner_pending_state ON messages(device_id,state,created_at) WHERE state IN ('accepted','queued','claimed')").await.unwrap();
                db.batch_execute("CREATE INDEX messages_owner_in_flight_state ON messages(device_id,state,created_at) WHERE state IN ('submitting','submitted')").await.unwrap();
            }
            "052_admission_pending_index.sql" => {
                db.batch_execute("CREATE INDEX messages_admission_pending ON messages(account_id,device_id) WHERE state IN ('queued','claimed')").await.unwrap();
            }
            "057_webhook_history_index.sql" => {
                db.batch_execute("CREATE INDEX webhook_deliveries_history ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)").await.unwrap();
            }
            "058_drop_abuse_counters_updated_index.sql" => {
                db.batch_execute("DROP INDEX IF EXISTS auth_abuse_counters_stale")
                    .await
                    .unwrap();
            }
            "059_erasure_fk_indexes.sql" => {
                db.batch_execute("CREATE INDEX erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id); CREATE INDEX erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id); CREATE INDEX erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id); CREATE INDEX erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL; CREATE INDEX erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL").await.unwrap();
            }
            "060_optout_review_indexes.sql" => {
                db.batch_execute("CREATE INDEX CONCURRENTLY recipient_suppressions_review_queue ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) WHERE active AND source IN ('sms_review','sms_unsolicited_review')").await.unwrap();
                db.batch_execute("CREATE INDEX CONCURRENTLY recipient_suppressions_review_event ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) WHERE source IN ('sms_review','sms_unsolicited_review')").await.unwrap();
                db.batch_execute("DROP INDEX IF EXISTS recipient_suppressions_active")
                    .await
                    .unwrap();
            }
            "061_inbound_events_attempt_fk_index.sql" => {
                db.batch_execute("CREATE INDEX CONCURRENTLY erasure_fk_inbound_events_attempt ON inbound_events(account_id,device_id,message_id,attempt_id)").await.unwrap();
            }
            "062_pending_recipient_index.sql" => {
                db.batch_execute("CREATE INDEX CONCURRENTLY messages_pending_recipient ON messages(recipient_e164,account_id) WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL").await.unwrap();
            }
            "066_conversation_interval_session_index.sql" => {
                db.batch_execute("CREATE INDEX CONCURRENTLY erasure_fk_conversation_interval_session ON conversation_intervals(account_id,initiating_session_id)").await.unwrap();
            }
            "050_message_attempts_recent_index.sql" => {
                db.batch_execute("CREATE INDEX message_attempts_device_created ON message_attempts(account_id,device_id,created_at)").await.unwrap();
            }
            _ => {}
        }
        db.batch_execute(sql).await.unwrap();
    }
}
