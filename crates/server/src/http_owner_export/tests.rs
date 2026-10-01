use super::*;
use crate::auth::{login, register, verify_email};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::Value;
use tower::ServiceExt;
use zeroize::Zeroizing;

fn get(path: &str, session: Option<&crate::auth::SessionCredentials>) -> Request<Body> {
    let mut request = Request::builder().uri(path);
    if let Some(session) = session {
        // Content-bearing owner reads need the CSRF header, not Origin.
        request = request
            .header(
                header::COOKIE,
                format!(
                    "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                    session.token, session.csrf_token
                ),
            )
            .header("x-zrotext-csrf", &session.csrf_token);
    }
    request.body(Body::empty()).unwrap()
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

// The takeout must survive every schema change that affects message
// content: nullable content columns (026) and binary sealed payloads
// (045). Applying the full ordered chain keeps their dependencies intact.
macro_rules! export_schema {
        ($($name:literal),+ $(,)?) => {
            [$(($name, include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/compose/migrations/", $name)))),+]
        };
    }
const EXPORT_SCHEMA: [(&str, &str); 72] = export_schema!(
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
);
#[test]
fn export_schema_includes_every_checked_in_migration() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let count = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "sql"))
        .count();
    assert_eq!(
        count,
        EXPORT_SCHEMA.len(),
        "add the new migration to EXPORT_SCHEMA so the export test covers it"
    );
}

#[test]
fn text_payloads_export_as_utf8_and_binary_payloads_as_base64() {
    assert_eq!(
        encode_payload("synthetic_alpha", b"hello export".to_vec()),
        ("hello export".to_owned(), PayloadEncoding::Utf8)
    );
    assert_eq!(
        encode_payload("synthetic_alpha", vec![0xff, 0xfe, 0x00, 0x80]),
        ("//4AgA==".to_owned(), PayloadEncoding::Base64)
    );
    // Sealed envelopes are binary even when every byte happens to be ASCII.
    assert_eq!(
        encode_payload("sealed_candidate02", b"ZTSE".to_vec()),
        ("WlRTRQ==".to_owned(), PayloadEncoding::Base64)
    );
    assert_eq!(
        serde_json::to_string(&PayloadEncoding::Utf8).unwrap(),
        "\"utf8\""
    );
    assert_eq!(
        serde_json::to_string(&PayloadEncoding::Base64).unwrap(),
        "\"base64\""
    );
}

fn page_payload_index(item: &Value) -> usize {
    item["transport_payload"]
        .as_str()
        .unwrap()
        .strip_prefix("EXPORT_PAGE_A_")
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn export_is_tenant_bound_and_carries_owner_content() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_export_test_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in EXPORT_SCHEMA {
        if name == "070_message_summary_metadata.sql" {
            db.batch_execute("CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')").await.unwrap();
            db.batch_execute("BEGIN").await.unwrap();
            let result = db.batch_execute(migration).await;
            db.batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
            result.unwrap();
            continue;
        }
        // CREATE INDEX CONCURRENTLY cannot run inside 034/040's own
        // transactional file, so the real migrator builds each index on
        // an autocommit connection before applying the file that only
        // validates its shape (crates/migrator/src/lib.rs). Mirror that
        // out-of-band preparation here or the validation DO block in
        // these two files raises "... is absent, invalid, or has the
        // wrong definition" against a schema that never built the index.
        if name == "052_admission_pending_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_admission_pending \
                     ON messages(account_id,device_id) \
                     WHERE state IN ('queued','claimed')",
            )
            .await
            .unwrap();
        }
        if name == "057_webhook_history_index.sql" {
            db.batch_execute("CREATE INDEX CONCURRENTLY webhook_deliveries_history ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)")
                .await
                .unwrap();
        }
        if name == "058_drop_abuse_counters_updated_index.sql" {
            db.batch_execute("DROP INDEX IF EXISTS auth_abuse_counters_stale")
                .await
                .unwrap();
        }
        if name == "059_erasure_fk_indexes.sql" {
            db.batch_execute("CREATE INDEX erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id); CREATE INDEX erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id); CREATE INDEX erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id); CREATE INDEX erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL; CREATE INDEX erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL")
                .await
                .unwrap();
        }
        if name == "060_optout_review_indexes.sql" {
            db.batch_execute("CREATE INDEX recipient_suppressions_review_queue ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) WHERE active AND source IN ('sms_review','sms_unsolicited_review')")
                .await
                .unwrap();
            db.batch_execute("CREATE INDEX recipient_suppressions_review_event ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) WHERE source IN ('sms_review','sms_unsolicited_review')")
                .await
                .unwrap();
            db.batch_execute("DROP INDEX IF EXISTS recipient_suppressions_active")
                .await
                .unwrap();
        }
        if name == "061_inbound_events_attempt_fk_index.sql" {
            db.batch_execute("CREATE INDEX erasure_fk_inbound_events_attempt ON inbound_events(account_id,device_id,message_id,attempt_id)")
                .await
                .unwrap();
        }
        if name == "062_pending_recipient_index.sql" {
            db.batch_execute("CREATE INDEX messages_pending_recipient ON messages(recipient_e164,account_id) WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL")
                .await
                .unwrap();
        }
        if name == "034_delivery_sweep_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                     ON messages(updated_at,id) \
                     WHERE state IN ('claimed','submitting','submitted')",
            )
            .await
            .unwrap();
        }
        if name == "040_radio_evidence_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY message_events_attempt_evidence \
                 ON message_events(attempt_id,evidence_code)",
            )
            .await
            .unwrap();
        }
        if name == "066_conversation_interval_session_index.sql" {
            db.batch_execute("CREATE INDEX erasure_fk_conversation_interval_session ON conversation_intervals(account_id,initiating_session_id)")
                .await
                .unwrap();
        }
        if name == "049_owner_queue_probe_indexes.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_owner_pending_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('accepted','queued','claimed')",
            )
            .await
            .unwrap();
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('submitting','submitted')",
            )
            .await
            .unwrap();
        }
        if name == "050_message_attempts_recent_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY message_attempts_device_created \
                 ON message_attempts(account_id,device_id,created_at)",
            )
            .await
            .unwrap();
        }
        db.batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(19)).unwrap());
    let a = register(
        &mut db,
        &hasher,
        "export-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let b = register(
        &mut db,
        &hasher,
        "export-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap();
    verify_email(&mut db, &hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &b.verification_token)
        .await
        .unwrap();
    let session_a = login(
        &db,
        &hasher,
        "export-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let session_b = login(
        &db,
        &hasher,
        "export-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap();
    for index in 0..2 {
        let observer = Uuid::new_v4();
        db.execute("INSERT INTO users(id,email,password_hash,email_verified_at) SELECT $1,$2,password_hash,now() FROM users WHERE id=$3", &[&observer, &format!("export-observer-{index}@example.test"), &a.user_id]).await.unwrap();
        db.execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&a.account_id, &observer],
        )
        .await
        .unwrap();
    }
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Exporter'),($3,$4,'Other')",
        &[&device_a, &a.account_id, &device_b, &b.account_id],
    )
    .await
    .unwrap();
    let mut a_ids = Vec::new();
    for index in 0..2 {
        let id = Uuid::new_v4();
        a_ids.push(id);
        db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
                &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                    &format!("EXPORT_BODY_A_{index}").as_bytes().to_vec(), &vec![2_u8; 32],
                    &if index == 0 { "delivered" } else { "queued" }],
            )
            .await
            .unwrap();
    }
    let b_id = Uuid::new_v4();
    db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour')",
            &[&b_id, &b.account_id, &device_b, &vec![3_u8; 32],
                &b"EXPORT_BODY_B_NEVER_LEAK".as_slice(), &vec![4_u8; 32]],
        )
        .await
        .unwrap();
    // A terminal message whose content the retention worker already
    // nulled (migration 026 semantics) must not break the takeout.
    let scrubbed_id = Uuid::new_v4();
    db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,NULL,$4,'synthetic_alpha',NULL,$5,'delivered',now()+interval '1 hour')",
            &[&scrubbed_id, &a.account_id, &device_a, &vec![6_u8; 32], &vec![7_u8; 32]],
        )
        .await
        .unwrap();
    // A queued sealed candidate carries a binary envelope that is not
    // valid UTF-8 (migration 045 semantics).
    let line = Uuid::new_v4();
    db.execute(
        "INSERT INTO phone_lines(id,account_id) VALUES($1,$2)",
        &[&line, &a.account_id],
    )
    .await
    .unwrap();
    db.execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation) VALUES($1,$2,$3,1)",
            &[&a.account_id, &line, &device_a],
        )
        .await
        .unwrap();
    let mut sealed_envelope = b"ZTSE\x02\x01".to_vec();
    sealed_envelope.resize(426, 0xff);
    let sealed_id = Uuid::new_v4();
    db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at, \
             sealed_line_id,sealed_binding_generation,sealed_manifest_generation,sealed_manifest_version,sealed_manifest_digest,sealed_signer_key_id) \
             VALUES($1,$2,$3,'+15551234567',$4,'sealed_candidate02',$5,$6,'queued',now()+interval '1 hour',$7,1,1,1,$8,$9)",
            &[&sealed_id, &a.account_id, &device_a, &vec![8_u8; 32], &sealed_envelope,
                &vec![9_u8; 32], &line, &vec![10_u8; 32], &vec![11_u8; 32]],
        )
        .await
        .unwrap();
    let attempt = Uuid::new_v4();
    db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES($1,$2,$3,$4,1,1,1,'submitted')",
            &[&attempt, &a.account_id, &a_ids[0], &device_a],
        )
        .await
        .unwrap();
    for (evidence, state) in [
        ("sent_callback_ok", "submitted"),
        ("delivery_callback_ok", "delivered"),
    ] {
        db.execute(
                "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
                 VALUES($1,$2,$3,$4,$5,$6,now(),$7,0,1)",
                &[&Uuid::new_v4(), &a.account_id, &a_ids[0], &attempt,
                    &evidence, &vec![5_u8; 32], &state],
            )
            .await
            .unwrap();
    }
    let app = router(OwnerExportState {
        database_url,
        auth_hasher: hasher,
        canonical_origin: "https://test.example".to_owned(),
        contacts_vault: Some(Arc::new(
            crate::http_owner_contacts::vault::ContactFieldVault::new(
                1,
                Zeroizing::new(vec![9_u8; 32]),
            )
            .unwrap(),
        )),
    });
    let anonymous = app
        .clone()
        .oneshot(get("/v1/owner/export", None))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(get("/v1/owner/export", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let raw = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let takeout: Value = serde_json::from_slice(&raw).unwrap();
    assert!(takeout["conversation_inventory"]["consent"].is_null());
    assert_eq!(
        takeout["conversation_inventory"]["sealed_events"],
        serde_json::json!([])
    );
    assert_eq!(
        takeout["conversation_inventory"]["sealed_events_truncated"],
        false
    );
    assert!(takeout["conversation_inventory"]["sealed_events_next_cursor"].is_null());
    let unknown_sealed = app
        .clone()
        .oneshot(get(
            &format!("/v1/owner/export?sealed_before={}", Uuid::new_v4()),
            Some(&session_a),
        ))
        .await
        .unwrap();
    assert_eq!(unknown_sealed.status(), StatusCode::NOT_FOUND);
    assert_eq!(unknown_sealed.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(takeout["account"]["account_id"], a.account_id.to_string());
    assert_eq!(takeout["account"]["email"], "export-a@example.test");
    assert_eq!(takeout["account"]["email_verified"], true);
    assert_eq!(takeout["devices"].as_array().unwrap().len(), 1);
    assert_eq!(takeout["devices"][0]["device_id"], device_a.to_string());
    assert_eq!(takeout["devices"][0]["display_name"], "Exporter");
    assert_eq!(takeout["messages_truncated"], false);
    let messages = takeout["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 4);
    assert!(String::from_utf8_lossy(&raw).contains("EXPORT_BODY_A_0"));
    assert!(String::from_utf8_lossy(&raw).contains("EXPORT_BODY_A_1"));
    assert!(!String::from_utf8_lossy(&raw).contains("EXPORT_BODY_B_NEVER_LEAK"));
    assert!(!String::from_utf8_lossy(&raw).contains("+15557654321"));
    let delivered = messages
        .iter()
        .find(|item| item["message_id"] == a_ids[0].to_string())
        .unwrap();
    assert_eq!(delivered["state"], "delivered");
    assert_eq!(delivered["recipient_e164"], "+15551234567");
    assert_eq!(delivered["transport_mode"], "synthetic_alpha");
    assert_eq!(delivered["transport_payload"], "EXPORT_BODY_A_0");
    assert_eq!(delivered["payload_encoding"], "utf8");
    assert_eq!(delivered["content_scrubbed"], false);
    let events = delivered["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["evidence_code"], "sent_callback_ok");
    assert_eq!(events[0]["resulting_state"], "submitted");
    assert_eq!(events[1]["evidence_code"], "delivery_callback_ok");
    assert_eq!(events[1]["resulting_state"], "delivered");
    assert_eq!(events[0]["segment_count"], 1);
    let queued = messages
        .iter()
        .find(|item| item["message_id"] == a_ids[1].to_string())
        .unwrap();
    assert_eq!(queued["state"], "queued");
    assert_eq!(
        queued["events"].as_array().unwrap().len(),
        0,
        "message without events exports an empty event list"
    );
    let scrubbed = messages
        .iter()
        .find(|item| item["message_id"] == scrubbed_id.to_string())
        .unwrap();
    assert_eq!(scrubbed["state"], "delivered");
    assert_eq!(scrubbed["recipient_e164"], Value::Null);
    assert_eq!(scrubbed["transport_payload"], Value::Null);
    assert_eq!(scrubbed["payload_encoding"], Value::Null);
    assert_eq!(scrubbed["content_scrubbed"], true);
    let sealed = messages
        .iter()
        .find(|item| item["message_id"] == sealed_id.to_string())
        .unwrap();
    assert_eq!(sealed["transport_mode"], "sealed_candidate02");
    assert_eq!(sealed["content_scrubbed"], false);
    assert_eq!(sealed["payload_encoding"], "base64");
    assert_eq!(
        STANDARD
            .decode(sealed["transport_payload"].as_str().unwrap())
            .unwrap(),
        sealed_envelope
    );
    let foreign = app
        .clone()
        .oneshot(get("/v1/owner/export", Some(&session_b)))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::OK);
    let foreign = body(foreign).await;
    assert_eq!(foreign["account"]["email"], "export-b@example.test");
    let foreign_messages = foreign["messages"].as_array().unwrap();
    assert_eq!(foreign_messages.len(), 1);
    assert_eq!(foreign_messages[0]["message_id"], b_id.to_string());
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn export_paginates_full_history_beyond_the_first_page() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_export_page_test_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in [
        include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
        include_str!("../../../../deploy/compose/migrations/043_sealed_candidate_inbound.sql"),
        include_str!("../../../../deploy/compose/migrations/048_observer_memberships.sql"),
        include_str!("../../../../deploy/compose/migrations/064_owner_conversation_consent.sql"),
        include_str!("../../../../deploy/compose/migrations/065_conversation_activation.sql"),
        include_str!("../../../../deploy/compose/migrations/067_contacts_consent.sql"),
    ] {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(19)).unwrap());
    let a = register(
        &mut db,
        &hasher,
        "export-page-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let b = register(
        &mut db,
        &hasher,
        "export-page-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap();
    verify_email(&mut db, &hasher, &a.verification_token)
        .await
        .unwrap();
    let session_a = login(
        &db,
        &hasher,
        "export-page-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Pager'),($3,$4,'Other')",
        &[&device_a, &a.account_id, &device_b, &b.account_id],
    )
    .await
    .unwrap();
    let total = EXPORT_MESSAGE_LIMIT + 5;
    let a_ids: Vec<_> = (0..total).map(|_| Uuid::new_v4()).collect();
    // Timestamp order must not depend on insertion order or database clock
    // adjustments. Reverse insertion also exercises that distinction.
    for index in (0..total).rev() {
        let id = a_ids[index];
        let created_at_offset = i64::try_from(index).unwrap();
        db.execute(
                "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at,created_at) \
                 VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour', \
                        TIMESTAMPTZ '2000-01-01 00:00:00+00' + $7::bigint * interval '1 second')",
                &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                    &format!("EXPORT_PAGE_A_{index}").as_bytes().to_vec(), &vec![2_u8; 32],
                    &created_at_offset],
            )
            .await
            .unwrap();
    }
    let b_id = Uuid::new_v4();
    db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour')",
            &[&b_id, &b.account_id, &device_b, &vec![3_u8; 32],
                &b"EXPORT_PAGE_B_NEVER_LEAK".as_slice(), &vec![4_u8; 32]],
        )
        .await
        .unwrap();
    let attempt = Uuid::new_v4();
    db.execute(
            "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES($1,$2,$3,$4,1,1,1,'submitted')",
            &[&attempt, &a.account_id, &a_ids[0], &device_a],
        )
        .await
        .unwrap();
    db.execute(
            "INSERT INTO message_events(id,account_id,message_id,attempt_id,evidence_code,event_digest,observed_at,resulting_state,segment_index,segment_count) \
             VALUES($1,$2,$3,$4,$5,$6,now(),$7,0,1)",
            &[&Uuid::new_v4(), &a.account_id, &a_ids[0], &attempt,
                &"sent_callback_ok", &vec![5_u8; 32], &"submitted"],
        )
        .await
        .unwrap();
    let app = router(OwnerExportState {
        database_url,
        auth_hasher: hasher,
        canonical_origin: "https://test.example".to_owned(),
        contacts_vault: Some(Arc::new(
            crate::http_owner_contacts::vault::ContactFieldVault::new(
                1,
                Zeroizing::new(vec![9_u8; 32]),
            )
            .unwrap(),
        )),
    });
    let first = body(
        app.clone()
            .oneshot(get("/v1/owner/export", Some(&session_a)))
            .await
            .unwrap(),
    )
    .await;
    let first_messages = first["messages"].as_array().unwrap();
    assert_eq!(first_messages.len(), EXPORT_MESSAGE_LIMIT);
    assert_eq!(first["messages_truncated"], true);
    assert!(!first["next_cursor"].is_null());
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    assert_eq!(
        cursor,
        first_messages[EXPORT_MESSAGE_LIMIT - 1]["message_id"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        first_messages[0]["transport_payload"],
        format!("EXPORT_PAGE_A_{}", total - 1)
    );
    assert_eq!(
        first_messages[EXPORT_MESSAGE_LIMIT - 1]["transport_payload"],
        format!("EXPORT_PAGE_A_{}", total - EXPORT_MESSAGE_LIMIT)
    );
    let first_text = serde_json::to_string(&first).unwrap();
    assert!(!first_text.contains("EXPORT_PAGE_B"));
    let second = body(
        app.clone()
            .oneshot(get(
                &format!("/v1/owner/export?before={cursor}"),
                Some(&session_a),
            ))
            .await
            .unwrap(),
    )
    .await;
    let second_messages = second["messages"].as_array().unwrap();
    let remainder = total - EXPORT_MESSAGE_LIMIT;
    assert_eq!(second_messages.len(), remainder);
    assert_eq!(second["messages_truncated"], false);
    assert!(second["next_cursor"].is_null());
    assert_eq!(second["account"]["account_id"], a.account_id.to_string());
    assert_eq!(second["devices"].as_array().unwrap().len(), 1);
    assert_eq!(
        second_messages[0]["transport_payload"],
        format!("EXPORT_PAGE_A_{}", remainder - 1)
    );
    assert_eq!(
        second_messages[remainder - 1]["transport_payload"],
        "EXPORT_PAGE_A_0"
    );
    let oldest = &second_messages[remainder - 1];
    assert_eq!(oldest["message_id"], a_ids[0].to_string());
    let events = oldest["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["evidence_code"], "sent_callback_ok");
    assert_eq!(events[0]["resulting_state"], "submitted");
    let combined: Vec<&Value> = first_messages
        .iter()
        .chain(second_messages.iter())
        .collect();
    let indices: Vec<usize> = combined
        .iter()
        .map(|item| page_payload_index(item))
        .collect();
    assert!(
        indices.windows(2).all(|pair| pair[0] > pair[1]),
        "both pages come back newest-first: {indices:?}"
    );
    let seen: std::collections::HashSet<&str> = combined
        .iter()
        .map(|item| item["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(seen.len(), total);
    for id in &a_ids {
        assert!(seen.contains(id.to_string().as_str()));
    }
    let foreign = app
        .clone()
        .oneshot(get(
            &format!("/v1/owner/export?before={b_id}"),
            Some(&session_a),
        ))
        .await
        .unwrap();
    assert_eq!(foreign.status(), StatusCode::NOT_FOUND);
    let unknown = app
        .clone()
        .oneshot(get(
            &format!("/v1/owner/export?before={}", Uuid::new_v4()),
            Some(&session_a),
        ))
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn export_carries_contacts_with_consent_history_and_never_foreign_rows() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_export_contacts_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in EXPORT_SCHEMA {
        if name == "070_message_summary_metadata.sql" {
            db.batch_execute("CREATE INDEX CONCURRENTLY messages_summary_queue ON messages(account_id,state,created_at) WHERE state IN ('accepted','queued','claimed','submitting','submitted')").await.unwrap();
            db.batch_execute("BEGIN").await.unwrap();
            let result = db.batch_execute(migration).await;
            db.batch_execute(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                .await
                .unwrap();
            result.unwrap();
            continue;
        }
        if name == "034_delivery_sweep_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                 ON messages(updated_at,id) \
                 WHERE state IN ('claimed','submitting','submitted')",
            )
            .await
            .unwrap();
        }
        if name == "040_radio_evidence_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY message_events_attempt_evidence \
                 ON message_events(attempt_id,evidence_code)",
            )
            .await
            .unwrap();
        }
        if name == "049_owner_queue_probe_indexes.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_owner_pending_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('accepted','queued','claimed')",
            )
            .await
            .unwrap();
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state \
                 ON messages(device_id,state,created_at) \
                 WHERE state IN ('submitting','submitted')",
            )
            .await
            .unwrap();
        }
        if name == "050_message_attempts_recent_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY message_attempts_device_created \
                 ON message_attempts(account_id,device_id,created_at)",
            )
            .await
            .unwrap();
        }
        if name == "052_admission_pending_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_admission_pending \
                 ON messages(account_id,device_id) \
                 WHERE state IN ('queued','claimed')",
            )
            .await
            .unwrap();
        }
        if name == "057_webhook_history_index.sql" {
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY webhook_deliveries_history \
                 ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)",
            )
            .await
            .unwrap();
        }
        if name == "058_drop_abuse_counters_updated_index.sql" {
            db.batch_execute("DROP INDEX IF EXISTS auth_abuse_counters_stale")
                .await
                .unwrap();
        }
        if name == "059_erasure_fk_indexes.sql" {
            db.batch_execute(
                "CREATE INDEX erasure_fk_webhook_deliveries_event ON webhook_deliveries(account_id,event_id); \
                 CREATE INDEX erasure_fk_suppressions_attempt ON recipient_suppressions(source_attempt_id); \
                 CREATE INDEX erasure_fk_suppressions_event ON recipient_suppressions(account_id,source_event_id); \
                 CREATE INDEX erasure_fk_holds_release_event ON owner_recipient_holds(account_id,release_event_id) WHERE release_event_id IS NOT NULL; \
                 CREATE INDEX erasure_fk_opt_out_audit_release_event ON owner_opt_out_audit(account_id,release_event_id) WHERE release_event_id IS NOT NULL",
            )
            .await
            .unwrap();
        }
        if name == "060_optout_review_indexes.sql" {
            db.batch_execute(
                "CREATE INDEX recipient_suppressions_review_queue \
                 ON recipient_suppressions(account_id,changed_at DESC,recipient_e164 DESC) \
                 WHERE active AND source IN ('sms_review','sms_unsolicited_review')",
            )
            .await
            .unwrap();
            db.batch_execute(
                "CREATE INDEX recipient_suppressions_review_event \
                 ON recipient_suppressions(account_id,COALESCE(source_event_id,source_unsolicited_event_id)) \
                 WHERE source IN ('sms_review','sms_unsolicited_review')",
            )
            .await
            .unwrap();
            db.batch_execute("DROP INDEX IF EXISTS recipient_suppressions_active")
                .await
                .unwrap();
        }
        if name == "061_inbound_events_attempt_fk_index.sql" {
            db.batch_execute(
                "CREATE INDEX erasure_fk_inbound_events_attempt \
                 ON inbound_events(account_id,device_id,message_id,attempt_id)",
            )
            .await
            .unwrap();
        }
        if name == "062_pending_recipient_index.sql" {
            db.batch_execute(
                "CREATE INDEX messages_pending_recipient \
                 ON messages(recipient_e164,account_id) \
                 WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL",
            )
            .await
            .unwrap();
        }
        if name == "066_conversation_interval_session_index.sql" {
            db.batch_execute(
                "CREATE INDEX erasure_fk_conversation_interval_session \
                 ON conversation_intervals(account_id,initiating_session_id)",
            )
            .await
            .unwrap();
        }
        db.batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(41)).unwrap());
    let a = register(
        &mut db,
        &hasher,
        "export-contacts-a@example.test",
        &crate::test_keys::password(7),
    )
    .await
    .unwrap();
    let b = register(
        &mut db,
        &hasher,
        "export-contacts-b@example.test",
        &crate::test_keys::password(8),
    )
    .await
    .unwrap();
    verify_email(&mut db, &hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &b.verification_token)
        .await
        .unwrap();
    let session_a = login(
        &db,
        &hasher,
        "export-contacts-a@example.test",
        &crate::test_keys::password(7),
    )
    .await
    .unwrap();

    let vault = crate::http_owner_contacts::vault::ContactFieldVault::new(
        1,
        Zeroizing::new(vec![9_u8; 32]),
    )
    .unwrap();
    let contact = Uuid::new_v4();
    let name_ciphertext = vault
        .seal(
            a.account_id,
            contact,
            crate::http_owner_contacts::vault::ContactField::DisplayName,
            b"Ada Lovelace",
        )
        .unwrap();
    let notes_ciphertext = vault
        .seal(
            a.account_id,
            contact,
            crate::http_owner_contacts::vault::ContactField::Notes,
            b"prefers morning",
        )
        .unwrap();
    db.execute(
        "INSERT INTO contacts(id,account_id,recipient_e164,display_name_ciphertext,notes_ciphertext) \
         VALUES($1,$2,'+15550100001',$3,$4)",
        &[&contact, &a.account_id, &name_ciphertext, &notes_ciphertext],
    )
    .await
    .unwrap();
    let foreign = Uuid::new_v4();
    db.execute(
        "INSERT INTO contacts(id,account_id,recipient_e164) VALUES($1,$2,'+15550100002')",
        &[&foreign, &b.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO contact_consent_records \
         (id,account_id,contact_id,purpose,action,source,effective_at,expires_at,recorded_by) \
         SELECT $1::uuid,$2::uuid,$3::uuid,'marketing','grant','manual_entry', \
         now()-interval '1 hour',now()+interval '30 days',$4::uuid \
         UNION ALL SELECT $5::uuid,$2::uuid,$3::uuid,'marketing','withdraw', \
         'off_channel_record',now()-interval '30 minutes',NULL,$4::uuid",
        &[
            &Uuid::new_v4(),
            &a.account_id,
            &contact,
            &a.user_id,
            &Uuid::new_v4(),
        ],
    )
    .await
    .unwrap();

    let app = router(OwnerExportState {
        database_url,
        auth_hasher: hasher.clone(),
        canonical_origin: "https://test.example".to_owned(),
        contacts_vault: Some(Arc::new(vault)),
    });
    let response = app
        .clone()
        .oneshot(get("/v1/owner/export", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    let contacts: Vec<Value> = serde_json::from_value(report["contacts"].clone()).unwrap();
    assert_eq!(contacts.len(), 1, "the other account's contact never leaks");
    assert_eq!(contacts[0]["contact_id"], contact.to_string());
    assert_eq!(contacts[0]["recipient_e164"], "+15550100001");
    assert_eq!(contacts[0]["display_name"], "Ada Lovelace");
    assert_eq!(contacts[0]["notes"], "prefers morning");
    let states: Vec<Value> = serde_json::from_value(contacts[0]["consents"].clone()).unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0]["purpose"], "marketing");
    assert_eq!(states[0]["status"], "withdrawn");
    let history: Vec<Value> =
        serde_json::from_value(contacts[0]["consent_history"].clone()).unwrap();
    assert_eq!(history.len(), 2, "the whole consent history exports");
    assert_eq!(report["contacts_truncated"], false);
    assert_eq!(report["contacts_next_cursor"], Value::Null);

    // A vault that cannot open the stored ciphertext fails the export
    // closed instead of shipping unreadable fields. Only the key differs;
    // the session hasher stays the one that signed the login.
    let rekeyed = router(OwnerExportState {
        database_url: format!("{base_url}{separator}options=-csearch_path%3D{schema}"),
        auth_hasher: hasher,
        canonical_origin: "https://test.example".to_owned(),
        contacts_vault: Some(Arc::new(
            crate::http_owner_contacts::vault::ContactFieldVault::new(
                2,
                Zeroizing::new(vec![8_u8; 32]),
            )
            .unwrap(),
        )),
    });
    let response = rekeyed
        .oneshot(get("/v1/owner/export", Some(&session_a)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
