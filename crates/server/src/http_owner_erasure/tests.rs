// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL-backed tests for the owner erasure route, plus one
//! repository-SQL proof that the runtime database role covers every table
//! the erasure deletes. The ignored tests share the fixture style of the
//! sibling owner/auth suites: a throwaway schema, the real migration files,
//! and the router under test driven through `tower::ServiceExt`.

use super::*;
use crate::auth::{authenticate_session, login, register, verify_email};
use axum::body::{Body, to_bytes};
use serde_json::{Value, json};
use totp_rs::{Builder, Secret};
use tower::ServiceExt;

const ORIGIN: &str = "https://test.example";

/// The complete, ordered migration set from deploy/compose/migrations, as
/// the Compose runner applies it to a fresh database. Nothing is skipped:
/// the erasure's blocked-table and delete plans must stay honest against the
/// schema production actually runs.
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
        "053_observer_seat_invitations.sql",
        include_str!("../../../../deploy/compose/migrations/053_observer_seat_invitations.sql"),
    ),
];

/// Indexes the Compose migrator prepares with CREATE INDEX CONCURRENTLY in
/// autocommit mode before the numbered 034, 040, 049 and 050 files record their
/// checksum gates (deploy/compose/README.md, "Migration 034 is a narrow
/// online-index exception"). The gate SQL validates the exact index
/// definition; a fresh fixture schema builds the identical index with a
/// plain CREATE INDEX, which differs only in not being concurrent.
const PREPARED_INDEXES: &[(&str, &str)] = &[
    (
        "034_delivery_sweep_index.sql",
        "CREATE INDEX messages_in_flight_updated ON messages(updated_at,id) \
         WHERE state = ANY (ARRAY['claimed','submitting','submitted'])",
    ),
    (
        "040_radio_evidence_index.sql",
        "CREATE INDEX message_events_attempt_evidence ON message_events(attempt_id,evidence_code)",
    ),
    (
        "049_owner_queue_probe_indexes.sql",
        "CREATE INDEX messages_owner_pending_state ON messages(device_id,state,created_at) \
         WHERE state IN ('accepted','queued','claimed'); \
         CREATE INDEX messages_owner_in_flight_state ON messages(device_id,state,created_at) \
         WHERE state IN ('submitting','submitted')",
    ),
    (
        "050_message_attempts_recent_index.sql",
        "CREATE INDEX message_attempts_device_created ON message_attempts(account_id,device_id,created_at)",
    ),
];

/// A migrated schema plus its admin connection for teardown. Mirrors the
/// sibling owner/auth PostgreSQL tests.
async fn migrated_schema(
    label: &str,
) -> (
    tokio_postgres::Client,
    tokio_postgres::Client,
    String,
    String,
) {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_erasure_{label}_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (file, migration) in MIGRATIONS {
        if let Some((_, index)) = PREPARED_INDEXES.iter().find(|(gate, _)| gate == file) {
            db.batch_execute(index).await.unwrap();
        }
        db.batch_execute(migration).await.unwrap();
    }
    (admin, db, database_url, schema)
}

fn erasure_post(
    session: Option<&str>,
    csrf: Option<&str>,
    origin: Option<&str>,
    password: &str,
    code: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/owner/erasure")
        .header(axum::http::header::CONTENT_TYPE, "application/json");
    if let Some(token) = session {
        request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
    }
    if let Some(token) = csrf {
        request = request.header(header::COOKIE, format!("__Host-zrotext_csrf={token}"));
        request = request.header("x-zrotext-csrf", token);
    }
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let mut payload = json!({ "current_password": password });
    if let Some(code) = code {
        payload["code"] = json!(code);
    }
    request.body(Body::from(payload.to_string())).unwrap()
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

fn deleted_count(report: &Value, table: &str) -> u64 {
    report["deleted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["table"] == table)
        .unwrap_or_else(|| panic!("{table} missing from the deleted list"))["rows"]
        .as_u64()
        .unwrap()
}

fn blocked_count(report: &Value, table: &str) -> u64 {
    report["blocked"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["table"] == table)
        .unwrap_or_else(|| panic!("{table} missing from the blocked list"))["rows"]
        .as_u64()
        .unwrap()
}

/// Two accounts carrying delivery, enrollment, metering, webhook,
/// billing and account-recovery fixtures. Returns both signups, both
/// sessions and the hasher-backed router under test. Neither account
/// carries enrolled device keys or their auth challenges: migration 044
/// records immutable signing trust history for every enrolled key, which
/// blocks erasure (proven by `sealed_trust_history_blocks_erasure`), so
/// this erasable fixture models accounts without that history.
async fn fixture(
    db: &mut tokio_postgres::Client,
    hasher: &Arc<TokenHasher>,
    database_url: &str,
    mfa_cipher: Option<Arc<mfa::MfaCipher>>,
) -> (
    crate::auth::Signup,
    crate::auth::SessionCredentials,
    crate::auth::Signup,
    crate::auth::SessionCredentials,
    Router,
) {
    let a = register(
        db,
        hasher,
        "erase-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let b = register(
        db,
        hasher,
        "erase-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap();
    verify_email(db, hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(db, hasher, &b.verification_token)
        .await
        .unwrap();
    let session_a = login(
        db,
        hasher,
        "erase-a@example.test",
        &crate::test_keys::password(1),
    )
    .await
    .unwrap();
    let session_b = login(
        db,
        hasher,
        "erase-b@example.test",
        &crate::test_keys::password(2),
    )
    .await
    .unwrap();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    db.execute("INSERT INTO sites(site_id) VALUES('erasure-site')", &[])
        .await
        .unwrap();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) \
         VALUES($1,$2,'Erasure probe'),($3,$4,'Isolation probe')",
        &[&device_a, &a.account_id, &device_b, &b.account_id],
    )
    .await
    .unwrap();
    // One device-reported precondition row: the schema would cascade it from
    // the account, but the plan deletes it explicitly so its count is
    // reported.
    db.execute(
        "INSERT INTO device_preconditions(device_id,account_id,connection_epoch,deployment_epoch,selected_sim,sms_permission,airplane_mode) \
         VALUES($1,$2,1,1,'active','granted','disabled')",
        &[&device_a, &a.account_id],
    )
    .await
    .unwrap();
    let message_a0 = Uuid::new_v4();
    let message_a1 = Uuid::new_v4();
    for (id, state) in [(message_a0, "delivered"), (message_a1, "queued")] {
        db.execute(
            "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
             VALUES($1,$2,$3,'+15551234567',$4,'synthetic_alpha',$5,$6,$7,now()+interval '1 hour')",
            &[&id, &a.account_id, &device_a, &vec![1_u8; 32],
                &b"ERASE_A_BODY".to_vec(), &vec![2_u8; 32], &state],
        )
        .await
        .unwrap();
    }
    let message_b = Uuid::new_v4();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,'+15557654321',$4,'synthetic_alpha',$5,$6,'queued',now()+interval '1 hour')",
        &[&message_b, &b.account_id, &device_b, &vec![3_u8; 32],
            &b"KEEP_B_BODY".to_vec(), &vec![4_u8; 32]],
    )
    .await
    .unwrap();
    let attempt = Uuid::new_v4();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'submitted')",
        &[&attempt, &a.account_id, &message_a0, &device_a],
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
            &[&Uuid::new_v4(), &a.account_id, &message_a0, &attempt,
                &evidence, &vec![5_u8; 32], &state],
        )
        .await
        .unwrap();
    }
    db.execute(
        "INSERT INTO dispatch_jobs(message_id,account_id,device_id) VALUES($1,$2,$3)",
        &[&message_a0, &a.account_id, &device_a],
    )
    .await
    .unwrap();
    // The second fence is a pre-accounting legacy row: a NULL account_id
    // escapes the composite foreign keys, so it needs its own attempt and
    // is matched by the message/device arms of the delete. The alpha fence
    // guard from migration 045 rejects new NULL-account rows by design, so
    // this pre-existing row is inserted the way the inbound tests seed
    // guarded history: with that one trigger disabled for the insert.
    let legacy_attempt = Uuid::new_v4();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'failed')",
        &[&legacy_attempt, &a.account_id, &message_a1, &device_a],
    )
    .await
    .unwrap();
    db.batch_execute("ALTER TABLE dispatch_fences DISABLE TRIGGER alpha_fence_before_write")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO dispatch_fences(message_id,account_id,device_id,attempt_id,generation,session_epoch,deployment_epoch,grant_expires_at,outcome) \
         VALUES($1,$2,$3,$4,1,1,1,now(),'failed'),($5,NULL,$3,$6,1,1,1,now(),'failed')",
        &[&message_a0, &a.account_id, &device_a, &attempt, &message_a1,
            &legacy_attempt],
    )
    .await
    .unwrap();
    db.batch_execute("ALTER TABLE dispatch_fences ENABLE TRIGGER alpha_fence_before_write")
        .await
        .unwrap();
    db.execute(
        "INSERT INTO idempotency_keys(account_id,key,request_digest,message_id,expires_at) \
         VALUES($1,'erase-key',$2,$3,now()+interval '1 hour')",
        &[&a.account_id, &vec![6_u8; 32], &message_a0],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_sessions(device_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch,account_id) \
         VALUES($1,'erasure-site','erasure-instance',1,now()+interval '1 hour',1,NULL)",
        &[&device_a],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,expires_at) \
         VALUES($1,$2,$3,$4,'Erasure pairer',now()+interval '1 hour')",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![7_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes,bound_device_id) \
         VALUES($1,$2,$3,'erase-prefix',$4,ARRAY['messages:read'],$5)",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![11_u8; 32],
            &device_a],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units) \
         VALUES($1,'outbound_message',date_trunc('month',now())::date,(date_trunc('month',now())+interval '1 month')::date,10)",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO usage_quota_policies(account_id,metric,limit_units) \
         VALUES($1,'outbound_message',10)",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) \
         VALUES($1,$2,'outbound_message',date_trunc('month',now())::date,'reserve',1)",
        &[&a.account_id, &message_a0],
    )
    .await
    .unwrap();
    let endpoint = Uuid::new_v4();
    db.execute(
        "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) \
         VALUES($1,$2,'https://example.test/hooks',$3,1)",
        &[&endpoint, &a.account_id, &vec![12_u8; 32]],
    )
    .await
    .unwrap();
    let inbound = Uuid::new_v4();
    db.execute(
        "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,$5,1,'captured_local',now(),1,'metadata_only',$6,$7)",
        &[&inbound, &a.account_id, &device_a, &message_a0, &attempt,
            &vec![13_u8; 32], &vec![14_u8; 8]],
    )
    .await
    .unwrap();
    let delivery = Uuid::new_v4();
    db.execute(
        "INSERT INTO webhook_deliveries(id,account_id,endpoint_id,event_id,status) \
         VALUES($1,$2,$3,$4,'pending')",
        &[&delivery, &a.account_id, &endpoint, &inbound],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO webhook_attempts(id,delivery_id,attempt_number) VALUES($1,$2,1)",
        &[&Uuid::new_v4(), &delivery],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO webhook_replay_requests(account_id,request_id,delivery_id,generation) \
         VALUES($1,$2,$3,2)",
        &[&a.account_id, &Uuid::new_v4(), &delivery],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_event_id,source_attempt_id,source_observed_at,source) \
         VALUES($1,'+15559999999',true,$2,$3,now(),'sms_keyword')",
        &[&a.account_id, &inbound, &attempt],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_erasurefixture')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_events(stripe_event_id,event_type,stripe_customer_id,account_id,body_sha256,disposition) \
         VALUES('evt_erasurefixture','invoice.paid','cus_erasurefixture',$1,$2,'queued')",
        &[&a.account_id, &vec![15_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
         VALUES('evt_erasurefixture','ch_erasurefixture','refund',$1)",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_payment_holds(stripe_event_id,account_id,stripe_subscription_id,stripe_charge_id,reason) \
         VALUES('evt_erasurefixture',$1,'sub_erasurefixture','ch_erasurefixture','refund')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) \
         VALUES('sub_erasurefixture',$1,'cus_erasurefixture')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status) \
         VALUES('sub_erasurefixture',$1,'cus_erasurefixture','active')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_quota_audit(account_id,stripe_subscription_id,reconciliation_generation,limit_units,reason) \
         VALUES($1,'sub_erasurefixture',1,10,'active')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_device_caps(account_id,limit_devices) VALUES($1,2)",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_device_cap_audit(account_id,stripe_subscription_id,reconciliation_generation,limit_devices,reason) \
         VALUES($1,'sub_erasurefixture',1,2,'active')",
        &[&a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO password_resets(id,account_id,user_id,token_hash,expires_at) \
         VALUES($1,$2,$3,$4,now()+interval '1 hour')",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![16_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO password_reset_notice_outbox(id,account_id,user_id) VALUES($1,$2,$3)",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO owner_mfa(account_id,user_id,secret_nonce,secret_ciphertext,pending_expires_at,pending_session_id) \
         VALUES($1,$2,$3,$4,now()+interval '1 hour',$5)",
        &[&a.account_id, &a.user_id, &vec![17_u8; 12], &vec![18_u8; 36],
            &session_a.id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO owner_mfa_recovery_codes(account_id,user_id,code_hash) VALUES($1,$2,$3)",
        &[&a.account_id, &a.user_id, &vec![19_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO owner_mfa_login_challenges(id,account_id,user_id,token_hash,expires_at) \
         VALUES($1,$2,$3,$4,now()+interval '1 hour')",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id, &vec![20_u8; 32]],
    )
    .await
    .unwrap();
    // An expired challenge is deletable; the live-row guard must not trip.
    db.execute(
        "INSERT INTO sms_owner_key_challenges(id,account_id,user_id,session_id,signing_key_sec1,fingerprint,nonce_digest,created_at,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,now()-interval '3 hours',now()-interval '2 hours')",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id, &session_a.id,
            &vec![21_u8; 65], &vec![22_u8; 32], &vec![23_u8; 32]],
    )
    .await
    .unwrap();
    let app = router(OwnerErasureState {
        database_url: database_url.to_owned(),
        auth_hasher: hasher.clone(),
        canonical_origin: ORIGIN.to_owned(),
        mfa_cipher,
    });
    (a, session_a, b, session_b, app)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn erasure_deletes_every_account_row_and_ends_the_session() {
    let (admin, mut db, database_url, schema) = migrated_schema("full").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(23)).unwrap());
    let (a, session_a, b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let report = body(response).await;
    assert_eq!(report["account_id"], a.account_id.to_string());
    for (table, rows) in [
        ("recipient_suppressions", 1),
        ("webhook_attempts", 1),
        ("webhook_replay_requests", 1),
        ("webhook_deliveries", 1),
        ("webhook_dispatch_accounts", 1),
        ("webhook_endpoints", 1),
        ("inbound_events", 1),
        ("usage_ledger", 1),
        ("usage_periods", 1),
        ("usage_quota_policies", 1),
        ("message_events", 2),
        ("dispatch_jobs", 1),
        ("dispatch_fences", 2),
        ("idempotency_keys", 1),
        ("message_attempts", 2),
        ("messages", 2),
        ("device_auth_challenges", 0),
        ("device_keys", 0),
        ("pairing_requests", 1),
        ("api_keys", 1),
        ("device_sessions", 1),
        ("device_preconditions", 1),
        ("devices", 1),
        ("billing_payment_holds", 1),
        ("billing_risk_events", 1),
        ("billing_events", 1),
        ("billing_quota_audit", 1),
        ("billing_device_cap_audit", 1),
        ("billing_device_caps", 1),
        ("billing_subscriptions", 1),
        ("billing_reconciliations", 1),
        ("billing_customers", 1),
        ("sealed_manifest_authorities", 0),
        ("sealed_root_challenges", 0),
        ("email_verifications", 1),
        ("verification_mail_outbox", 1),
        ("password_resets", 1),
        ("password_reset_notice_outbox", 1),
        ("sms_owner_key_challenges", 1),
        ("owner_mfa", 1),
        ("owner_mfa_recovery_codes", 1),
        ("owner_mfa_login_challenges", 1),
        ("sessions", 1),
        ("memberships", 1),
        ("users", 1),
        ("accounts", 1),
    ] {
        assert_eq!(
            deleted_count(&report, table),
            rows,
            "per-table count {table}"
        );
    }
    assert_eq!(deleted_count(&report, "line_opt_out_events"), 0);
    assert_eq!(deleted_count(&report, "sealed_inbound_events"), 0);
    // The only retained set is the shared request-budget counters: the
    // account's own billing risk rows never mask its events as retained.
    let retained = report["retained"].as_array().unwrap();
    assert_eq!(
        retained.len(),
        1,
        "retained must only name the budget counters"
    );
    assert_eq!(retained[0]["table"], "auth_abuse_counters");
    // Direct queries: no row for the erased account survives anywhere.
    for table in [
        "messages",
        "message_events",
        "message_attempts",
        "dispatch_jobs",
        "dispatch_fences",
        "idempotency_keys",
        "devices",
        "device_sessions",
        "device_keys",
        "device_auth_challenges",
        "pairing_requests",
        "api_keys",
        "usage_ledger",
        "usage_periods",
        "usage_quota_policies",
        "webhook_endpoints",
        "webhook_deliveries",
        "webhook_replay_requests",
        "webhook_dispatch_accounts",
        "inbound_events",
        "recipient_suppressions",
        "billing_customers",
        "billing_events",
        "billing_risk_events",
        "billing_payment_holds",
        "billing_reconciliations",
        "billing_subscriptions",
        "billing_quota_audit",
        "billing_device_caps",
        "billing_device_cap_audit",
        "device_preconditions",
        "sealed_manifest_authorities",
        "sealed_root_challenges",
        "email_verifications",
        "password_resets",
        "password_reset_notice_outbox",
        "sms_owner_key_challenges",
        "owner_mfa",
        "owner_mfa_recovery_codes",
        "owner_mfa_login_challenges",
        "sessions",
        "memberships",
    ] {
        let sql = format!("SELECT count(*) FROM {table} WHERE account_id=$1");
        let left: i64 = db.query_one(&sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(left, 0, "{table} still holds erased-account rows");
    }
    // Outbox rows follow their verification codes, not an account column.
    let mail_left: i64 = db
        .query_one(
            "SELECT count(*) FROM verification_mail_outbox o \
             JOIN email_verifications v ON v.id=o.verification_id \
             WHERE v.account_id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(mail_left, 0, "verification mail outbox still holds rows");
    // Webhook attempts follow their delivery rows, not an account column.
    let attempts_left: i64 = db
        .query_one(
            "SELECT count(*) FROM webhook_attempts a \
             JOIN webhook_deliveries d ON d.id=a.delivery_id \
             WHERE d.account_id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(attempts_left, 0, "webhook attempts still hold rows");
    let account_gone: i64 = db
        .query_one(
            "SELECT count(*) FROM accounts WHERE id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(account_gone, 0, "the erased account row is gone");
    let users_gone: i64 = db
        .query_one("SELECT count(*) FROM users WHERE id=$1", &[&a.user_id])
        .await
        .unwrap()
        .get(0);
    assert_eq!(users_gone, 0);
    // The second account keeps every row: tenant isolation.
    let b_alive: i64 = db
        .query_one(
            "SELECT count(*) FROM accounts WHERE id=$1",
            &[&b.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(b_alive, 1);
    for sql in [
        "SELECT count(*) FROM devices WHERE account_id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&b.account_id]).await.unwrap().get(0);
        assert_eq!(rows, 1, "isolation probe row missing for account b");
    }
    let raw = serde_json::to_string(&report).unwrap();
    assert!(!raw.contains("ERASE_A_BODY"));
    assert!(!raw.contains("KEEP_B_BODY"));
    // The erased session no longer authenticates.
    let again = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn wrong_current_password_is_rejected_and_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("wrongpw").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(24)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(3),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let error = body(response).await;
    assert_eq!(error["code"], "invalid_request");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.account_id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM billing_customers WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a rejected erasure must not delete anything"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn missing_csrf_or_wrong_origin_is_rejected_and_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("csrf").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(25)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    let missing_csrf = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            None,
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(missing_csrf).await["code"], "forbidden");
    let wrong_origin = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some("https://evil.example"),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
    let anonymous = app
        .clone()
        .oneshot(erasure_post(
            None,
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(rows, if sql.contains("messages") { 2 } else { 1 });
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn schema_protected_consent_rows_block_the_whole_erasure() {
    let (admin, mut db, database_url, schema) = migrated_schema("blocked").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(26)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    db.execute(
        "INSERT INTO owner_recipient_holds(id,account_id,recipient_e164,channel,reason,reported_at,created_by) \
         VALUES($1,$2,'+15559999999','email','opt_out',now()-interval '1 hour',$3)",
        &[&Uuid::new_v4(), &a.account_id, &a.user_id],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let blocked = body(response).await;
    assert_eq!(blocked["code"], "erasure_blocked");
    assert_eq!(blocked_count(&blocked, "owner_recipient_holds"), 1);
    // The rollback is complete: every fixture row is still present.
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM billing_events WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(rows, if sql.contains("messages") { 2 } else { 1 });
    }
    let holds: i64 = db
        .query_one(
            "SELECT count(*) FROM owner_recipient_holds WHERE account_id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(holds, 1);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn phone_line_tombstone_blocks_erasure() {
    let (admin, mut db, database_url, schema) = migrated_schema("phone_line").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(30)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    // A pending line identity tombstone: schema policy keeps it, so the
    // whole erasure must fail closed before anything is deleted.
    db.execute(
        "INSERT INTO phone_lines(id,account_id,state) VALUES($1,$2,'pending')",
        &[&Uuid::new_v4(), &a.account_id],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let blocked = body(response).await;
    assert_eq!(blocked["code"], "erasure_blocked");
    assert_eq!(blocked_count(&blocked, "phone_lines"), 1);
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM phone_lines WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a blocked erasure must delete nothing"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn sealed_trust_history_blocks_erasure() {
    let (admin, mut db, database_url, schema) = migrated_schema("trust_history").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(37)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    // Enroll a device key through the production path: migration 044's
    // trigger records the immutable signing trust history, which neither a
    // direct DELETE nor the account-row cascade may remove. The erasure
    // must fail closed with those tables listed instead of dying on the
    // cascade mid-transaction.
    let device_a: Uuid = db
        .query_one(
            "SELECT id FROM devices WHERE account_id=$1 ORDER BY id LIMIT 1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    db.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) \
         VALUES($1,$2,$3,$4)",
        &[&device_a, &a.account_id, &vec![24_u8; 65], &vec![25_u8; 32]],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let blocked = body(response).await;
    assert_eq!(blocked["code"], "erasure_blocked");
    assert_eq!(blocked_count(&blocked, "known_signing_role_claims"), 1);
    assert_eq!(
        blocked_count(&blocked, "known_signing_point_reservations"),
        1
    );
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM device_keys WHERE account_id=$1",
        "SELECT count(*) FROM known_signing_point_reservations WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a blocked erasure must delete nothing"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn cross_account_billing_reference_blocks_erasure() {
    let (admin, mut db, database_url, schema) = migrated_schema("shared_event").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(31)).unwrap());
    let (a, session_a, b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    // Account A owns a second billing event, and account B's risk record
    // references it. The event cannot be deleted while B's row exists, so a
    // success-with-retained response was never reachable: the accounts
    // foreign key would fail after the other deletes. This must block up
    // front with nothing deleted.
    db.execute(
        "INSERT INTO billing_events(stripe_event_id,event_type,stripe_customer_id,account_id,body_sha256,disposition) \
         VALUES('evt_sharedotheracct00','invoice.paid','cus_erasurefixture',$1,$2,'queued')",
        &[&a.account_id, &vec![31_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
         VALUES('evt_sharedotheracct00','ch_sharedotheracct00','refund',$1)",
        &[&b.account_id],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let blocked = body(response).await;
    assert_eq!(blocked["code"], "erasure_blocked");
    // Only the cross-account-referenced event counts: A's own risk row on
    // evt_erasurefixture is deleted by the plan and must not block.
    assert_eq!(blocked_count(&blocked, "billing_events"), 1);
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM billing_events WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") || sql.contains("billing_events") {
                2
            } else {
                1
            },
            "a blocked erasure must delete nothing"
        );
    }
    // The other account's referencing row survives untouched.
    let shared: i64 = db
        .query_one(
            "SELECT count(*) FROM billing_risk_events WHERE account_id=$1",
            &[&b.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(shared, 1);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// The erasure handler under test connects with this application_name
/// appended to its database URL, so park detection can bind to this exact
/// request instead of to any FOR UPDATE waiter in the database.
fn handler_url(database_url: &str, application_name: &str) -> String {
    format!("{database_url}&application_name={application_name}")
}

/// Block until this request's own connection (identified by its unique
/// application_name) is actually blocked by the blocker's backend, as
/// observed through `pg_blocking_pids`. That proves the request has
/// finished its pre-transaction password proof and is parked on the
/// in-transaction fence's row lock held by `blocker`, so a change committed
/// after this returns is observed by the fence and by nothing earlier.
/// (When the blocker holds the session row, the caller must first touch
/// the session's `last_used_at` so the `authenticate_session` refresh does
/// not take that row before the fence does.)
async fn wait_until_handler_is_blocked_by(
    admin: &tokio_postgres::Client,
    application_name: &str,
    blocker_pid: i32,
) {
    for _ in 0..600 {
        let blocked: bool = admin
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a \
                 WHERE a.application_name=$1 \
                   AND $2=ANY(pg_blocking_pids(a.pid)))",
                &[&application_name, &blocker_pid],
            )
            .await
            .unwrap()
            .get(0);
        if blocked {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the erasure request never parked on the blocker's lock");
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn session_revoked_during_erasure_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("revoke_race").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(27)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_revoke_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    // authenticate_session only rewrites last_used_at when it is stale;
    // touching it here keeps the request from taking the session row lock
    // before its final fence, so the park detected below is exactly the
    // fence. This reproduces a revocation landing inside the request's
    // pre-fence window deterministically, instead of racing argon2.
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Hold the session row so the erasure transaction cannot get past its
    // final authorization fence (which takes that row FOR UPDATE) until the
    // revocation below has committed.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = db.transaction().await.unwrap();
    blocker
        .query_opt(
            "SELECT id FROM sessions WHERE id=$1 FOR UPDATE",
            &[&session_a.id],
        )
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    // Let the request finish its pre-transaction proof and park at the
    // fence, then revoke the session on the blocker's connection while the
    // erasure is in flight: the fenced recheck must observe the revocation
    // and abort the whole transaction.
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_revoke_race", blocker_pid).await;
    blocker
        .execute(
            "UPDATE sessions SET revoked_at=now() WHERE id=$1",
            &[&session_a.id],
        )
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(response).await["code"], "unauthorized");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM billing_events WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn password_changed_during_erasure_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("pw_race").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(32)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_pw_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    // Keep authenticate_session's last_used_at refresh from touching the
    // session row before the fence (see wait_until_handler_is_blocked_by).
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Hold the user row so the erasure's locked re-read of the password hash
    // cannot complete until the rotation below has committed.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = db.transaction().await.unwrap();
    blocker
        .query_opt("SELECT id FROM users WHERE id=$1 FOR UPDATE", &[&a.user_id])
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    // The password hash is replaced while the request is parked at the
    // fence. The pre-transaction proof verified the old hash; the locked
    // re-read must reject the new one and abort with nothing deleted.
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_pw_race", blocker_pid).await;
    blocker
        .execute(
            "UPDATE users SET password_hash='rotated-during-erasure' WHERE id=$1",
            &[&a.user_id],
        )
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(response).await["code"], "unauthorized");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn account_disabled_during_erasure_wait_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("disable_race").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(33)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_disable_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    // Keep authenticate_session's last_used_at refresh off the blocker's
    // path (see wait_until_handler_is_blocked_by).
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Connection A: hold the user row so the fence's joined lock parks there
    // before it ever reaches the account row.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = db.transaction().await.unwrap();
    blocker
        .query_opt("SELECT id FROM users WHERE id=$1 FOR UPDATE", &[&a.user_id])
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    // Once the request is parked on the user lock, connection B commits the
    // disable, then A releases. The fence locks the account row too
    // (FOR UPDATE OF u,m,a), so the disable committed before that grant
    // fails the locked row's re-qualification — and the fence's final
    // fresh-statement recheck would catch it regardless.
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_disable_race", blocker_pid).await;
    admin
        .execute(
            &format!("UPDATE {schema}.accounts SET disabled_at=now() WHERE id=$1"),
            &[&a.account_id],
        )
        .await
        .unwrap();
    blocker.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(response).await["code"], "unauthorized");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM billing_events WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    // The disable itself stands; only the erasure was refused.
    let disabled: bool = db
        .query_one(
            "SELECT disabled_at IS NOT NULL FROM accounts WHERE id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert!(disabled);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn session_expires_during_erasure_wait_deletes_nothing() {
    let (admin, mut db, database_url, schema) = migrated_schema("expiry_race").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(34)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_expiry_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    // The authenticate_session refresh must not touch the session row: the
    // blocker below holds it, and the detected park must be the fence.
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Short-fuse the session directly: the absolute expiry lands far enough
    // out for the pre-transaction proof, then passes while the request is
    // parked. `now()` inside the parked statement stays frozen at statement
    // start, so only a post-lock `clock_timestamp()` recheck can catch it.
    // The fuse also has to pass inside production's bounded lock wait: the
    // server's pooled connections run with lock_timeout=3s
    // (crate::runtime_db), after which the request fails closed with 503 —
    // so the fuse is set well below that bound while still clearing the
    // request's pre-fence proof work.
    db.execute(
        "UPDATE sessions SET expires_at=now()+interval '2 seconds' WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Hold the session row so the fence parks inside its live-session lock
    // statement, whose snapshot predates the expiry passing.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = db.transaction().await.unwrap();
    blocker
        .query_opt(
            "SELECT id FROM sessions WHERE id=$1 FOR UPDATE",
            &[&session_a.id],
        )
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    // Let the database clock run past the short fuse (with a short grace)
    // while the request stays parked, then release the lock well inside the
    // lock_timeout so the parked statement itself is not canceled.
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_expiry_race", blocker_pid).await;
    let mut fuse_passed = false;
    for _ in 0..1200 {
        let past: bool = admin
            .query_one(
                &format!(
                    "SELECT clock_timestamp() > expires_at + interval '250 milliseconds' \
                     FROM {schema}.sessions WHERE id=$1"
                ),
                &[&session_a.id],
            )
            .await
            .unwrap()
            .get(0);
        if past {
            fuse_passed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert!(fuse_passed, "the short-fused expiry never passed");
    blocker.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(response).await["code"], "unauthorized");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM billing_events WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mfa_failure_budget_recorded_exactly_once_after_wait() {
    let (admin, mut db, database_url, schema) = migrated_schema("mfa_wait").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(35)).unwrap());
    let cipher = Arc::new(mfa::MfaCipher::new(crate::test_keys::key(36)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_mfa_wait");
    let (a, session_a, _b, _session_b, app) = fixture(
        &mut db,
        &hasher,
        &handler_database_url,
        Some(cipher.clone()),
    )
    .await;
    // Enroll a real TOTP factor through the production flow, then keep the
    // request's factor state to check the budget bookkeeping around a
    // late-wait abort.
    let principal = authenticate_session(&db, &hasher, &session_a.token)
        .await
        .unwrap();
    let enrollment =
        mfa::begin_enrollment(&mut db, &cipher, &principal, &crate::test_keys::password(1))
            .await
            .unwrap();
    let secret = Secret::try_from_base32(&enrollment.secret_base32).unwrap();
    let totp = Builder::new().with_secret(secret).build().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let confirm_code = totp.generate(now).to_string();
    mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &confirm_code)
        .await
        .unwrap();
    // Park the request on the user row, then let it proceed to a wrong
    // factor: the abort happens after a lock wait, and the shared failure
    // budget must record that one wrong factor exactly once.
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let blocker = db.transaction().await.unwrap();
    blocker
        .query_opt("SELECT id FROM users WHERE id=$1 FOR UPDATE", &[&a.user_id])
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn({
        let app = app.clone();
        async move {
            app.oneshot(erasure_post(
                Some(&token),
                Some(&csrf),
                Some(ORIGIN),
                &crate::test_keys::password(1),
                Some("not-a-code"),
            ))
            .await
            .unwrap()
        }
    });
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_mfa_wait", blocker_pid).await;
    blocker.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Exactly one recorded failure for exactly one wrong factor, committed
    // by the rejection path rather than rolled back with the erasure.
    let budget_after_late_wait =
        abuse_limits::failures_in_window(&db, &hasher, Limit::MfaStepUp, &a.user_id.to_string())
            .await
            .unwrap();
    assert_eq!(budget_after_late_wait, 1);
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM owner_mfa WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    // An abort that happens before the factor step (the session was
    // revoked) must not touch the budget at all.
    db.execute(
        "UPDATE sessions SET revoked_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    let response = app
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            Some("not-a-code"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let budget_after_pre_factor_abort =
        abuse_limits::failures_in_window(&db, &hasher, Limit::MfaStepUp, &a.user_id.to_string())
            .await
            .unwrap();
    assert_eq!(
        budget_after_pre_factor_abort, 1,
        "a pre-factor abort must not record a failure"
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn mfa_enabled_erasure_requires_code() {
    let (admin, mut db, database_url, schema) = migrated_schema("mfa").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(28)).unwrap());
    let cipher = Arc::new(mfa::MfaCipher::new(crate::test_keys::key(29)).unwrap());
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &database_url, Some(cipher.clone())).await;
    // Enroll a real TOTP factor through the production flow.
    let principal = authenticate_session(&db, &hasher, &session_a.token)
        .await
        .unwrap();
    let enrollment =
        mfa::begin_enrollment(&mut db, &cipher, &principal, &crate::test_keys::password(1))
            .await
            .unwrap();
    let secret = Secret::try_from_base32(&enrollment.secret_base32).unwrap();
    let totp = Builder::new().with_secret(secret).build().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let confirm_code = totp.generate(now).to_string();
    mfa::confirm_enrollment(&mut db, &cipher, &hasher, &principal, &confirm_code)
        .await
        .unwrap();
    // Without a code the erasure is an auth failure and deletes nothing.
    let missing = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(missing).await["code"], "unauthorized");
    // A malformed code is a failed factor: still an auth failure, still
    // nothing deleted, and the shared failure budget recorded it.
    let wrong = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            Some("not-a-code"),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
    let budget =
        abuse_limits::failures_in_window(&db, &hasher, Limit::MfaStepUp, &a.user_id.to_string())
            .await
            .unwrap();
    assert_eq!(budget, 1, "the wrong factor must spend the failure budget");
    for sql in [
        "SELECT count(*) FROM accounts WHERE id=$1",
        "SELECT count(*) FROM messages WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
    ] {
        let rows: i64 = db.query_one(sql, &[&a.account_id]).await.unwrap().get(0);
        assert_eq!(
            rows,
            if sql.contains("messages") { 2 } else { 1 },
            "a fenced-off erasure must delete nothing"
        );
    }
    // A fresh step's code satisfies the step-up and the erasure proceeds.
    let next_code = totp.generate(((now / 30) + 1) * 30).to_string();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            Some(&next_code),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    assert_eq!(deleted_count(&report, "owner_mfa"), 1);
    let account_gone: i64 = db
        .query_one(
            "SELECT count(*) FROM accounts WHERE id=$1",
            &[&a.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(account_gone, 0);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

/// The runtime database role provisioner cannot run inside an isolated test
/// schema: it drives psql meta-commands (`\getenv`, `\gset`, `\if`,
/// `\gexec`) that tokio-postgres cannot execute, and it issues cluster-level
/// `CREATE ROLE`/`ALTER ROLE` statements plus database-wide ACLs that are
/// not schema-scopable. The honest repository-level proof is parsing: every
/// table the erasure plan deletes (plus `users` and `accounts`) must be
/// covered by the role's schema-wide DML grant, and none may appear in the
/// file's per-table revocation exceptions. The schema coverage itself is
/// proven for real by the PostgreSQL tests above, which apply the identical
/// migration set before the plan's deletes run.
#[test]
fn runtime_role_covers_every_erased_table() {
    let role_sql = include_str!("../../../../deploy/compose/runtime-role.sql");
    assert!(
        role_sql.contains(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zrotext_runtime"
        ),
        "the runtime role must hold DELETE on every public table"
    );
    let revoked: Vec<&str> = role_sql
        .lines()
        .filter_map(|line| line.trim().strip_prefix("REVOKE ALL ON TABLE public."))
        .map(|rest| {
            rest.split_whitespace()
                .next()
                .expect("a table name follows every table revocation")
        })
        .collect();
    assert_eq!(
        revoked.as_slice(),
        ["schema_migrations"],
        "new table exceptions would silently deny the runtime role's erasure access"
    );
    for table in DELETE_PLAN
        .iter()
        .map(|(table, _)| *table)
        .chain(["users", "accounts"])
    {
        assert!(
            !revoked.contains(&table),
            "runtime-role.sql revokes {table}, which the erasure deletes"
        );
    }
}

// ---------------------------------------------------------------------------
// Observer seats: erasing an account must erase its observers' accounts too.
// ---------------------------------------------------------------------------

use crate::auth::seats;

async fn principal_of(
    db: &tokio_postgres::Client,
    hasher: &Arc<TokenHasher>,
    session: &crate::auth::SessionCredentials,
) -> crate::auth::SessionPrincipal {
    authenticate_session(db, hasher, &session.token)
        .await
        .unwrap()
}

/// Invite, accept and (optionally) verify one observer through the real
/// seat functions; returns its user id and the password it chose.
async fn seat_observer(
    db: &mut tokio_postgres::Client,
    hasher: &Arc<TokenHasher>,
    owner: &crate::auth::SessionPrincipal,
    owner_password: &str,
    email: &str,
    verified: bool,
) -> (Uuid, String) {
    let issued =
        seats::create_invitation_with_proof(db, None, hasher, owner, owner_password, None, email)
            .await
            .unwrap();
    let password = crate::test_keys::password(7);
    let acceptance = seats::accept_invitation(db, hasher, &issued.token, &password)
        .await
        .unwrap();
    if verified {
        assert!(
            crate::auth::verify_email_with_password(
                db,
                hasher,
                &acceptance.verification_token,
                &password
            )
            .await
            .unwrap()
        );
    }
    (acceptance.user_id, password)
}

async fn rows(db: &tokio_postgres::Client, sql: &str, id: Uuid) -> i64 {
    db.query_one(sql, &[&id]).await.unwrap().get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn erasure_deletes_the_accounts_observers_invitations_and_tombstones_only() {
    let (admin, mut db, database_url, schema) = migrated_schema("observers").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(41)).unwrap());
    let (a, session_a, b, session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    let owner_a = principal_of(&db, &hasher, &session_a).await;
    let owner_b = principal_of(&db, &hasher, &session_b).await;
    let (pw_a, pw_b) = (crate::test_keys::password(1), crate::test_keys::password(2));

    // Account A: a live verified observer with a session and an API key, an
    // accepted but unverified observer, a removed observer (tombstone, user
    // deleted), a removed observer whose user survived because a restricting
    // reference refused the delete, and one open invitation.
    let (live_id, live_pw) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &pw_a,
        "live-observer@example.test",
        true,
    )
    .await;
    let (pending_id, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &pw_a,
        "pending-observer@example.test",
        false,
    )
    .await;
    let (removed_id, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &pw_a,
        "removed-observer@example.test",
        true,
    )
    .await;
    assert!(
        seats::remove_observer(&mut db, &owner_a, removed_id)
            .await
            .unwrap()
            .unwrap()
            .address_freed
    );
    let (fallback_id, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &pw_a,
        "fallback-observer@example.test",
        true,
    )
    .await;
    db.execute(
        "INSERT INTO pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,expires_at) VALUES($1,$2,$3,$4,'synthetic',now()+interval '1 hour')",
        &[
            &Uuid::new_v4(),
            &a.account_id,
            &fallback_id,
            &crate::test_keys::key(43),
        ],
    )
    .await
    .unwrap();
    assert!(
        !seats::remove_observer(&mut db, &owner_a, fallback_id)
            .await
            .unwrap()
            .unwrap()
            .address_freed
    );
    seats::create_invitation_with_proof(
        &mut db,
        None,
        &hasher,
        &owner_a,
        &pw_a,
        None,
        "open-invite@example.test",
    )
    .await
    .unwrap();
    let live_session = login(&db, &hasher, "live-observer@example.test", &live_pw)
        .await
        .unwrap();
    let key_prefix = Uuid::new_v4().simple().to_string();
    let key_hash = crate::test_keys::key(42);
    db.execute(
        "INSERT INTO api_keys(id,account_id,created_by_user_id,public_prefix,token_hash,scopes) VALUES($1,$2,$3,$4,$5,ARRAY['devices:read'])",
        &[&Uuid::new_v4(), &a.account_id, &live_id, &key_prefix, &key_hash],
    )
    .await
    .unwrap();

    // Account B keeps a verified observer and an open invitation.
    let (b_observer, b_observer_pw) = seat_observer(
        &mut db,
        &hasher,
        &owner_b,
        &pw_b,
        "b-observer@example.test",
        true,
    )
    .await;
    let b_open = seats::create_invitation_with_proof(
        &mut db,
        None,
        &hasher,
        &owner_b,
        &pw_b,
        None,
        "b-open@example.test",
    )
    .await
    .unwrap();

    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &pw_a,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;

    // The report says what happened: three surviving observer users (live,
    // pending, fallback) plus the owner, five invitation rows including both
    // tombstones and the open one, and only the owner's membership left for
    // the membership delete because the user deletes cascaded the rest.
    assert_eq!(deleted_count(&report, "observer_users"), 3);
    assert_eq!(deleted_count(&report, "seat_invitations"), 5);
    assert_eq!(deleted_count(&report, "memberships"), 1);
    assert_eq!(deleted_count(&report, "users"), 1);
    assert_eq!(deleted_count(&report, "accounts"), 1);
    let raw = serde_json::to_string(&report).unwrap();
    assert!(!raw.contains("observer@example.test"));

    // Nothing of the erased account's observers survives: user rows (email,
    // password hash), sessions, keys, verification state, invitations.
    let emails = [
        "live-observer@example.test",
        "pending-observer@example.test",
        "removed-observer@example.test",
        "fallback-observer@example.test",
        "open-invite@example.test",
        "erase-a@example.test",
    ];
    let left: i64 = db
        .query_one(
            "SELECT count(*) FROM users WHERE email = ANY($1) OR id = ANY($2)",
            &[
                &emails.to_vec(),
                &vec![a.user_id, live_id, pending_id, removed_id, fallback_id],
            ],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0, "users of the erased account survive");
    for sql in [
        "SELECT count(*) FROM seat_invitations WHERE account_id=$1",
        "SELECT count(*) FROM memberships WHERE account_id=$1",
        "SELECT count(*) FROM sessions WHERE account_id=$1",
        "SELECT count(*) FROM api_keys WHERE account_id=$1",
        "SELECT count(*) FROM email_verifications WHERE account_id=$1",
        "SELECT count(*) FROM verification_mail_outbox o JOIN email_verifications v ON v.id=o.verification_id WHERE v.account_id=$1",
    ] {
        assert_eq!(rows(&db, sql, a.account_id).await, 0, "{sql}");
    }
    assert!(
        crate::auth::authenticate_session(&db, &hasher, &live_session.token)
            .await
            .is_err()
    );
    assert!(
        login(&db, &hasher, "live-observer@example.test", &live_pw)
            .await
            .is_err()
    );

    // The addresses are free again: the person can register their own
    // account, and another account can invite and seat a former address.
    register(
        &mut db,
        &hasher,
        "live-observer@example.test",
        &crate::test_keys::password(8),
    )
    .await
    .unwrap();
    let elsewhere = seats::create_invitation_with_proof(
        &mut db,
        None,
        &hasher,
        &owner_b,
        &pw_b,
        None,
        "pending-observer@example.test",
    )
    .await
    .unwrap();
    seats::accept_invitation(
        &mut db,
        &hasher,
        &elsewhere.token,
        &crate::test_keys::password(9),
    )
    .await
    .unwrap();

    // Account B is untouched: owner, observer, sessions, and its open
    // invitation with a still-live token.
    for user in [b.user_id, b_observer] {
        assert_eq!(
            rows(&db, "SELECT count(*) FROM users WHERE id=$1", user).await,
            1
        );
    }
    assert!(
        login(&db, &hasher, "b-observer@example.test", &b_observer_pw)
            .await
            .is_ok()
    );
    assert!(
        login(&db, &hasher, "erase-b@example.test", &pw_b)
            .await
            .is_ok()
    );
    assert!(
        seats::invitation_token_is_live(&db, &hasher, &b_open.token)
            .await
            .unwrap()
    );
    assert_eq!(
        rows(
            &db,
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1 AND email='b-observer@example.test' AND accepted_at IS NOT NULL",
            b.account_id
        )
        .await,
        1
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn erasure_fails_closed_when_an_observer_user_cannot_be_deleted() {
    let (admin, mut db, database_url, schema) = migrated_schema("observer_block").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(44)).unwrap());
    let (a, session_a, _b, _session_b, app) = fixture(&mut db, &hasher, &database_url, None).await;
    let owner_a = principal_of(&db, &hasher, &session_a).await;
    let (observer, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &crate::test_keys::password(1),
        "pinned-observer@example.test",
        true,
    )
    .await;
    // A restricting reference to the observer's user row that no erasure
    // step clears, standing in for any future table that pins a user.
    db.batch_execute(
        "CREATE TABLE observer_user_pin(user_id uuid PRIMARY KEY REFERENCES users(id))",
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO observer_user_pin(user_id) VALUES($1)",
        &[&observer],
    )
    .await
    .unwrap();
    let response = app
        .clone()
        .oneshot(erasure_post(
            Some(&session_a.token),
            Some(&session_a.csrf_token),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap();
    // Fail closed like every other blocker: a 409 naming what blocks it,
    // never a 503 that looks retryable and never a half-erased account.
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let report = body(response).await;
    assert_eq!(report["code"], "erasure_blocked");
    assert_eq!(blocked_count(&report, "observer_users"), 1);
    for (sql, expected) in [
        ("SELECT count(*) FROM accounts WHERE id=$1", 1),
        ("SELECT count(*) FROM messages WHERE account_id=$1", 2),
        ("SELECT count(*) FROM memberships WHERE account_id=$1", 2),
        ("SELECT count(*) FROM sessions WHERE account_id=$1", 1),
        (
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1",
            1,
        ),
    ] {
        assert_eq!(
            rows(&db, sql, a.account_id).await,
            expected,
            "a blocked erasure must delete nothing: {sql}"
        );
    }
    assert_eq!(
        rows(&db, "SELECT count(*) FROM users WHERE id=$1", observer).await,
        1
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn an_acceptance_in_flight_during_erasure_cannot_leave_an_observer_behind() {
    let (admin, mut db, database_url, schema) = migrated_schema("observer_accept").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(45)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_accept_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    let owner_a = principal_of(&db, &hasher, &session_a).await;
    let issued = seats::create_invitation_with_proof(
        &mut db,
        None,
        &hasher,
        &owner_a,
        &crate::test_keys::password(1),
        None,
        "race-observer@example.test",
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Act as an acceptance that has claimed its invitation and created the
    // observer but not yet committed.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let observer = Uuid::new_v4();
    let acceptance = db.transaction().await.unwrap();
    acceptance
        .query_one(
            "SELECT id FROM seat_invitations WHERE account_id=$1 AND email='race-observer@example.test' AND accepted_at IS NULL FOR UPDATE",
            &[&a.account_id],
        )
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    // The erasure parks on the invitation row before its fence, so it waits
    // for the acceptance instead of racing it.
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_accept_race", blocker_pid).await;
    // Only now does the acceptance create the observer. Were the erasure past
    // its fence, this membership insert would queue behind the fence's lock on
    // the account row while the erasure queued behind this invitation row: a
    // deadlock. Parked before the fence, it completes first.
    acceptance
        .execute(
            "INSERT INTO users(id,email,password_hash) SELECT $1,'race-observer@example.test',password_hash FROM users WHERE id=$2",
            &[&observer, &a.user_id],
        )
        .await
        .unwrap();
    acceptance
        .execute(
            "INSERT INTO memberships(account_id,user_id,role) VALUES($1,$2,'observer')",
            &[&a.account_id, &observer],
        )
        .await
        .unwrap();
    acceptance
        .execute(
            "UPDATE seat_invitations SET accepted_at=now(),accepted_user_id=$2 WHERE account_id=$1 AND email='race-observer@example.test'",
            &[&a.account_id, &observer],
        )
        .await
        .unwrap();
    acceptance.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    // The observer created by the acceptance is erased with the account, not
    // orphaned, and its token is dead.
    assert_eq!(deleted_count(&report, "observer_users"), 1);
    assert_eq!(
        rows(&db, "SELECT count(*) FROM users WHERE id=$1", observer).await,
        0
    );
    assert_eq!(
        rows(
            &db,
            "SELECT count(*) FROM seat_invitations WHERE account_id=$1",
            a.account_id
        )
        .await,
        0
    );
    assert!(matches!(
        seats::accept_invitation(
            &mut db,
            &hasher,
            &issued.token,
            &crate::test_keys::password(9)
        )
        .await,
        Err(AuthError::InvalidCredentials)
    ));
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn a_seat_removal_in_flight_during_erasure_finishes_first_without_a_deadlock() {
    let (admin, mut db, database_url, schema) = migrated_schema("observer_remove").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(46)).unwrap());
    let handler_database_url = handler_url(&database_url, "zt_erasure_remove_race");
    let (a, session_a, _b, _session_b, app) =
        fixture(&mut db, &hasher, &handler_database_url, None).await;
    let owner_a = principal_of(&db, &hasher, &session_a).await;
    let (observer, observer_pw) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &crate::test_keys::password(1),
        "removal-race@example.test",
        true,
    )
    .await;
    let observer_session = login(&db, &hasher, "removal-race@example.test", &observer_pw)
        .await
        .unwrap();
    db.execute(
        "UPDATE sessions SET last_used_at=now() WHERE id=$1",
        &[&session_a.id],
    )
    .await
    .unwrap();
    // Act as seat removal: it locks the observer's membership first and only
    // then touches the observer's sessions and invitation.
    let blocker_pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    let removal = db.transaction().await.unwrap();
    removal
        .query_one(
            "SELECT user_id FROM memberships WHERE user_id=$1 FOR UPDATE",
            &[&observer],
        )
        .await
        .unwrap();
    let token = session_a.token.clone();
    let csrf = session_a.csrf_token.clone();
    let request = tokio::spawn(async move {
        app.oneshot(erasure_post(
            Some(&token),
            Some(&csrf),
            Some(ORIGIN),
            &crate::test_keys::password(1),
            None,
        ))
        .await
        .unwrap()
    });
    wait_until_handler_is_blocked_by(&admin, "zt_erasure_remove_race", blocker_pid).await;
    // The erasure has taken no session or invitation lock yet, so the removal
    // can finish its remaining statements without waiting on it.
    removal
        .execute(
            "UPDATE memberships SET revoked_at=now() WHERE user_id=$1",
            &[&observer],
        )
        .await
        .unwrap();
    removal
        .execute(
            "UPDATE sessions SET revoked_at=now() WHERE id=$1",
            &[&observer_session.id],
        )
        .await
        .unwrap();
    removal
        .execute(
            "UPDATE seat_invitations SET canceled_at=now() WHERE account_id=$1 AND email='removal-race@example.test' AND accepted_at IS NULL",
            &[&a.account_id],
        )
        .await
        .unwrap();
    removal.commit().await.unwrap();
    let response = request.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    // The removal's revoked membership still belonged to an observer user, so
    // the erasure deleted that user too.
    assert_eq!(deleted_count(&report, "observer_users"), 1);
    assert_eq!(
        rows(&db, "SELECT count(*) FROM users WHERE id=$1", observer).await,
        0
    );
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn the_observer_user_delete_never_reaches_owners_or_other_accounts() {
    let (admin, mut db, database_url, schema) = migrated_schema("observer_guard").await;
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(47)).unwrap());
    let (a, session_a, b, session_b, _app) = fixture(&mut db, &hasher, &database_url, None).await;
    let owner_a = principal_of(&db, &hasher, &session_a).await;
    let owner_b = principal_of(&db, &hasher, &session_b).await;
    let (a_observer, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_a,
        &crate::test_keys::password(1),
        "guard-a@example.test",
        true,
    )
    .await;
    let (b_observer, _) = seat_observer(
        &mut db,
        &hasher,
        &owner_b,
        &crate::test_keys::password(2),
        "guard-b@example.test",
        true,
    )
    .await;
    // Run exactly the erasure's observer statement for account A inside a
    // transaction and inspect what it reaches.
    let tx = db.transaction().await.unwrap();
    let deleted = tx
        .execute(OBSERVER_USERS_SQL, &[&a.account_id])
        .await
        .unwrap();
    assert_eq!(deleted, 1, "only account A's observer");
    for (user, survives) in [
        (a_observer, false),
        (b_observer, true),
        (a.user_id, true),
        (b.user_id, true),
    ] {
        let count: i64 = tx
            .query_one("SELECT count(*) FROM users WHERE id=$1", &[&user])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count == 1, survives, "user {user}");
    }
    // An account with no observers of its own reaches nothing, even though
    // observers and owners exist elsewhere.
    tx.rollback().await.unwrap();
    let nothing = db
        .execute(OBSERVER_USERS_SQL, &[&Uuid::new_v4()])
        .await
        .unwrap();
    assert_eq!(nothing, 0);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
