// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL-backed tests for the owner contacts routes. The ignored tests
//! share the owned style of the sibling owner suites: a throwaway schema,
//! the complete real migration set, and the router under test driven through
//! `tower::ServiceExt`. All phone numbers are synthetic (+1555).

use super::*;
use crate::{
    auth::{SessionCredentials, TokenHasher, login, register, verify_email},
    http_owner_contacts::router,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;
use zeroize::Zeroizing;

mod consent_chronology;

const ORIGIN: &str = "https://test.example";

macro_rules! migration {
    ($name:literal) => {
        (
            $name,
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/compose/migrations/",
                $name
            )),
        )
    };
}

// The routes run on the complete schema, SQL embedded at build time.
const TEST_MIGRATIONS: [(&str, &str); 71] = [
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
];

#[test]
fn contacts_fixture_tracks_numbered_migrations() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/compose/migrations");
    let mut discovered = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    discovered.sort();
    let embedded = TEST_MIGRATIONS
        .iter()
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    assert_eq!(discovered, embedded, "update the embedded migration list");
}

#[test]
fn number_normalization_collapses_equivalent_spellings_only() {
    assert_eq!(
        normalize_e164("+1 555 010 0001").as_deref(),
        Some("+15550100001")
    );
    assert_eq!(
        normalize_e164("+1(555)010-0002.3").as_deref(),
        Some("+155501000023")
    );
    assert_eq!(
        normalize_e164("+15550100004").as_deref(),
        Some("+15550100004")
    );
    for invalid in [
        "",
        "+",
        "15550100005",
        "+05550100006",
        "tel:+15550100007",
        "+1555010000a",
        "+15550100008;ext=5",
        "+12345678901234567",
        "+123456789012345678901234567890123",
    ] {
        assert_eq!(normalize_e164(invalid), None, "{invalid}");
    }
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn cookies(owner: &SessionCredentials) -> String {
    format!(
        "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
        owner.token, owner.csrf_token
    )
}

fn get(path: &str, owner: &SessionCredentials) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .body(Body::empty())
        .unwrap()
}

fn request_with_cookies(method: &str, path: &str, owner: &SessionCredentials) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::empty())
        .unwrap()
}

fn post_json(path: &str, owner: &SessionCredentials, payload: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

/// Same request with a mismatched CSRF pair, to prove the pair is checked.
fn post_json_bad_csrf(path: &str, owner: &SessionCredentials, payload: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", "ztc_mismatched_csrf_token_value0")
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

fn post_json_no_origin(path: &str, owner: &SessionCredentials, payload: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

fn put_json(path: &str, owner: &SessionCredentials, payload: &Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap()
}

fn post_csv(path: &str, owner: &SessionCredentials, csv_body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::COOKIE, cookies(owner))
        .header("x-zrotext-csrf", &owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "text/csv")
        .body(Body::from(csv_body.to_owned()))
        .unwrap()
}

fn test_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Purpose -> state object, from a consents array.
fn states_by_purpose(value: &Value) -> HashMap<String, Value> {
    value
        .as_array()
        .expect("consents is an array")
        .iter()
        .map(|state| (state["purpose"].as_str().unwrap().to_owned(), state.clone()))
        .collect()
}

/// One fresh schema on the shared test database, the full migration set
/// applied, plus one registered owner account.
struct Fixture {
    app: axum::Router,
    db: Client,
    hasher: Arc<TokenHasher>,
    owner: SessionCredentials,
    account_id: uuid::Uuid,
    schema: String,
    admin: Client,
}

async fn fixture(vault: bool) -> Fixture {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_contacts_http_test_{}", uuid::Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in TEST_MIGRATIONS {
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
        // The migrator builds these indexes online before their numbered
        // files; a schema cannot run CREATE INDEX CONCURRENTLY inside its
        // transaction, so mirror the migrator's autocommit preparation.
        match name {
            "034_delivery_sweep_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                     ON messages(updated_at,id) \
                     WHERE state IN ('claimed','submitting','submitted')",
                )
                .await
                .unwrap();
            }
            "040_radio_evidence_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX CONCURRENTLY message_events_attempt_evidence \
                     ON message_events(attempt_id,evidence_code)",
                )
                .await
                .unwrap();
            }
            "049_owner_queue_probe_indexes.sql" => {
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
            "050_message_attempts_recent_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX CONCURRENTLY message_attempts_device_created \
                     ON message_attempts(account_id,device_id,created_at)",
                )
                .await
                .unwrap();
            }
            "052_admission_pending_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX CONCURRENTLY messages_admission_pending \
                     ON messages(account_id,device_id) \
                     WHERE state IN ('queued','claimed')",
                )
                .await
                .unwrap();
            }
            "057_webhook_history_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX CONCURRENTLY webhook_deliveries_history \
                     ON webhook_deliveries(endpoint_id,created_at DESC,id DESC)",
                )
                .await
                .unwrap();
            }
            "058_drop_abuse_counters_updated_index.sql" => {
                db.batch_execute("DROP INDEX IF EXISTS auth_abuse_counters_stale")
                    .await
                    .unwrap();
            }
            "059_erasure_fk_indexes.sql" => {
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
            "060_optout_review_indexes.sql" => {
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
            "061_inbound_events_attempt_fk_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX erasure_fk_inbound_events_attempt \
                     ON inbound_events(account_id,device_id,message_id,attempt_id)",
                )
                .await
                .unwrap();
            }
            "062_pending_recipient_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX messages_pending_recipient \
                     ON messages(recipient_e164,account_id) \
                     WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL",
                )
                .await
                .unwrap();
            }
            "066_conversation_interval_session_index.sql" => {
                db.batch_execute(
                    "CREATE INDEX erasure_fk_conversation_interval_session \
                     ON conversation_intervals(account_id,initiating_session_id)",
                )
                .await
                .unwrap();
            }
            _ => {}
        }
        db.batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let email = format!("contacts-{}@example.test", uuid::Uuid::new_v4().simple());
    let password = uuid::Uuid::new_v4().to_string();
    let signup = register(&mut db, &hasher, &email, &password).await.unwrap();
    verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let owner = login(&db, &hasher, &email, &password).await.unwrap();
    let contacts_vault = vault.then(|| {
        Arc::new(vault::ContactFieldVault::new(1, Zeroizing::new(vec![9_u8; 32])).unwrap())
    });
    let app = router(OwnerContactsState {
        database_url,
        auth_hasher: hasher.clone(),
        canonical_origin: ORIGIN.to_owned(),
        vault: contacts_vault,
    });
    Fixture {
        app,
        db,
        hasher,
        owner,
        account_id: signup.account_id,
        schema,
        admin,
    }
}

impl Fixture {
    async fn send(&self, request: Request<Body>) -> axum::response::Response {
        self.app.clone().oneshot(request).await.unwrap()
    }

    /// A second, unrelated account on the same schema, signed by the same
    /// session hasher the router under test uses.
    async fn owner_b(&mut self) -> (uuid::Uuid, SessionCredentials) {
        let email = format!("contacts-b-{}@example.test", uuid::Uuid::new_v4().simple());
        let password = uuid::Uuid::new_v4().to_string();
        let hasher = self.hasher.clone();
        let signup = register(&mut self.db, &hasher, &email, &password)
            .await
            .unwrap();
        verify_email(&mut self.db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let owner = login(&self.db, &hasher, &email, &password).await.unwrap();
        (signup.account_id, owner)
    }

    async fn drop_schema(&self) {
        self.admin
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn contacts_are_tenant_scoped_encrypted_and_duplicate_reviewed() {
    let mut owned = fixture(true).await;
    let create = |recipient: &str, name: Option<&str>, notes: Option<&str>| {
        json!({
            "recipient_e164": recipient,
            "display_name": name,
            "notes": notes,
        })
    };

    // Mutations need the exact Origin and a matching CSRF pair.
    let response = owned
        .send(post_json_no_origin(
            "/v1/owner/contacts",
            &owned.owner,
            &create("+15550100001", None, None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = owned
        .send(post_json_bad_csrf(
            "/v1/owner/contacts",
            &owned.owner,
            &create("+15550100001", None, None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Invalid routing identities never write a row.
    for invalid in ["5550100001", "+05550100002", "+1 555 010 0003 x9", ""] {
        let response = owned
            .send(post_json(
                "/v1/owner/contacts",
                &owned.owner,
                &create(invalid, None, None),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{invalid}");
    }
    let rows: i64 = owned
        .db
        .query_one("SELECT count(*) FROM contacts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "rejected requests must not write a contact");

    // Oversized free text is rejected before sealing.
    let oversized = json!({
        "recipient_e164": "+15550100001",
        "display_name": "n".repeat(NAME_MAX_BYTES + 1),
    });
    let response = owned
        .send(post_json("/v1/owner/contacts", &owned.owner, &oversized))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A valid create stores only ciphertext for the free-text fields.
    let response = owned
        .send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &create(
                "+1 555 010 0001",
                Some("Ada Lovelace"),
                Some("prefers morning"),
            ),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body(response).await;
    let contact_id: uuid::Uuid = serde_json::from_value(created["contact_id"].clone()).unwrap();
    assert_eq!(created["recipient_e164"], "+15550100001");
    assert_eq!(created["display_name"], "Ada Lovelace");
    let stored = owned
        .db
        .query_one(
            "SELECT display_name_ciphertext,notes_ciphertext FROM contacts WHERE id=$1",
            &[&contact_id],
        )
        .await
        .unwrap();
    let name_ciphertext: Vec<u8> = stored.get(0);
    let notes_ciphertext: Vec<u8> = stored.get(1);
    assert!(!name_ciphertext.is_empty());
    assert!(!notes_ciphertext.is_empty());
    assert!(
        !String::from_utf8_lossy(&name_ciphertext).contains("Ada"),
        "the name must be encrypted at rest"
    );
    assert!(!String::from_utf8_lossy(&notes_ciphertext).contains("morning"));

    // The equivalent-number duplicate is reported, never written twice.
    let response = owned
        .send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &create("+15550100001", Some("Other Name"), None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let duplicate = body(response).await;
    assert_eq!(duplicate["code"], "duplicate");
    assert_eq!(duplicate["existing_contact_id"], contact_id.to_string());
    let rows: i64 = owned
        .db
        .query_one("SELECT count(*) FROM contacts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);

    // Concurrent creates of one number commit exactly one row.
    let (left, right) = tokio::join!(
        owned.send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &create("+15550100009", None, None),
        )),
        owned.send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &create("+1-555-010-0009", None, None),
        )),
    );
    let mut statuses = vec![left.status(), right.status()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::CREATED, StatusCode::CONFLICT]);
    let rows: i64 = owned
        .db
        .query_one(
            "SELECT count(*) FROM contacts WHERE recipient_e164='+15550100009'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);

    // Listing and detail decrypt only for the owning account.
    let response = owned.send(get("/v1/owner/contacts", &owned.owner)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let list = body(response).await;
    let listed: Vec<Value> = serde_json::from_value(list["contacts"].clone()).unwrap();
    assert_eq!(listed.len(), 2);
    let detail = owned
        .send(get(
            &format!("/v1/owner/contacts/{contact_id}"),
            &owned.owner,
        ))
        .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = body(detail).await;
    assert_eq!(detail["display_name"], "Ada Lovelace");
    assert_eq!(detail["notes"], "prefers morning");
    assert_eq!(detail["consents"].as_array().map(Vec::len), Some(0));

    // Updates serialize on the row and replace exactly the fields carried.
    let response = owned
        .send(put_json(
            &format!("/v1/owner/contacts/{contact_id}"),
            &owned.owner,
            &json!({"notes": "prefers afternoon"}),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let updated = body(response).await;
    assert_eq!(updated["display_name"], "Ada Lovelace");
    assert_eq!(updated["notes"], "prefers afternoon");
    let cleared = owned
        .send(put_json(
            &format!("/v1/owner/contacts/{contact_id}"),
            &owned.owner,
            &json!({"display_name": null}),
        ))
        .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared = body(cleared).await;
    assert_eq!(cleared["display_name"], Value::Null);
    assert_eq!(cleared["notes"], "prefers afternoon");

    // Another account sees nothing of this contact.
    let (account_b, owner_b) = owned.owner_b().await;
    let response = owned
        .send(get(&format!("/v1/owner/contacts/{contact_id}"), &owner_b))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = owned
        .send(put_json(
            &format!("/v1/owner/contacts/{contact_id}"),
            &owner_b,
            &json!({"notes": "cross-account write"}),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = owned
        .send(request_with_cookies(
            "DELETE",
            &format!("/v1/owner/contacts/{contact_id}"),
            &owner_b,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let foreign: i64 = owned
        .db
        .query_one(
            "SELECT count(*) FROM contacts WHERE account_id=$1",
            &[&account_b],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(foreign, 0);

    // Deleting the contact removes the encrypted fields and cascades the
    // consent history; the suppression plane is untouched.
    owned
        .db
        .execute(
            "INSERT INTO contact_consent_records \
             (id,account_id,contact_id,purpose,action,source,effective_at,recorded_by) \
             SELECT $1,$2,$3,'transactional','grant','manual_entry',now(), \
             (SELECT user_id FROM memberships WHERE account_id=$2)",
            &[&uuid::Uuid::new_v4(), &owned.account_id, &contact_id],
        )
        .await
        .unwrap();
    let response = owned
        .send(request_with_cookies(
            "DELETE",
            &format!("/v1/owner/contacts/{contact_id}"),
            &owned.owner,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let remaining: i64 = owned
        .db
        .query_one("SELECT count(*) FROM contacts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(remaining, 1);
    let consent_rows: i64 = owned
        .db
        .query_one("SELECT count(*) FROM contact_consent_records", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(consent_rows, 0, "contact deletion cascades consent history");
    owned.drop_schema().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn csv_import_is_bounded_idempotent_and_writes_no_consent() {
    let owned = fixture(true).await;

    let wrong_type = Request::builder()
        .method("POST")
        .uri("/v1/owner/contacts/import")
        .header(header::COOKIE, cookies(&owned.owner))
        .header("x-zrotext-csrf", &owned.owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}".to_owned()))
        .unwrap();
    let response = owned.send(wrong_type).await;
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let bad_header = owned
        .send(post_csv(
            "/v1/owner/contacts/import",
            &owned.owner,
            "name,recipient\nAda,+15550100001",
        ))
        .await;
    assert_eq!(bad_header.status(), StatusCode::BAD_REQUEST);

    // Oversized bodies are refused before parsing.
    let oversized = [
        &b"recipient,name\n"[..],
        &vec![b'x'; csv::MAX_BODY_BYTES][..],
    ]
    .concat();
    let oversized_request = Request::builder()
        .method("POST")
        .uri("/v1/owner/contacts/import")
        .header(header::COOKIE, cookies(&owned.owner))
        .header("x-zrotext-csrf", &owned.owner.csrf_token)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "text/csv")
        .body(Body::from(oversized))
        .unwrap();
    let response = owned.send(oversized_request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // Mixed validity: an invalid number and an oversized name are reported
    // per row; the valid rows import; equivalent spellings collapse.
    let csv_body = "recipient,name,notes\n\
         +15550100001,Ada,\"prefers morning\"\n\
         5550100002,Invalid Row,\n\
         +1 555 010 0001,Duplicate Spelling,\n"
        .to_string()
        + &format!("+15550100003,{},\n", "n".repeat(NAME_MAX_BYTES + 1))
        + "+15550100004,Grace,\"said \"\"hi\"\"\"";
    let response = owned
        .send(post_csv(
            "/v1/owner/contacts/import",
            &owned.owner,
            &csv_body,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    assert_eq!(report["created"], 2);
    assert_eq!(report["duplicates"], 1);
    assert_eq!(report["invalid"], 2);
    let rows: Vec<Value> = serde_json::from_value(report["rows"].clone()).unwrap();
    assert_eq!(rows[0]["outcome"], "created");
    assert_eq!(rows[1]["outcome"], "invalid");
    assert_eq!(rows[1]["reason"], "invalid_recipient");
    assert_eq!(rows[2]["outcome"], "duplicate");
    assert_eq!(rows[2]["reason"], "duplicate_in_import");
    assert_eq!(rows[3]["outcome"], "invalid");
    assert_eq!(rows[3]["reason"], "field_too_large");
    assert_eq!(rows[4]["outcome"], "created");

    let stored = owned
        .db
        .query_one(
            "SELECT count(*),count(display_name_ciphertext),count(notes_ciphertext) \
             FROM contacts",
            &[],
        )
        .await
        .unwrap();
    let (total, named, noted): (i64, i64, i64) = (stored.get(0), stored.get(1), stored.get(2));
    assert_eq!((total, named, noted), (2, 2, 2));

    // Import never creates consent and never touches the suppression or
    // hold planes.
    for table in [
        "contact_consent_records",
        "recipient_suppressions",
        "owner_recipient_holds",
    ] {
        let rows: i64 = owned
            .db
            .query_one(&format!("SELECT count(*) FROM {table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 0, "importing a contact is not consent: {table}");
    }

    // A replay of the same file (import restart) reports every earlier row
    // as an existing duplicate and writes nothing new.
    let replay = owned
        .send(post_csv(
            "/v1/owner/contacts/import",
            &owned.owner,
            &csv_body,
        ))
        .await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay = body(replay).await;
    assert_eq!(replay["created"], 0);
    assert_eq!(replay["duplicates"], 3);
    assert_eq!(replay["invalid"], 2);
    let total_after: i64 = owned
        .db
        .query_one("SELECT count(*) FROM contacts", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(total_after, 2, "reimport must be idempotent");
    let replay_rows: Vec<Value> = serde_json::from_value(replay["rows"].clone()).unwrap();
    assert_eq!(replay_rows[0]["reason"], "duplicate_existing");

    // A vault-less deployment still imports routing metadata but refuses
    // any row that carries encrypted fields.
    let mut plain = fixture(false).await;
    let response = plain
        .send(post_csv(
            "/v1/owner/contacts/import",
            &plain.owner,
            "recipient,name\n+15550100005,Ada",
        ))
        .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bare = plain
        .send(post_csv(
            "/v1/owner/contacts/import",
            &plain.owner,
            "recipient,name\n+15550100006,",
        ))
        .await;
    assert_eq!(bare.status(), StatusCode::OK);

    // Cross-account isolation: a second account imports its own rows.
    let (account_b, owner_b) = plain.owner_b().await;
    let response = plain
        .send(post_csv(
            "/v1/owner/contacts/import",
            &owner_b,
            "recipient,name\n+15550100001,",
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = body(response).await;
    assert_eq!(report["created"], 1, "numbers are scoped per account");
    let foreign: i64 = plain
        .db
        .query_one(
            "SELECT count(*) FROM contacts WHERE account_id=$1",
            &[&account_b],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(foreign, 1);
    plain.drop_schema().await;
    owned.drop_schema().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn consent_records_track_purpose_expiry_and_withdrawal() {
    let mut owned = fixture(true).await;
    let response = owned
        .send(post_json(
            "/v1/owner/contacts",
            &owned.owner,
            &json!({"recipient_e164": "+15550100001"}),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let contact_id: uuid::Uuid =
        serde_json::from_value(body(response).await["contact_id"].clone()).unwrap();
    let consent_path = format!("/v1/owner/contacts/{contact_id}/consents");
    let now = test_now_ms();

    let grant = |purpose: &str, expiry_ms: Option<i64>| {
        json!({
            "purpose": purpose,
            "action": "grant",
            "source": "manual_entry",
            "effective_at_ms": now - 60_000,
            "expires_at_ms": expiry_ms,
        })
    };
    let withdraw = |purpose: &str| {
        json!({
            "purpose": purpose,
            "action": "withdraw",
            "source": "off_channel_record",
            "effective_at_ms": now - 30_000,
        })
    };

    // Marketing consent must carry an expiry; inconsistent times are
    // rejected as invalid; a withdrawal without any grant conflicts.
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("marketing", None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("transactional", Some(now - 120_000)),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &withdraw("transactional"),
        ))
        .await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "no grant to withdraw"
    );

    // An open-ended transactional grant and a bounded marketing grant.
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("transactional", None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("marketing", Some(now + 86_400_000)),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let states = states_by_purpose(&body(response).await["consents"]);
    assert_eq!(states["transactional"]["status"], "granted");
    assert_eq!(states["marketing"]["status"], "granted");

    // Granting an already-granted purpose conflicts, and one purpose's
    // grant never covers another.
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("marketing", Some(now + 86_400_000)),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &grant("operational", None),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let states = states_by_purpose(&body(response).await["consents"]);
    assert_eq!(states.len(), 3, "purposes are recorded separately");

    // Withdrawal closes a purpose; a second withdrawal conflicts;
    // re-granting after withdrawal is allowed.
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &withdraw("marketing"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let states = states_by_purpose(&body(response).await["consents"]);
    assert_eq!(states["marketing"]["status"], "withdrawn");
    assert_eq!(states["transactional"]["status"], "granted");
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &withdraw("marketing"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &json!({
                "purpose": "marketing", "action": "grant", "source": "manual_entry",
                "effective_at_ms": now - 10_000, "expires_at_ms": now + 3_600_000,
            }),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    // A grant whose expiry has passed reads as expired with no write, and
    // every event stays in the history. The re-grant takes effect after the
    // withdrawal (later effective time) but its bounded expiry is already
    // in the past.
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &withdraw("operational"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = owned
        .send(post_json(
            &consent_path,
            &owned.owner,
            &json!({
                "purpose": "operational",
                "action": "grant",
                "source": "manual_entry",
                "effective_at_ms": now - 20_000,
                "expires_at_ms": now - 10_000,
            }),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = owned
        .send(get(
            &format!("/v1/owner/contacts/{contact_id}"),
            &owned.owner,
        ))
        .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = body(detail).await;
    let states = states_by_purpose(&detail["consents"]);
    assert_eq!(states["operational"]["status"], "expired");
    let history: Vec<Value> = serde_json::from_value(detail["consent_history"].clone()).unwrap();
    assert!(history.len() >= 7, "every event stays in the history");

    // Consent for one contact is invisible from another account.
    let (_, owner_b) = owned.owner_b().await;
    let response = owned
        .send(post_json(
            &consent_path,
            &owner_b,
            &grant("marketing", Some(now + 3_600_000)),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // The recorder is the acting membership.
    let recorder: uuid::Uuid = owned
        .db
        .query_one(
            "SELECT recorded_by FROM contact_consent_records LIMIT 1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let member: uuid::Uuid = owned
        .db
        .query_one(
            "SELECT user_id FROM memberships WHERE account_id=$1",
            &[&owned.account_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recorder, member);
    owned.drop_schema().await;
}
