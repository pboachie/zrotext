// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::{
    auth::{SessionCredentials, TokenHasher, login, register, verify_email},
    http_owner_review::router,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::{Value, json};
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;

const ORIGIN: &str = "https://test.example";
const NOW_MS: i64 = 1_800_000_000_000;

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

// Holds are checked by admission and released by inbound, so these routes run
// on the complete schema. SQL is embedded at build time.
const TEST_MIGRATIONS: [(&str, &str); 39] = [
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
];

#[test]
fn hold_fixture_tracks_numbered_migrations() {
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

fn hold_body(value: Value) -> Result<HoldBody, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn hold_requests_accept_only_bounded_codes() {
    let valid = json!({
        "recipient_e164": "+15550200001", "channel": "phone_call",
        "reason": "consent_withdrawn", "reported_at_ms": NOW_MS,
    });
    let parsed = hold_body(valid.clone()).unwrap();
    assert_eq!(parsed.channel, Channel::PhoneCall);
    assert_eq!(parsed.reason, Reason::ConsentWithdrawn);
    // Free text never reaches storage: notes and unknown codes are rejected.
    let mut with_note = valid.clone();
    with_note["note"] = json!("recipient asked by email");
    assert!(hold_body(with_note).is_err());
    let mut sms_channel = valid.clone();
    sms_channel["channel"] = json!("sms");
    assert!(hold_body(sms_channel).is_err());
    let mut free_reason = valid;
    free_reason["reason"] = json!("they were upset");
    assert!(hold_body(free_reason).is_err());
    assert!(
        serde_json::from_value::<DecisionBody>(json!({
            "review_event_id": Uuid::new_v4(), "decision": "lift_stop",
        }))
        .is_err()
    );
    let decision: DecisionBody = serde_json::from_value(json!({
        "review_event_id": Uuid::new_v4(), "decision": "not_opt_out",
    }))
    .unwrap();
    assert_eq!(decision.decision, Decision::NotOptOut);
}

#[test]
fn hold_validation_bounds_recipient_and_report_time() {
    let hold = |recipient: &str, reported_at_ms: i64| HoldBody {
        recipient_e164: recipient.to_owned(),
        channel: Channel::Email,
        reason: Reason::OptOut,
        reported_at_ms,
    };
    assert!(valid_hold(&hold("+15550200001", NOW_MS), NOW_MS));
    assert!(valid_hold(&hold("+15550200001", NOW_MS + 60_000), NOW_MS));
    assert!(!valid_hold(
        &hold("+15550200001", NOW_MS + MAX_FUTURE_SKEW_MS + 1),
        NOW_MS
    ));
    assert!(!valid_hold(
        &hold("+15550200001", NOW_MS - MAX_REPORT_AGE_MS - 1),
        NOW_MS
    ));
    for invalid in [
        "",
        "+",
        "15550200001",
        "+05550200001",
        "+1555 0200001",
        "+1234567890123456",
    ] {
        assert!(!valid_hold(&hold(invalid, NOW_MS), NOW_MS), "{invalid}");
    }
}

async fn body(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
    if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn get(path: &str, owner: &SessionCredentials) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(
            header::COOKIE,
            format!("__Host-zrotext_session={}", owner.token),
        )
        .body(Body::empty())
        .unwrap()
}

fn post(
    path: &str,
    owner: &SessionCredentials,
    origin: Option<&str>,
    csrf: &str,
    payload: &Value,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(
            header::COOKIE,
            format!(
                "__Host-zrotext_session={}; __Host-zrotext_csrf={}",
                owner.token, owner.csrf_token
            ),
        )
        .header("x-zrotext-csrf", csrf)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    request.body(Body::from(payload.to_string())).unwrap()
}

/// A signed, attempt-bound withdrawal and its suppression row.
async fn signed_withdrawal(
    db: &Client,
    (account, device): (Uuid, Uuid),
    recipient: &str,
    source: &str,
    sequence: i64,
) -> Uuid {
    let (message, attempt, event) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,$4,$5,'synthetic_alpha','synthetic',$6,'submitted',now()+interval '1 hour')",
        &[&message, &account, &device, &recipient, &vec![1_u8; 32], &vec![2_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO message_attempts(id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
         VALUES($1,$2,$3,$4,1,1,1,'submitted')",
        &[&attempt, &account, &message, &device],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO inbound_events(id,account_id,device_id,message_id,attempt_id,device_sequence,classification,observed_at,part_count,content_kind,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,$5,$6,$7,now(),1,'metadata_only',$8,$9)",
        &[&event, &account, &device, &message, &attempt, &sequence,
            &if source == "sms_review" { "opt_out_review" } else { "opt_out" },
            &vec![3_u8; 32], &vec![4_u8; 8]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_event_id,source_attempt_id,source_observed_at,source) \
         VALUES($1,$2,TRUE,$3,$4,now(),$5)",
        &[&account, &recipient, &event, &attempt, &source],
    )
    .await
    .unwrap();
    event
}

async fn suppression_active(db: &Client, account: Uuid, recipient: &str) -> bool {
    db.query_one(
        "SELECT active FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2",
        &[&account, &recipient],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_holds_and_review_decisions_are_owner_bound_tenant_scoped_and_audited() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_hold_http_test_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for (name, migration) in TEST_MIGRATIONS {
        if name == "034_delivery_sweep_index.sql" {
            // Mirror the migrator's autocommit preparation before 034.
            db.batch_execute(
                "CREATE INDEX CONCURRENTLY messages_in_flight_updated \
                 ON messages(updated_at,id) \
                 WHERE state IN ('claimed','submitting','submitted')",
            )
            .await
            .unwrap();
        }
        db.batch_execute(migration)
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
    }
    let hasher = Arc::new(TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let mut owners = Vec::new();
    for label in ["hold-a", "hold-b"] {
        let email = format!("{label}@example.test");
        let password = Uuid::new_v4().to_string();
        let signup = register(&mut db, &hasher, &email, &password).await.unwrap();
        verify_email(&mut db, &hasher, &signup.verification_token)
            .await
            .unwrap();
        let session = login(&db, &hasher, &email, &password).await.unwrap();
        let device = Uuid::new_v4();
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'hold test phone')",
            &[&device, &signup.account_id],
        )
        .await
        .unwrap();
        owners.push((signup.account_id, device, session));
    }
    let (account_a, device_a, owner_a) = &owners[0];
    let (account_b, device_b, owner_b) = &owners[1];
    let review_a = signed_withdrawal(
        &db,
        (*account_a, *device_a),
        "+15550201001",
        "sms_review",
        1,
    )
    .await;
    let stop_a = signed_withdrawal(
        &db,
        (*account_a, *device_a),
        "+15550201002",
        "sms_keyword",
        2,
    )
    .await;
    let review_b = signed_withdrawal(
        &db,
        (*account_b, *device_b),
        "+15550201003",
        "sms_review",
        1,
    )
    .await;

    let app = router(OwnerReviewState {
        database_url,
        auth_hasher: hasher,
        canonical_origin: ORIGIN.to_owned(),
    });
    let send = |request: Request<Body>| {
        let app = app.clone();
        async move { app.oneshot(request).await.unwrap() }
    };
    let hold = |recipient: &str| {
        json!({
            "recipient_e164": recipient, "channel": "email", "reason": "opt_out",
            "reported_at_ms": now_ms().unwrap() - 60_000,
        })
    };

    // Mutations need the exact Origin and a matching CSRF token.
    let no_origin = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        None,
        &owner_a.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(no_origin.status(), StatusCode::FORBIDDEN);
    let wrong_origin = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some("https://attacker.example"),
        &owner_a.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(wrong_origin.status(), StatusCode::FORBIDDEN);
    let wrong_csrf = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some(ORIGIN),
        &owner_b.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(wrong_csrf.status(), StatusCode::FORBIDDEN);
    let mut noted = hold("+15550202000");
    noted["note"] = json!("free text is never stored");
    let noted = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some(ORIGIN),
        &owner_a.csrf_token,
        &noted,
    ))
    .await;
    assert!(noted.status().is_client_error());
    let invalid = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some(ORIGIN),
        &owner_a.csrf_token,
        &hold("5550202000"),
    ))
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    let holds: i64 = db
        .query_one("SELECT count(*) FROM owner_recipient_holds", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(holds, 0, "rejected requests must not write a hold");

    let queued = Uuid::new_v4();
    zrotext_delivery_store::DeliveryStore::new(&mut db)
        .accept(zrotext_delivery_store::NewMessage {
            account_id: *account_a,
            device_id: *device_a,
            client_message_id: queued,
            idempotency_key: "owner-hold-cancellation",
            recipient_e164: "+15550202000",
            synthetic_payload: b"synthetic queued message",
            expires_at_ms: now_ms().unwrap() + 60_000,
        })
        .await
        .unwrap();
    let created = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some(ORIGIN),
        &owner_a.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(created.headers()[header::CACHE_CONTROL], "no-store");
    let created = body(created).await;
    assert_eq!(created["cancelled_messages"], 1);
    let cancelled: String = db
        .query_one("SELECT state FROM messages WHERE id=$1", &[&queued])
        .await
        .unwrap()
        .get(0);
    assert_eq!(cancelled, "cancelled");
    let first_hold = created["hold_id"].as_str().unwrap().to_owned();
    let duplicate = send(post(
        "/v1/owner/opt-out-holds",
        owner_a,
        Some(ORIGIN),
        &owner_a.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    assert_eq!(body(duplicate).await["code"], "hold_active");
    // The same number is independent in another tenant.
    let other_tenant = send(post(
        "/v1/owner/opt-out-holds",
        owner_b,
        Some(ORIGIN),
        &owner_b.csrf_token,
        &hold("+15550202000"),
    ))
    .await;
    assert_eq!(other_tenant.status(), StatusCode::CREATED);
    // Allowed browser clock skew is clamped to the insert time.
    let mut ahead = hold("+15550202999");
    ahead["reported_at_ms"] = json!(now_ms().unwrap() + 60_000);
    let ahead = send(post(
        "/v1/owner/opt-out-holds",
        owner_b,
        Some(ORIGIN),
        &owner_b.csrf_token,
        &ahead,
    ))
    .await;
    assert_eq!(ahead.status(), StatusCode::CREATED);
    assert!(
        db.query_one(
            "SELECT reported_at=created_at FROM owner_recipient_holds WHERE recipient_e164='+15550202999'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    for index in 1..=20 {
        let response = send(post(
            "/v1/owner/opt-out-holds",
            owner_a,
            Some(ORIGIN),
            &owner_a.csrf_token,
            &hold(&format!("+1555020{index:04}")),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    let first_page = send(get("/v1/owner/opt-out-holds", owner_a)).await;
    assert_eq!(first_page.status(), StatusCode::OK);
    assert_eq!(first_page.headers()[header::CACHE_CONTROL], "no-store");
    let first_page = body(first_page).await;
    assert_eq!(first_page["holds"].as_array().unwrap().len(), 20);
    assert_eq!(first_page["holds"][0]["channel"], "email");
    assert_eq!(first_page["holds"][0]["reason"], "opt_out");
    let cursor = first_page["next_cursor"].as_str().unwrap().to_owned();
    let second_page = body(
        send(get(
            &format!("/v1/owner/opt-out-holds?before={cursor}"),
            owner_a,
        ))
        .await,
    )
    .await;
    assert_eq!(second_page["holds"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["holds"][0]["hold_id"], first_hold.as_str());
    assert!(second_page["next_cursor"].is_null());
    let b_page = body(send(get("/v1/owner/opt-out-holds", owner_b)).await).await;
    assert_eq!(b_page["holds"].as_array().unwrap().len(), 2);
    let foreign_cursor = send(get(
        &format!("/v1/owner/opt-out-holds?before={first_hold}"),
        owner_b,
    ))
    .await;
    assert_eq!(foreign_cursor.status(), StatusCode::NOT_FOUND);

    // Decisions apply only to this tenant's ambiguous review items.
    let decide = |owner: &SessionCredentials, event: Uuid, decision: &str| {
        post(
            "/v1/owner/opt-out-review/decisions",
            owner,
            Some(ORIGIN),
            &owner.csrf_token,
            &json!({"review_event_id": event, "decision": decision}),
        )
    };
    let no_csrf_decision = send(post(
        "/v1/owner/opt-out-review/decisions",
        owner_a,
        Some(ORIGIN),
        "wrong",
        &json!({"review_event_id": review_a, "decision": "not_opt_out"}),
    ))
    .await;
    assert_eq!(no_csrf_decision.status(), StatusCode::FORBIDDEN);
    let dismiss_stop = send(decide(owner_a, stop_a, "not_opt_out")).await;
    assert_eq!(dismiss_stop.status(), StatusCode::NOT_FOUND);
    let foreign_review = send(decide(owner_a, review_b, "not_opt_out")).await;
    assert_eq!(foreign_review.status(), StatusCode::NOT_FOUND);
    let dismissed = send(decide(owner_a, review_a, "not_opt_out")).await;
    assert_eq!(dismissed.status(), StatusCode::CREATED);
    let again = send(decide(owner_a, review_a, "confirmed_opt_out")).await;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    assert_eq!(body(again).await["code"], "already_decided");
    // A decision never lifts a suppression, and a signed STOP stays in force.
    assert!(suppression_active(&db, *account_a, "+15550201001").await);
    assert!(suppression_active(&db, *account_a, "+15550201002").await);
    assert!(
        db.execute(
            "INSERT INTO owner_opt_out_review_decisions(account_id,review_event_id,recipient_e164,decision,decided_by) \
             SELECT $1,$2,'+15550201002','not_opt_out',user_id FROM memberships WHERE account_id=$1",
            &[account_a, &stop_a],
        )
        .await
        .is_err(),
        "the database refuses a decision on a signed STOP"
    );
    let queue = body(send(get("/v1/owner/opt-out-review", owner_a)).await).await;
    let reviewed = queue["holds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["review_event_id"] == review_a.to_string().as_str())
        .unwrap();
    assert_eq!(reviewed["decision"], "not_opt_out");
    let queue_b = body(send(get("/v1/owner/opt-out-review", owner_b)).await).await;
    assert!(queue_b["holds"][0]["decision"].is_null());

    // Every owner action is audited, and the audit is append-only.
    let audits = db
        .query(
            "SELECT event,count(*) FROM owner_opt_out_audit WHERE account_id=$1 GROUP BY event ORDER BY event",
            &[account_a],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect::<Vec<_>>();
    assert_eq!(
        audits,
        [
            ("hold_created".to_owned(), 21),
            ("review_dismissed".to_owned(), 1)
        ]
    );
    for statement in [
        "UPDATE owner_opt_out_audit SET event='review_confirmed' WHERE account_id=$1",
        "DELETE FROM owner_opt_out_audit WHERE account_id=$1",
        "UPDATE owner_opt_out_review_decisions SET decision='confirmed_opt_out' WHERE account_id=$1",
        "DELETE FROM owner_opt_out_review_decisions WHERE account_id=$1",
        "DELETE FROM owner_recipient_holds WHERE account_id=$1",
    ] {
        assert!(
            db.execute(statement, &[account_a]).await.is_err(),
            "{statement}"
        );
    }
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
