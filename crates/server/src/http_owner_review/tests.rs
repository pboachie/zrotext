use super::*;
use crate::auth::{login, register, verify_email};
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use serde_json::Value;
use tokio_postgres::{Client, NoTls};
use tower::ServiceExt;

macro_rules! migration {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/compose/migrations/",
            $name
        ))
    };
}

const TEST_MIGRATIONS: [&str; 22] = [
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
    migration!("031_recipient_suppression.sql"),
    migration!("032_line_opt_out_events.sql"),
    migration!("033_sms_line_binding_scope.sql"),
];

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
    }
    request.body(Body::empty()).unwrap()
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 128 * 1024).await.unwrap()).unwrap()
}

async fn insert_attempt_hold(
    db: &Client,
    (account, device): (Uuid, Uuid),
    recipient: &str,
    source: &str,
    active: bool,
    sequence: i64,
    changed_seconds: i64,
) -> Uuid {
    let message = Uuid::new_v4();
    let attempt = Uuid::new_v4();
    let event = Uuid::new_v4();
    db.execute(
        "INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
         VALUES($1,$2,$3,$4,$5,'synthetic_alpha',$6,$7,'submitted',now()+interval '1 hour')",
        &[&message, &account, &device, &recipient, &vec![1_u8; 32],
            &b"PRIVATE_BODY_NEVER_EXPOSE".as_slice(), &vec![2_u8; 32]],
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
         VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8::bigint),1,'metadata_only',$9,$10)",
        &[&event, &account, &device, &message, &attempt, &sequence,
            &if source == "sms_review" { "opt_out_review" } else { "opt_out" },
            &changed_seconds, &vec![3_u8; 32], &vec![4_u8; 8]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_event_id,source_attempt_id,source_observed_at,source,changed_at) \
         VALUES($1,$2,$3,$4,$5,to_timestamp($7::bigint),$6,to_timestamp($7::bigint))",
        &[&account, &recipient, &active, &event, &attempt, &source, &changed_seconds],
    )
    .await
    .unwrap();
    event
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn review_queue_is_owner_only_tenant_bound_paginated_and_content_free() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (admin, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("owner_review_test_{}", Uuid::new_v4().simple());
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let database_url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&database_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for migration in TEST_MIGRATIONS {
        db.batch_execute(migration).await.unwrap();
    }
    let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(61)).unwrap());
    // Per-run test passwords avoid publishing reusable credential literals.
    let password_a = Uuid::new_v4().to_string();
    let password_b = Uuid::new_v4().to_string();
    let a = register(&mut db, &hasher, "review-a@example.test", &password_a)
        .await
        .unwrap();
    let b = register(&mut db, &hasher, "review-b@example.test", &password_b)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &a.verification_token)
        .await
        .unwrap();
    verify_email(&mut db, &hasher, &b.verification_token)
        .await
        .unwrap();
    let session_a = login(&db, &hasher, "review-a@example.test", &password_a)
        .await
        .unwrap();
    let session_b = login(&db, &hasher, "review-b@example.test", &password_b)
        .await
        .unwrap();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'A'),($3,$4,'B')",
        &[&device_a, &a.account_id, &device_b, &b.account_id],
    )
    .await
    .unwrap();
    let mut held_numbers = Vec::new();
    for index in 0..21 {
        let recipient = format!("+1555000{index:04}");
        held_numbers.push(recipient.clone());
        insert_attempt_hold(
            &db,
            (a.account_id, device_a),
            &recipient,
            "sms_review",
            true,
            index + 1,
            1_700_000_000 + index,
        )
        .await;
    }
    let foreign_event = insert_attempt_hold(
        &db,
        (b.account_id, device_b),
        "+15559990001",
        "sms_review",
        true,
        1,
        1_700_000_100,
    )
    .await;
    insert_attempt_hold(
        &db,
        (a.account_id, device_a),
        "+15559990002",
        "sms_review",
        false,
        22,
        1_700_000_101,
    )
    .await;
    insert_attempt_hold(
        &db,
        (a.account_id, device_a),
        "+15559990003",
        "sms_keyword",
        true,
        23,
        1_700_000_102,
    )
    .await;

    let line = Uuid::new_v4();
    let unsolicited_event = Uuid::new_v4();
    db.execute(
        "INSERT INTO phone_lines(id,account_id,state,approved_at,current_binding_generation,last_issued_generation) \
         VALUES($1,$2,'active',clock_timestamp(),1,1)",
        &[&line, &a.account_id],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,state,purpose,owner_approval_digest,device_confirmation_digest,activated_at) \
         VALUES($1,$2,$3,1,'active','sms',$4,$5,clock_timestamp())",
        &[&a.account_id, &line, &device_a, &vec![5_u8; 32], &vec![6_u8; 32]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO line_opt_out_events(id,account_id,device_id,line_id,binding_generation,device_sequence,recipient_e164,classification,observed_at,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,1,100,'+15559990004','opt_out_review',to_timestamp(1700000103),$5,$6)",
        &[&unsolicited_event, &a.account_id, &device_a, &line,
            &vec![7_u8; 32], &vec![8_u8; 8]],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO recipient_suppressions(account_id,recipient_e164,active,source_unsolicited_event_id,source_observed_at,source,changed_at) \
         VALUES($1,'+15559990004',true,$2,to_timestamp(1700000103),'sms_unsolicited_review',to_timestamp(1700000103))",
        &[&a.account_id, &unsolicited_event],
    )
    .await
    .unwrap();

    let app = router(OwnerReviewState {
        database_url,
        auth_hasher: hasher,
        canonical_origin: "https://test.example".to_owned(),
    });
    let anonymous = app
        .clone()
        .oneshot(get("/v1/owner/opt-out-review", None))
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.headers()[header::CACHE_CONTROL], "no-store");
    let first = app
        .clone()
        .oneshot(get("/v1/owner/opt-out-review", Some(&session_a.token)))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()[header::CACHE_CONTROL], "no-store");
    let first = body(first).await;
    assert_eq!(first["holds"].as_array().unwrap().len(), 20);
    assert_eq!(first["holds"][0]["source"], "sms_unsolicited_review");
    let cursor = first["next_cursor"].as_str().unwrap();
    assert!(Uuid::parse_str(cursor).is_ok());
    assert!(!cursor.contains('+'));
    let second = body(
        app.clone()
            .oneshot(get(
                &format!("/v1/owner/opt-out-review?before={cursor}"),
                Some(&session_a.token),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(second["holds"].as_array().unwrap().len(), 2);
    assert!(second["next_cursor"].is_null());
    let holds: Vec<_> = first["holds"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["holds"].as_array().unwrap().iter())
        .collect();
    assert_eq!(holds.len(), 22);
    assert!(
        held_numbers
            .iter()
            .all(|number| holds.iter().any(|hold| hold["recipient_e164"] == *number))
    );
    assert!(
        holds
            .iter()
            .all(|hold| hold.as_object().unwrap().len() == 4)
    );
    let text = serde_json::to_string(&holds).unwrap();
    for forbidden in [
        "+15559990001",
        "+15559990002",
        "+15559990003",
        "PRIVATE_BODY_NEVER_EXPOSE",
        &session_a.token,
        &session_b.token,
    ] {
        assert!(!text.contains(forbidden));
    }
    let foreign_cursor = app
        .clone()
        .oneshot(get(
            &format!("/v1/owner/opt-out-review?before={foreign_event}"),
            Some(&session_a.token),
        ))
        .await
        .unwrap();
    assert_eq!(foreign_cursor.status(), StatusCode::NOT_FOUND);
    assert_eq!(foreign_cursor.headers()[header::CACHE_CONTROL], "no-store");
    let b_page = body(
        app.clone()
            .oneshot(get("/v1/owner/opt-out-review", Some(&session_b.token)))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(b_page["holds"].as_array().unwrap().len(), 1);
    assert_eq!(b_page["holds"][0]["recipient_e164"], "+15559990001");
    let post = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/owner/opt-out-review")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    admin
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
