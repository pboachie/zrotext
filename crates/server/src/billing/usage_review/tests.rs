// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use zrotext_delivery_store::{DeliveryStore, NewMessage, RadioEvent};
use zrotext_domain::Evidence;

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated schema, synthetic callbacks, no provider/radio calls"]
async fn exact_live_owner_review_is_immutable_and_revoked_cached_session_cannot_replay() {
    let url = std::env::var("ZT_AUTH_TEST_DATABASE_URL").unwrap();
    let (mut db, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let schema = format!("usage_review_test_{}", Uuid::new_v4().simple());
    db.batch_execute(&format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    ))
    .await
    .unwrap();
    crate::auth::test_schema::apply(&db).await;
    let hasher = TokenHasher::new(crate::test_keys::key(23)).unwrap();
    let password = crate::test_keys::password(4);
    let signup = auth::register(&mut db, &hasher, "usage-review@example.test", &password)
        .await
        .unwrap();
    auth::verify_email_with_password(&mut db, &hasher, &signup.verification_token, &password)
        .await
        .unwrap();
    let session = auth::login(&db, &hasher, "usage-review@example.test", &password)
        .await
        .unwrap();
    let owner = auth::authenticate_session(&db, &hasher, &session.token)
        .await
        .unwrap();
    let account = signup.account_id;
    let device = Uuid::new_v4();
    let message = Uuid::new_v4();
    db.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'synthetic phone')",
        &[&device, &account],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_SyntheticReview')",&[&account]).await.unwrap();
    db.execute("INSERT INTO billing_reconciliations(account_id,stripe_customer_id,stripe_subscription_id,processed_generation) VALUES($1,'cus_SyntheticReview','sub_SyntheticReview',1)",&[&account]).await.unwrap();
    db.execute("INSERT INTO usage_quota_policies(account_id,metric,source,limit_units) VALUES($1,'outbound_message','stripe_test',10)",&[&account]).await.unwrap();
    db.execute("INSERT INTO billing_usage_test_policies(account_id,policy_version,stripe_customer_id,meter_id,event_name,active) VALUES($1,1,'cus_SyntheticReview','mtr_SyntheticReview','synthetic_review',true)",&[&account]).await.unwrap();
    db.batch_execute("UPDATE deployment_authority SET dispatch_enabled=true")
        .await
        .unwrap();
    let now = db
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    let mut store = DeliveryStore::new(&mut db);
    store
        .accept_metered(NewMessage {
            account_id: account,
            device_id: device,
            client_message_id: message,
            idempotency_key: "review-action",
            recipient_e164: "+15551234567",
            synthetic_payload: b"synthetic only",
            expires_at_ms: now + 60_000,
        })
        .await
        .unwrap();
    let device_session = store
        .connect_session(account, device, "test", "test", 60)
        .await
        .unwrap();
    let claim = store
        .claim_due_for_device("test", account, device)
        .await
        .unwrap()
        .unwrap();
    let attempt = Uuid::new_v4();
    store
        .issue_grant(&claim, &device_session, attempt)
        .await
        .unwrap();
    let event = RadioEvent {
        event_id: Uuid::new_v4(),
        account_id: account,
        device_id: device,
        message_id: message,
        attempt_id: attempt,
        evidence: Evidence::DurableSubmitIntent,
        observed_at_ms: now,
        segment_index: None,
        segment_count: None,
    };
    store.record_radio_event(event).await.unwrap();
    store
        .record_radio_event(RadioEvent {
            event_id: Uuid::new_v4(),
            evidence: Evidence::SentCallbackOk,
            segment_index: Some(0),
            segment_count: Some(1),
            ..event
        })
        .await
        .unwrap();
    // Actual conflicting callback provenance parks the success for review.
    store
        .record_radio_event(RadioEvent {
            event_id: Uuid::new_v4(),
            evidence: Evidence::CallbackConflict,
            ..event
        })
        .await
        .unwrap();
    let context = ReviewContext {
        hasher: &hasher,
        cipher: None,
        canonical_origin: "https://test.example",
    };
    let request = ReviewRequest {
        message_id: message,
        request_id: Uuid::new_v4(),
        decision: "request_credit",
        reason: "uncertain_execution",
        password: &password,
        factor: None,
        origin: "https://test.example",
        csrf_cookie: &session.csrf_token,
        csrf_header: &session.csrf_token,
    };
    let bad = ReviewRequest {
        csrf_header: "wrong",
        ..request
    };
    assert!(matches!(
        record_request(&mut db, &owner, &context, &bad).await,
        Err(AuthError::Forbidden)
    ));
    let foreign = ReviewRequest {
        message_id: Uuid::new_v4(),
        ..request
    };
    assert!(matches!(
        record_request(&mut db, &owner, &context, &foreign).await,
        Err(AuthError::Unauthorized)
    ));
    // Reach the insert with a live owner, then stall the write beyond expiry.
    db.batch_execute("CREATE SEQUENCE review_insert_reached; CREATE FUNCTION delay_review_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('review_insert_reached'); PERFORM pg_sleep(6); RETURN NEW; END $$; CREATE TRIGGER delay_review_insert BEFORE INSERT ON billing_usage_adjustment_requests FOR EACH ROW EXECUTE FUNCTION delay_review_insert()").await.unwrap();
    db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    let expired_result = record_request(&mut db, &owner, &context, &request).await;
    assert!(
        db.query_one("SELECT is_called FROM review_insert_reached", &[])
            .await
            .unwrap()
            .get::<_, bool>(0),
        "owner reached the protected insert before expiring"
    );
    assert!(matches!(expired_result, Err(AuthError::Unauthorized)));
    assert_eq!(
        db.query_one(
            "SELECT count(*)::bigint FROM billing_usage_adjustment_requests",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    db.batch_execute("DROP TRIGGER delay_review_insert ON billing_usage_adjustment_requests; DROP FUNCTION delay_review_insert()").await.unwrap();
    db.execute(
        "UPDATE sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(
        record_request(&mut db, &owner, &context, &request)
            .await
            .unwrap()
    );
    assert!(
        !record_request(&mut db, &owner, &context, &request)
            .await
            .unwrap()
    );
    let changed = ReviewRequest {
        decision: "retain_charge",
        ..request
    };
    assert!(matches!(
        record_request(&mut db, &owner, &context, &changed).await,
        Err(AuthError::InvalidInput)
    ));
    let row=db.query_one("SELECT count(*)::bigint,sum(requested_units)::bigint FROM billing_usage_adjustment_requests WHERE account_id=$1",&[&account]).await.unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), -1);
    assert!(
        db.execute(
            "UPDATE billing_usage_adjustment_requests SET requested_units=0 WHERE account_id=$1",
            &[&account]
        )
        .await
        .is_err()
    );
    db.execute(
        "UPDATE sessions SET revoked_at=clock_timestamp() WHERE id=$1",
        &[&owner.session_id],
    )
    .await
    .unwrap();
    assert!(
        record_request(&mut db, &owner, &context, &request)
            .await
            .is_err()
    );
    db.batch_execute(&format!(
        "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
    ))
    .await
    .unwrap();
}
