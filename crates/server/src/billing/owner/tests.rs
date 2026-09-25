use super::*;
use crate::{auth, http_auth::DisabledVerificationDispatcher};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use serde_json::Value;
use tower::ServiceExt;

fn get(path: &str, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder().uri(path);
    if let Some(token) = token {
        request = request.header(header::COOKIE, format!("__Host-zrotext_session={token}"));
    }
    request.body(Body::empty()).unwrap()
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_status_omits_provider_ids_and_foreign_tenant_rows() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    let schema = format!("billing_owner_test_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let db_url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&db_url, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await.unwrap() });
    for sql in [
        include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password_a = Uuid::new_v4().to_string();
    let password_b = Uuid::new_v4().to_string();
    let first = auth::register(&mut db, &hasher, "billing-view-a@example.test", &password_a)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &first.verification_token)
        .await
        .unwrap();
    let owner_a = auth::login(&db, &hasher, "billing-view-a@example.test", &password_a)
        .await
        .unwrap();
    let second = auth::register(&mut db, &hasher, "billing-view-b@example.test", &password_b)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &second.verification_token)
        .await
        .unwrap();
    let owner_b = auth::login(&db, &hasher, "billing-view-b@example.test", &password_b)
        .await
        .unwrap();
    let auth_state = AuthHttpState::new(
        db_url,
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = page_router(auth_state.clone()).nest("/v1/billing", status_router(auth_state));

    assert_eq!(
        app.clone()
            .oneshot(get("/billing", None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(get("/v1/billing/status", None))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    db.execute(
        "UPDATE billing_device_cap_config SET enabled=true WHERE singleton=true",
        &[],
    )
    .await
    .unwrap();
    let empty = app
        .clone()
        .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
        .await
        .unwrap();
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(empty.headers()[header::CACHE_CONTROL], "no-store");
    let empty: Value =
        serde_json::from_slice(&to_bytes(empty.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(empty["customerBound"], false);
    assert_eq!(empty["pendingReconciliations"], 0);
    assert_eq!(empty["subscriptions"].as_array().unwrap().len(), 0);
    assert_eq!(empty["deviceCapacity"]["enrollmentBlocked"], true);

    for (account, customer, subscription, status, recognized, dirty, processed) in [
        (
            first.account_id,
            "cus_OwnerA",
            "sub_OwnerA",
            "past_due",
            false,
            2_i64,
            1_i64,
        ),
        (
            second.account_id,
            "cus_OwnerB",
            "sub_OwnerB",
            "active",
            true,
            1_i64,
            1_i64,
        ),
    ] {
        db.execute(
            "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,$2)",
            &[&account, &customer],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES($1,$2,$3,$4,$5)", &[&subscription, &account, &customer, &dirty, &processed]).await.unwrap();
        db.execute("INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price,payment_grace_started_at,latest_invoice_id,payment_grace_invoice_id) VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $4='past_due' THEN now()-interval '1 day' ELSE NULL END,CASE WHEN $4='past_due' THEN 'in_OwnerA' ELSE NULL END,CASE WHEN $4='past_due' THEN 'in_OwnerA' ELSE NULL END)", &[&subscription, &account, &customer, &status, &"price_Private", &recognized]).await.unwrap();
    }
    db.execute(
        "INSERT INTO billing_device_caps(account_id,limit_devices) VALUES($1,1)",
        &[&first.account_id],
    )
    .await
    .unwrap();
    for _ in 0..2 {
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test device')",
            &[&Uuid::new_v4(), &first.account_id],
        )
        .await
        .unwrap();
    }
    let response = app
        .clone()
        .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    let status: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["mode"], "test");
    assert_eq!(status["customerBound"], true);
    assert_eq!(status["pendingReconciliations"], 1);
    assert_eq!(status["subscriptions"].as_array().unwrap().len(), 1);
    assert_eq!(status["subscriptions"][0]["stripeStatus"], "past_due");
    assert_eq!(status["subscriptions"][0]["recognizedTestPrice"], false);
    assert_eq!(status["subscriptions"][0]["reconciliationPending"], true);
    assert!(
        status["subscriptions"][0]["paymentGraceEndsAtUnix"]
            .as_i64()
            .is_some()
    );
    assert_eq!(status["deviceCapacity"]["limit"], 1);
    assert_eq!(status["deviceCapacity"]["active"], 2);
    assert_eq!(status["deviceCapacity"]["overLimit"], true);
    assert_eq!(status["deviceCapacity"]["enrollmentBlocked"], true);
    for secret in [
        "cus_OwnerA",
        "sub_OwnerA",
        "cus_OwnerB",
        "sub_OwnerB",
        "price_Private",
        "\"stripeStatus\":\"active\"",
        &first.account_id.to_string(),
        &second.account_id.to_string(),
    ] {
        assert!(
            !text.contains(secret),
            "billing status exposed a provider identifier"
        );
    }
    let other = app
        .clone()
        .oneshot(get("/v1/billing/status", Some(&owner_b.token)))
        .await
        .unwrap();
    let other: Value =
        serde_json::from_slice(&to_bytes(other.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(other["subscriptions"][0]["stripeStatus"], "active");
    assert_eq!(other["pendingReconciliations"], 0);
    assert_eq!(other["deviceCapacity"]["limit"], Value::Null);
    assert_eq!(other["deviceCapacity"]["active"], 0);
    assert_eq!(other["deviceCapacity"]["enrollmentBlocked"], true);

    let page = app
        .clone()
        .oneshot(get("/billing", Some(&owner_a.token)))
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        page.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    assert!(
        page.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(
        page.headers()[header::STRICT_TRANSPORT_SECURITY],
        "max-age=63072000; includeSubDomains"
    );
    let page = to_bytes(page.into_body(), 4096).await.unwrap();
    assert!(
        std::str::from_utf8(&page)
            .unwrap()
            .contains("/billing/dashboard.js")
    );
    let asset = app
        .clone()
        .oneshot(get("/billing/dashboard.js", None))
        .await
        .unwrap();
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        asset.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );

    db.execute(
        "UPDATE sessions SET revoked_at=now() WHERE account_id=$1",
        &[&first.account_id],
    )
    .await
    .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(get("/v1/billing/status", Some(&owner_a.token)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(get("/billing", Some(&owner_a.token)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_status_reports_projected_entitlement_and_ambiguity() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("billing_entitlement_{}", Uuid::new_v4().simple());
    setup
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let db_url = format!("{base_url}?options=-csearch_path%3D{schema}");
    let (mut db, connection) = tokio_postgres::connect(&db_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    for sql in [
        include_str!("../../../../../deploy/compose/migrations/001_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/002_auth.sql"),
        include_str!("../../../../../deploy/compose/migrations/003_delivery.sql"),
        include_str!("../../../../../deploy/compose/migrations/004_enrollment.sql"),
        include_str!("../../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        include_str!("../../../../../deploy/compose/migrations/006_usage_metering.sql"),
        include_str!("../../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
        include_str!("../../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
        include_str!("../../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
        include_str!("../../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
        include_str!("../../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
        include_str!("../../../../../deploy/compose/migrations/013_owner_mfa.sql"),
        include_str!("../../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
        include_str!("../../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let signup = auth::register(&mut db, &hasher, "billing-view-c@example.test", &password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let owner = auth::login(&db, &hasher, "billing-view-c@example.test", &password)
        .await
        .unwrap();
    let auth_state = AuthHttpState::new(
        db_url,
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = status_router(auth_state);
    let account = signup.account_id;

    // Before any billing state, nothing has been projected.
    let response = app
        .clone()
        .oneshot(get("/status", Some(&owner.token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let fresh: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(fresh["nonterminalSubscriptions"], 0);
    assert_eq!(fresh["projectedEntitlement"]["reason"], Value::Null);
    assert_eq!(fresh["projectedEntitlement"]["outboundLimit"], Value::Null);
    assert_eq!(fresh["projectedEntitlement"]["deviceCap"], Value::Null);
    assert_eq!(fresh["projectedEntitlement"]["paymentHold"], false);

    db.execute(
        "UPDATE billing_device_cap_config SET enabled=true WHERE singleton=true",
        &[],
    )
    .await
    .unwrap();
    db.execute(
        "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_EntA')",
        &[&account],
    )
    .await
    .unwrap();
    for (subscription, status) in [("sub_Ent1", "active"), ("sub_Ent2", "past_due")] {
        db.execute(
                "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id) VALUES($1,$2,'cus_EntA')",
                &[&subscription, &account],
            )
            .await
            .unwrap();
        db.execute(
                "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price) VALUES($1,$2,'cus_EntA',$3,'price_Private',true)",
                &[&subscription, &account, &status],
            )
            .await
            .unwrap();
    }
    db.execute(
            "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',0,'stripe_test')",
            &[&account],
        )
        .await
        .unwrap();
    db.execute(
        "INSERT INTO billing_device_caps(account_id,limit_devices) VALUES($1,0)",
        &[&account],
    )
    .await
    .unwrap();
    db.execute(
            "INSERT INTO billing_quota_audit(account_id,stripe_subscription_id,reconciliation_generation,previous_limit_units,limit_units,reason) VALUES($1,'sub_Ent1',1,5,5,'active'),($1,'sub_Ent2',2,5,0,'ambiguous')",
            &[&account],
        )
        .await
        .unwrap();
    db.execute(
            "INSERT INTO billing_events(stripe_event_id,event_type,object_id,stripe_customer_id,account_id,body_sha256,disposition) VALUES('evt_EntHold1','refund.created','re_EntHold1','cus_EntA',$1,decode('0000000000000000000000000000000000000000000000000000000000000000','hex'),'queued')",
            &[&account],
        )
        .await
        .unwrap();
    db.execute(
            "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,state,account_id) VALUES('evt_EntHold1','ch_EntHold1','refund','held',$1)",
            &[&account],
        )
        .await
        .unwrap();
    db.execute(
            "INSERT INTO billing_payment_holds(stripe_event_id,account_id,stripe_subscription_id,stripe_charge_id,reason) VALUES('evt_EntHold1',$1,'sub_Ent1','ch_EntHold1','refund')",
            &[&account],
        )
        .await
        .unwrap();

    let response = app
        .oneshot(get("/status", Some(&owner.token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    let status: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["nonterminalSubscriptions"], 2);
    assert_eq!(status["projectedEntitlement"]["reason"], "ambiguous");
    assert_eq!(status["projectedEntitlement"]["outboundLimit"], 0);
    assert_eq!(status["projectedEntitlement"]["deviceCap"], 0);
    assert_eq!(status["projectedEntitlement"]["paymentHold"], true);
    for secret in [
        "cus_EntA",
        "sub_Ent1",
        "sub_Ent2",
        "price_Private",
        "evt_EntHold1",
        "ch_EntHold1",
        &account.to_string(),
    ] {
        assert!(
            !text.contains(secret),
            "billing status exposed a provider identifier"
        );
    }
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
