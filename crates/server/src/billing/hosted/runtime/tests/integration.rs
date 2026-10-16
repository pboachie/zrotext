// SPDX-License-Identifier: AGPL-3.0-only
use super::{fixture::*, *};
use axum::{body::to_bytes, http::StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn value(response: axum::response::Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
}
async fn status(f: &Fixture, r: &Arc<Runtime>) -> Value {
    value(
        r.router()
            .oneshot(f.request("/status", "GET"))
            .await
            .unwrap(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; ordinary owner HTTP and cached catalog fixture"]
async fn owner_status_accepts_normal_get_without_origin_and_public_catalog_never_spends_provider_requests()
 {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    assert_eq!(status(&f, &r).await["customer_bound"], false);
    let mut request = f.request("/status", "GET");
    request.headers_mut().remove("origin");
    assert_eq!(
        r.router().oneshot(request).await.unwrap().status(),
        StatusCode::OK
    );
    let mut missing = f.request("/status", "GET");
    missing.headers_mut().remove("x-zrotext-csrf");
    assert_eq!(
        r.router().oneshot(missing).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let mut mismatch = f.request("/status", "GET");
    mismatch
        .headers_mut()
        .insert("x-zrotext-csrf", "wrong".parse().unwrap());
    assert_eq!(
        r.router().oneshot(mismatch).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let calls = f.fake.inner.lock().unwrap().requests.len();
    for _ in 0..10 {
        assert_eq!(
            r.router()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/plan")
                        .body(axum::body::Body::empty())
                        .unwrap()
                )
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(f.fake.inner.lock().unwrap().requests.len(), calls);
    r.provider.expire_catalog().await;
    assert_eq!(
        r.router()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/plan")
                    .body(axum::body::Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        f.fake.inner.lock().unwrap().requests.len(),
        calls,
        "an expired public snapshot never triggers provider I/O"
    );
    f.fake.inner.lock().unwrap().active = false;
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        f.fake.inner.lock().unwrap().operations.is_empty(),
        "an archived price cannot create a checkout using cached terms"
    );
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated due-customer fairness fixture"]
async fn disabled_earliest_customer_does_not_starve_an_active_customer() {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    let disabled = Uuid::new_v4();
    f.admin
        .execute("INSERT INTO accounts(id) VALUES($1)", &[&disabled])
        .await
        .unwrap();
    f.admin.execute("INSERT INTO hosted_billing_customers(namespace_id,account_id,customer_id,next_attempt_at) VALUES($1,$2,'cus_disabled',0)",&[&f.namespace,&disabled]).await.unwrap();
    f.admin
        .execute(
            "UPDATE accounts SET disabled_at=clock_timestamp() WHERE id=$1",
            &[&disabled],
        )
        .await
        .unwrap();
    f.admin
        .execute(
            "UPDATE hosted_billing_customers SET next_attempt_at=1 WHERE account_id=$1",
            &[&f.owner.tenant.account_id()],
        )
        .await
        .unwrap();
    assert!(worker::run_one(&r).await.unwrap());
    let processed: i64 = f
        .admin
        .query_one(
            "SELECT processed_generation FROM hosted_billing_customers WHERE account_id=$1",
            &[&f.owner.tenant.account_id()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(processed > 0);
    assert_eq!(
        f.admin
            .query_one(
                "SELECT processed_generation FROM hosted_billing_customers WHERE account_id=$1",
                &[&disabled]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; provider-confirmed expired attempt fixture"]
async fn expired_checkout_is_replaceable_only_after_complete_reconciliation_and_explicit_post() {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    f.fake.inner.lock().unwrap().checkout.as_mut().unwrap()["status"] = json!("expired");
    assert_eq!(
        status(&f, &r).await["checkout"]["state"],
        "reconciliation_required"
    );
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_eq!(status(&f, &r).await["checkout"]["state"], "replaceable");
    assert_eq!(
        f.fake.inner.lock().unwrap().operations.len(),
        1,
        "status and worker never create checkout sessions"
    );
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    {
        let s = f.fake.inner.lock().unwrap();
        assert_eq!(s.operations.len(), 2);
        assert_ne!(s.operations[0], s.operations[1]);
    }
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated fake-provider PostgreSQL runtime"]
async fn protected_backend_proof_rejects_forged_settings_wrong_keys_shadow_tables_and_privileged_roles()
 {
    let f = Fixture::new(Mode::Live).await;
    let app = connect(&f.app_url).await;
    assert!(
        app.query_one("SELECT hosted_runtime_role_safe()", &[])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    app.batch_execute(&format!(
        "SET zrotext.hosted_namespace='{}';SET zrotext.hosted_revision='1'",
        f.namespace
    ))
    .await
    .unwrap();
    assert!(
        app.query_one("SELECT hosted_runtime_marker()", &[])
            .await
            .is_err()
    );
    assert!(
        app.query_one("SELECT * FROM hosted_runtime_secrets", &[])
            .await
            .is_err()
    );
    app.batch_execute("CREATE TEMP TABLE hosted_runtime_secrets(namespace_id uuid,runtime_key bytea); CREATE TEMP TABLE hosted_runtime_sessions(backend_pid int,verified bool)").await.unwrap();
    app.query_one("SELECT hosted_runtime_challenge($1,1)", &[&f.namespace])
        .await
        .unwrap();
    assert!(
        !app.query_one("SELECT hosted_runtime_bind($1,1,NULL)", &[&f.namespace])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    assert!(
        app.query_one("SELECT (hosted_runtime_marker()).namespace_id", &[])
            .await
            .is_err()
    );
    app.query_one("SELECT hosted_runtime_challenge($1,1)", &[&f.namespace])
        .await
        .unwrap();
    assert!(
        !app.query_one(
            "SELECT hosted_runtime_bind($1,1,$2)",
            &[&f.namespace, &&[0u8; 32][..]]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert!(
        app.query_one("SELECT hosted_runtime_marker()", &[])
            .await
            .is_err()
    );
    assert!(
        f.admin
            .query_one("SELECT hosted_runtime_challenge($1,1)", &[&f.namespace])
            .await
            .is_err()
    );
    let r = f.runtime(Mode::Live).await;
    let db = crate::runtime_db::connect(&f.app_url).await.unwrap();
    let namespace: Uuid = db
        .query_one("SELECT (hosted_runtime_marker()).namespace_id", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(namespace, f.namespace);
    // Freshening a checkout consumes the old trust before verifying the next.
    db.query_one("SELECT hosted_runtime_challenge($1,1)", &[&f.namespace])
        .await
        .unwrap();
    assert!(
        db.query_one("SELECT (hosted_runtime_marker()).namespace_id", &[])
            .await
            .is_err()
    );
    drop(db);
    // A raw/older connection cannot gain paid admission by naming the public
    // namespace. Only the protected proof registry can admit this backend.
    assert!(
        app.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Unverified phone')",
            &[&Uuid::new_v4(), &f.owner.tenant.account_id()]
        )
        .await
        .is_err()
    );
    let db = crate::runtime_db::connect(&f.app_url).await.unwrap();
    assert!(
        db.query_one("SELECT (hosted_runtime_marker()).namespace_id", &[])
            .await
            .is_ok()
    );
    let pid: i32 = db
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0);
    f.admin.execute("UPDATE hosted_runtime_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE backend_pid=$1",&[&pid]).await.unwrap();
    assert!(
        db.query_one("SELECT (hosted_runtime_marker()).namespace_id", &[])
            .await
            .is_err()
    );
    drop(db);
    f.admin
        .execute(
            "UPDATE hosted_billing_namespaces SET policy_revision=2",
            &[],
        )
        .await
        .unwrap();
    assert!(crate::runtime_db::connect(&f.app_url).await.is_err());
    drop(r);
    drop(app);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated fake-provider PostgreSQL runtime"]
async fn hosted_checkout_recovers_lost_results_and_restart_without_duplicate_attempts_then_meters_paid_access()
 {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    f.fake.inner.lock().unwrap().lose_checkout = true;
    assert_eq!(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    // A process restart clears only the transport pause, never the operation.
    let r = f.runtime(Mode::Live).await;
    assert_eq!(status(&f, &r).await["checkout"]["state"], "recoverable");
    for _ in 0..3 {
        assert_eq!(status(&f, &r).await["checkout"]["state"], "recoverable");
    }
    assert_eq!(
        f.fake.inner.lock().unwrap().operations.len(),
        1,
        "GET never replays a provider operation"
    );
    let first = value(
        r.router()
            .oneshot(f.request("/checkout/recover", "POST"))
            .await
            .unwrap(),
    )
    .await;
    let second = value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(first, second);
    assert_eq!(
        first["url"],
        f.fake.inner.lock().unwrap().checkout.as_ref().unwrap()["url"]
    );
    assert_eq!(
        first["url"],
        "https://checkout.stripe.com/c/pay/cs_fixture#fidkdWxOYHwnPyd1blppbHNgWjA0YHc2THZfZ2pzTGM9N2lL"
    );
    {
        let s = f.fake.inner.lock().unwrap();
        assert_eq!(s.operations.len(), 2);
        assert_eq!(s.operations[0], s.operations[1]);
    }
    assert_eq!(status(&f, &r).await["checkout"]["state"], "resumable");
    assert_eq!(status(&f, &r).await["customer_bound"], true);
    f.fake.inner.lock().unwrap().checkout.as_mut().unwrap()["status"] = json!("complete");
    assert_eq!(
        status(&f, &r).await["checkout"]["state"],
        "reconciliation_required"
    );
    assert_eq!(status(&f, &r).await["entitlement"]["phase"], "pending");
    let now = f.now().await;
    f.fake.subscription(now, "active");
    f.due().await;
    assert!(worker::run_one(&r).await.unwrap());
    f.due().await;
    assert!(worker::run_one(&r).await.unwrap());
    let view = status(&f, &r).await;
    assert_eq!(view["entitlement"]["phase"], "active");
    assert_eq!(view["mode"], "live");
    assert_eq!(view["account_id"], f.owner.tenant.account_id().to_string());
    let mut db = crate::runtime_db::connect(&f.app_url).await.unwrap();
    let account = f.owner.tenant.account_id();
    let d1 = Uuid::new_v4();
    let d2 = Uuid::new_v4();
    for device in [d1, d2] {
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Synthetic phone')",
            &[&device, &account],
        )
        .await
        .unwrap();
    }
    assert!(
        db.execute(
            "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'Over cap')",
            &[&Uuid::new_v4(), &account]
        )
        .await
        .is_err()
    );
    for _ in 0..10 {
        let tx = db.transaction().await.unwrap();
        tx.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+'||'1'||repeat('0',8)||'1',decode(repeat('00',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('01',32),'hex'),'queued',clock_timestamp()+interval '1 hour')",&[&Uuid::new_v4(),&account,&d1]).await.unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(
        db.query_one(
            "SELECT sum(units)::bigint FROM usage_ledger WHERE account_id=$1",
            &[&account]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        10
    );
    assert!(db.execute("INSERT INTO messages(id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) VALUES($1,$2,$3,'+'||'1'||repeat('0',8)||'1',decode(repeat('00',32),'hex'),'synthetic_alpha',decode('01','hex'),decode(repeat('01',32),'hex'),'queued',clock_timestamp()+interval '1 hour')",&[&Uuid::new_v4(),&account,&d1]).await.is_err());
    drop(db);
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated fake-provider PostgreSQL runtime"]
async fn startup_identity_mismatch_and_colliding_test_live_provider_ids_never_share_authority() {
    let f = Fixture::new(Mode::Live).await;
    let start = |o| {
        Runtime::start_with(
            f.auth.clone(),
            o,
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
            provider::Provider::fake(f.base.clone()),
        )
    };
    assert!(matches!(
        start(options(Mode::Test)).await,
        Err(Error::Identity)
    ));
    let mut wrong = options(Mode::Live);
    wrong.runtime_key = [8; 32];
    assert!(matches!(start(wrong).await, Err(Error::Identity)));
    let mut wrong = options(Mode::Live);
    wrong.namespace = Namespace::new([2; 16], Mode::Live, "acct_fixture").unwrap();
    assert!(matches!(start(wrong).await, Err(Error::Identity)));
    f.fake.inner.lock().unwrap().account = "acct_foreign".into();
    assert!(matches!(
        start(options(Mode::Live)).await,
        Err(Error::Identity)
    ));
    f.fake.inner.lock().unwrap().account = "acct_fixture".into();
    let live = f.runtime(Mode::Live).await;
    assert!(
        crate::runtime_db::require_unscoped(&f.app_url)
            .await
            .is_err()
    );
    let test = Fixture::new(Mode::Test).await;
    let test_runtime = test.runtime(Mode::Test).await;
    for (fixture, runtime) in [(&f, &live), (&test, &test_runtime)] {
        value(
            runtime
                .router()
                .oneshot(fixture.request("/checkout", "POST"))
                .await
                .unwrap(),
        )
        .await;
    }
    assert_eq!(status(&f, &live).await["mode"], "live");
    assert_eq!(status(&test, &test_runtime).await["mode"], "test");
    assert_ne!(
        status(&f, &live).await["account_id"],
        status(&test, &test_runtime).await["account_id"]
    );
    // Same opaque customer/session/price IDs exist in separate mode databases.
    assert_eq!(
        f.admin
            .query_one("SELECT customer_id FROM hosted_billing_customers", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        test.admin
            .query_one("SELECT customer_id FROM hosted_billing_customers", &[])
            .await
            .unwrap()
            .get::<_, String>(0)
    );
    drop(live);
    drop(test_runtime);
    f.cleanup().await;
    test.cleanup().await;
}

async fn event(
    f: &Fixture,
    r: &Arc<Runtime>,
    kind: &str,
    eid: &str,
    created: i64,
    object: Value,
) -> StatusCode {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let value = json!({"object":"event","id":eid,"livemode":true,"api_version":crate::billing::risk::STRIPE_API_VERSION,"type":kind,"created":created,"data":{"object":object}});
    f.fake
        .inner
        .lock()
        .unwrap()
        .events
        .insert(eid.into(), value.clone());
    let body = serde_json::to_vec(&value).unwrap();
    let now = f.now().await;
    let mut mac = Hmac::<Sha256>::new_from_slice(super::webhook_secret().as_bytes()).unwrap();
    mac.update(now.to_string().as_bytes());
    mac.update(b".");
    mac.update(&body);
    let sig = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    r.router()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/stripe-events")
                .header("stripe-signature", format!("t={now},v1={sig}"))
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}
#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; isolated fake-provider PostgreSQL runtime"]
async fn signed_failure_grace_survives_duplicate_invoice_change_restart_and_outage_without_extension()
 {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    let now = f.now().await;
    f.fake.subscription(now, "active");
    for _ in 0..2 {
        f.due().await;
        worker::run_one(&r).await.unwrap();
    }
    f.fake.subscription(now, "past_due");
    let failed_at = f.now().await + 1;
    let invoice = f.fake.inner.lock().unwrap().invoice.clone();
    assert_eq!(
        event(
            &f,
            &r,
            "invoice.payment_failed",
            "evt_failure",
            failed_at,
            invoice.clone()
        )
        .await,
        StatusCode::NO_CONTENT
    );
    f.due().await;
    worker::run_one(&r).await.unwrap();
    let first = status(&f, &r).await;
    assert_eq!(first["entitlement"]["phase"], "grace");
    let anchor = first["entitlement"]["first_failure_at_ms"].clone();
    assert!(!anchor.is_null());
    let generation: i64 = f
        .admin
        .query_one("SELECT queue_generation FROM hosted_billing_customers", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        event(
            &f,
            &r,
            "invoice.payment_failed",
            "evt_failure",
            failed_at,
            invoice
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.admin
            .query_one("SELECT queue_generation FROM hosted_billing_customers", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        generation
    );
    {
        let mut s = f.fake.inner.lock().unwrap();
        s.subscriptions["data"][0]["latest_invoice"] = json!("in_next");
        s.invoice["id"] = json!("in_next");
        s.invoice["lines"]["data"][0]["invoice"] = json!("in_next");
    }
    let invoice = f.fake.inner.lock().unwrap().invoice.clone();
    assert_eq!(
        event(
            &f,
            &r,
            "invoice.payment_failed",
            "evt_next_failure",
            now + 20,
            invoice
        )
        .await,
        StatusCode::NO_CONTENT
    );
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_eq!(
        status(&f, &r).await["entitlement"]["first_failure_at_ms"],
        anchor
    );
    let r = f.runtime(Mode::Live).await;
    f.fake.inner.lock().unwrap().outage = true;
    f.due().await;
    assert_eq!(worker::run_one(&r).await, Err(Error::Provider));
    assert_eq!(
        f.admin
            .query_one(
                "SELECT first_failure_at FROM hosted_billing_projections",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            * 1000,
        anchor.as_i64().unwrap()
    );
    f.fake.inner.lock().unwrap().outage = false;
    r.provider.unpause();
    let pending = status(&f, &r).await;
    assert_eq!(pending["entitlement"]["phase"], "pending");
    assert!(pending["reconciliation_pending"].as_bool().unwrap());
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_eq!(
        status(&f, &r).await["entitlement"]["first_failure_at_ms"],
        anchor
    );
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; in-flight generation and bounded provider list fixture"]
async fn intervening_event_invalidates_in_flight_reads_and_partial_lists_cannot_restore_access() {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    let now = f.now().await;
    f.fake.subscription(now, "active");
    for _ in 0..2 {
        f.due().await;
        worker::run_one(&r).await.unwrap();
    }
    assert_eq!(status(&f, &r).await["entitlement"]["phase"], "active");
    let pause = Arc::new(ReadPause {
        started: Notify::new(),
        release: Notify::new(),
    });
    *f.fake.pause.lock().unwrap() = Some(pause.clone());
    f.due().await;
    let pending = {
        let r = r.clone();
        tokio::spawn(async move { worker::run_one(&r).await })
    };
    tokio::time::timeout(Duration::from_secs(5), pause.started.notified())
        .await
        .unwrap();
    let subscription = f.fake.inner.lock().unwrap().subscriptions["data"][0].clone();
    assert_eq!(
        event(
            &f,
            &r,
            "customer.subscription.updated",
            "evt_intervening",
            now,
            subscription
        )
        .await,
        StatusCode::NO_CONTENT
    );
    pause.release.notify_one();
    assert_eq!(pending.await.unwrap(), Err(Error::Pending));
    assert_eq!(status(&f, &r).await["entitlement"]["phase"], "pending");
    f.fake.inner.lock().unwrap().subscriptions["has_more"] = json!(true);
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_ne!(status(&f, &r).await["entitlement"]["phase"], "active");
    f.fake.inner.lock().unwrap().subscriptions["has_more"] = json!(false);
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_eq!(status(&f, &r).await["entitlement"]["phase"], "active");
    drop(r);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; durable review and operator resolution fixture"]
async fn unbound_risk_blocks_access_and_only_audited_operator_resolution_then_fresh_read_can_restore_it()
 {
    let f = Fixture::new(Mode::Live).await;
    let r = f.runtime(Mode::Live).await;
    value(
        r.router()
            .oneshot(f.request("/checkout", "POST"))
            .await
            .unwrap(),
    )
    .await;
    let now = f.now().await;
    f.fake.subscription(now, "active");
    for _ in 0..2 {
        f.due().await;
        worker::run_one(&r).await.unwrap();
    }
    let unsupported = json!({"object":"refund","id":"re_unbound","livemode":true});
    assert_eq!(
        event(
            &f,
            &r,
            "refund.created",
            "evt_unbound",
            now,
            unsupported.clone()
        )
        .await,
        StatusCode::NO_CONTENT
    );
    let view = status(&f, &r).await;
    assert_eq!(view["entitlement"]["phase"], "restricted");
    assert_eq!(view["entitlement"]["review_required"], true);
    assert!(view["checkout"]["url"].is_null());
    let calls = f.fake.inner.lock().unwrap().requests.len();
    f.fake.inner.lock().unwrap().outage = true;
    assert_eq!(
        event(
            &f,
            &r,
            "refund.created",
            "evt_unbound",
            now,
            unsupported.clone()
        )
        .await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.fake.inner.lock().unwrap().requests.len(),
        calls,
        "identical durable event replay needs no provider request"
    );
    let mut changed = unsupported;
    changed["reason"] = json!("changed");
    assert_eq!(
        event(&f, &r, "refund.created", "evt_unbound", now, changed).await,
        StatusCode::CONFLICT
    );
    let app = crate::runtime_db::connect(&f.app_url).await.unwrap();
    assert!(
        app.query_one(
            "SELECT hosted_resolve_review($1,1,'evt_unbound','not_subscription_risk')",
            &[&f.namespace]
        )
        .await
        .is_err()
    );
    drop(app);
    f.admin
        .query_one(
            "SELECT hosted_resolve_review($1,1,'evt_unbound','not_subscription_risk')",
            &[&f.namespace],
        )
        .await
        .unwrap();
    assert_eq!(f.admin.query_one("SELECT count(*) FROM hosted_billing_resolutions WHERE operator_role=session_user AND reason='not_subscription_risk'",&[]).await.unwrap().get::<_,i64>(0),1);
    f.fake.inner.lock().unwrap().outage = false;
    assert_eq!(
        status(&f, &r).await["entitlement"]["phase"],
        "pending",
        "resolution alone cannot restore an old projection"
    );
    f.due().await;
    worker::run_one(&r).await.unwrap();
    assert_eq!(status(&f, &r).await["entitlement"]["phase"], "active");
    drop(r);
    f.cleanup().await;
}
