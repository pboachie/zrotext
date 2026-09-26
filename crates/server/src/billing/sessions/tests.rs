use super::*;
use crate::{auth, http_auth::DisabledVerificationDispatcher};
use axum::{
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode},
};
use std::sync::Mutex;
use tower::ServiceExt;

struct MockStripe {
    account_id: Uuid,
    calls: Mutex<Vec<(String, String, Option<String>)>>,
}

async fn mock_customer(
    State(state): State<Arc<MockStripe>>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    state.calls.lock().unwrap().push((
        "customer".into(),
        String::from_utf8(body.to_vec()).unwrap(),
        headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_owned()),
    ));
    Json(
        serde_json::json!({"id":"cus_fixture1","object":"customer","livemode":false,
            "metadata":{"account_id":state.account_id.to_string()}}),
    )
}

async fn mock_checkout(
    State(state): State<Arc<MockStripe>>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    state.calls.lock().unwrap().push((
        "checkout".into(),
        String::from_utf8(body.to_vec()).unwrap(),
        headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_owned()),
    ));
    Json(
        serde_json::json!({"id":"cs_test_fixture1","object":"checkout.session","livemode":false,
            "mode":"subscription","customer":"cus_fixture1","client_reference_id":state.account_id.to_string(),
            "url":"https://checkout.stripe.com/c/pay/cs_test_fixture1#stripe-fragment"}),
    )
}

async fn mock_portal(
    State(state): State<Arc<MockStripe>>,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    state.calls.lock().unwrap().push((
        "portal".into(),
        String::from_utf8(body.to_vec()).unwrap(),
        headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_owned()),
    ));
    Json(
        serde_json::json!({"id":"bps_fixture1","object":"billing_portal.session","livemode":false,
            "customer":"cus_fixture1","return_url":"https://zrotext.example/billing",
            "url":"https://billing.stripe.com/p/session/test_fixture1"}),
    )
}

fn owner_request(path: &str, token: &str, csrf: &str, with_csrf: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(
            header::COOKIE,
            format!("__Host-zrotext_session={token}; __Host-zrotext_csrf={csrf}"),
        )
        .header(header::ORIGIN, "https://zrotext.example")
        .header("idempotency-key", Uuid::new_v4().to_string());
    if with_csrf {
        request = request.header("x-zrotext-csrf", csrf);
    }
    request.body(Body::empty()).unwrap()
}

#[test]
fn exact_hosted_url_and_retry_key_are_required() {
    assert!(
        hosted_url(
            &Value::String("https://checkout.stripe.com/c/pay/test#stripe-fragment".into()),
            "checkout.stripe.com"
        )
        .is_ok()
    );
    for url in [
        "http://checkout.stripe.com/x",
        "https://checkout.stripe.com.evil.test/x",
        "https://user@checkout.stripe.com/x",
        "https://checkout.stripe.com:444/x",
    ] {
        assert!(hosted_url(&Value::String(url.into()), "checkout.stripe.com").is_err());
    }
    let mut headers = HeaderMap::new();
    let account_id = Uuid::new_v4();
    let key = |headers: &HeaderMap, price: &str| {
        checkout_retry_key(
            headers,
            account_id,
            price,
            "https://zrotext.example/billing/success",
            "https://zrotext.example/billing/cancel",
        )
    };
    assert!(key(&headers, "price_fixture1").is_err());
    headers.insert("idempotency-key", "123".parse().unwrap());
    assert!(key(&headers, "price_fixture1").is_err());
    headers.insert(
        "idempotency-key",
        Uuid::new_v4().to_string().parse().unwrap(),
    );
    let first = key(&headers, "price_fixture1").unwrap();
    assert_eq!(first, key(&headers, "price_fixture1").unwrap());
    assert_ne!(first, key(&headers, "price_fixture2").unwrap());
    assert_ne!(
        first,
        checkout_retry_key(
            &headers,
            account_id,
            "price_fixture1",
            "https://zrotext.example/new-success",
            "https://zrotext.example/billing/cancel",
        )
        .unwrap()
    );
}

#[tokio::test]
async fn stripe_return_destinations_are_concrete_and_do_not_claim_access() {
    for path in ["/billing/success", "/billing/cancel"] {
        let response = return_router()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let page = std::str::from_utf8(&body).unwrap();
        assert!(page.contains("billing") || page.contains("Billing"));
        assert!(
            page.contains("pending")
                || page.contains("not confirm")
                || page.contains("No subscription")
        );
    }
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_checkout_portal_bind_customer_and_reject_cross_tenant() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("hosted_billing_test_{}", Uuid::new_v4().simple());
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
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password_a = Uuid::new_v4().to_string();
    let password_b = Uuid::new_v4().to_string();
    let signup = auth::register(&mut db, &hasher, "billing-a@example.test", &password_a)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let owner = auth::login(&db, &hasher, "billing-a@example.test", &password_a)
        .await
        .unwrap();
    let other = auth::register(&mut db, &hasher, "billing-b@example.test", &password_b)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &other.verification_token)
        .await
        .unwrap();
    let other_owner = auth::login(&db, &hasher, "billing-b@example.test", &password_b)
        .await
        .unwrap();
    let mock = Arc::new(MockStripe {
        account_id: signup.account_id,
        calls: Mutex::new(Vec::new()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mock_router = Router::new()
        .route("/v1/customers", post(mock_customer))
        .route("/v1/checkout/sessions", post(mock_checkout))
        .route("/v1/billing_portal/sessions", post(mock_portal))
        .with_state(mock.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, mock_router).await.unwrap();
    });
    let auth_state = AuthHttpState::new(
        db_url.clone(),
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let mut state = SessionState::new(
        auth_state,
        "rk_test_fixture123456".into(),
        "price_fixture1".into(),
    )
    .unwrap();
    state.stripe = Arc::new(StripeClient {
        http: HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        secret_key: "rk_test_fixture123456".into(),
        api_base: format!("http://{address}"),
    });
    let app = router(state);
    let unauth = Request::builder()
        .method("POST")
        .uri("/checkout")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(unauth).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "/checkout",
                &owner.token,
                &owner.csrf_token,
                false
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    assert!(mock.calls.lock().unwrap().is_empty());
    let mut with_client_price = owner_request("/checkout", &owner.token, &owner.csrf_token, true);
    *with_client_price.body_mut() = Body::from(r#"{"price":"price_other"}"#);
    assert_eq!(
        app.clone()
            .oneshot(with_client_price)
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert!(mock.calls.lock().unwrap().is_empty());
    let checkout_response = app
        .clone()
        .oneshot(owner_request(
            "/checkout",
            &owner.token,
            &owner.csrf_token,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(checkout_response.status(), StatusCode::OK);
    assert_eq!(
        checkout_response.headers()[header::CACHE_CONTROL],
        "no-store"
    );
    let body: Value =
        serde_json::from_slice(&to_bytes(checkout_response.into_body(), 1024).await.unwrap())
            .unwrap();
    assert_eq!(
        body["url"],
        "https://checkout.stripe.com/c/pay/cs_test_fixture1#stripe-fragment"
    );
    assert_eq!(
        bound_customer(&db, signup.account_id)
            .await
            .unwrap()
            .as_deref(),
        Some("cus_fixture1")
    );
    let portal_response = app
        .clone()
        .oneshot(owner_request(
            "/portal",
            &owner.token,
            &owner.csrf_token,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(portal_response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(portal_response.into_body(), 1024).await.unwrap())
            .unwrap();
    assert_eq!(
        body["url"],
        "https://billing.stripe.com/p/session/test_fixture1"
    );
    assert_eq!(
        app.clone()
            .oneshot(owner_request(
                "/portal",
                &other_owner.token,
                &other_owner.csrf_token,
                true
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let calls = mock.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].0, "customer");
    assert!(
        calls[0]
            .1
            .contains(&format!("metadata%5Baccount_id%5D={}", signup.account_id))
    );
    assert_eq!(
        calls[0].2.as_deref(),
        Some(format!("zt-customer-v1-{}", signup.account_id).as_str())
    );
    assert_eq!(calls[1].0, "checkout");
    assert!(
        calls[1]
            .1
            .contains("line_items%5B0%5D%5Bprice%5D=price_fixture1")
    );
    assert!(
        calls[1]
            .1
            .contains("success_url=https%3A%2F%2Fzrotext.example%2Fbilling%2Fsuccess")
    );
    assert!(calls[1].1.contains("customer=cus_fixture1"));
    assert!(
        calls[1]
            .2
            .as_deref()
            .unwrap()
            .starts_with(&format!("zt-checkout-v2-{}-", signup.account_id))
    );
    assert_eq!(calls[2].0, "portal");
    assert!(
        calls[2]
            .1
            .contains("return_url=https%3A%2F%2Fzrotext.example%2Fbilling")
    );
    // Independent requests alternate routes and rotate checkout keys.
    // The two successful sessions above have already spent two of eight
    // account slots. Rejections must never reach the external provider.
    let mut attempts = tokio::task::JoinSet::new();
    for index in 0..16 {
        let app = app.clone();
        let request = owner_request(
            if index % 2 == 0 {
                "/checkout"
            } else {
                "/portal"
            },
            &owner.token,
            &owner.csrf_token,
            true,
        );
        attempts.spawn(async move { app.oneshot(request).await.unwrap().status() });
    }
    let mut accepted = 0;
    let mut limited = 0;
    while let Some(result) = attempts.join_next().await {
        match result.unwrap() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => limited += 1,
            status => panic!("unexpected hosted-session status: {status}"),
        }
    }
    assert_eq!((accepted, limited), (6, 10));
    assert_eq!(mock.calls.lock().unwrap().len(), 9);
    server.abort();
    drop(db);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires ZT_AUTH_TEST_DATABASE_URL; run the documented PostgreSQL test command"]
async fn owner_checkout_refused_while_subscription_live_or_pending() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for PostgreSQL-backed tests");
    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("hosted_billing_guard_{}", Uuid::new_v4().simple());
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
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let password = Uuid::new_v4().to_string();
    let signup = auth::register(&mut db, &hasher, "billing-guard@example.test", &password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let owner = auth::login(&db, &hasher, "billing-guard@example.test", &password)
        .await
        .unwrap();
    let account_id = signup.account_id;
    let mock = Arc::new(MockStripe {
        account_id,
        calls: Mutex::new(Vec::new()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mock_router = Router::new()
        .route("/v1/customers", post(mock_customer))
        .route("/v1/checkout/sessions", post(mock_checkout))
        .route("/v1/billing_portal/sessions", post(mock_portal))
        .with_state(mock.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, mock_router).await.unwrap();
    });
    let auth_state = AuthHttpState::new(
        db_url.clone(),
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let mut state = SessionState::new(
        auth_state,
        "rk_test_fixture123456".into(),
        "price_fixture1".into(),
    )
    .unwrap();
    state.stripe = Arc::new(StripeClient {
        http: HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        secret_key: "rk_test_fixture123456".into(),
        api_base: format!("http://{address}"),
    });
    let app = router(state);
    let request = || owner_request("/checkout", &owner.token, &owner.csrf_token, true);

    // Baseline: an account without any subscription row may subscribe.
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
    let customer: String = db
        .query_one(
            "SELECT stripe_customer_id FROM billing_customers WHERE account_id=$1",
            &[&account_id],
        )
        .await
        .unwrap()
        .get(0);

    // A nonterminal subscription refuses Checkout before any Stripe call.
    db.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES('sub_Guard1',$1,$2,1,1)",
            &[&account_id, &customer],
        )
        .await
        .unwrap();
    db.execute(
            "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price) VALUES('sub_Guard1',$1,$2,'past_due','price_fixture1',true)",
            &[&account_id, &customer],
        )
        .await
        .unwrap();
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(body["code"], "subscription_exists");
    assert_eq!(mock.calls.lock().unwrap().len(), 2);

    // A fully reconciled terminal subscription no longer blocks Checkout.
    db.execute(
            "UPDATE billing_subscriptions SET stripe_status='canceled' WHERE stripe_subscription_id='sub_Guard1'",
            &[],
        )
        .await
        .unwrap();
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(mock.calls.lock().unwrap().len(), 3);

    // A pending reconciliation blocks even a terminal subscription: the
    // next provider read is unknown and the guard must fail closed.
    db.execute(
            "UPDATE billing_reconciliations SET dirty_generation=2 WHERE stripe_subscription_id='sub_Guard1'",
            &[],
        )
        .await
        .unwrap();
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.lock().unwrap().len(), 3);
    // A queued subscription that has never been reconciled also blocks.
    db.execute(
        "DELETE FROM billing_subscriptions WHERE stripe_subscription_id='sub_Guard1'",
        &[],
    )
    .await
    .unwrap();
    let response = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.lock().unwrap().len(), 3);

    // Concurrent attempts serialize with an in-flight projection on the
    // reconciliation lock and must all observe the committed subscription.
    let (mut holder, connection) = tokio_postgres::connect(&db_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let lock = holder.transaction().await.unwrap();
    lock.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 2))",
        &[&account_id.to_string()],
    )
    .await
    .unwrap();
    lock.execute(
            "INSERT INTO billing_reconciliations(stripe_subscription_id,account_id,stripe_customer_id,dirty_generation,processed_generation) VALUES('sub_Guard2',$1,$2,1,1)",
            &[&account_id, &customer],
        )
        .await
        .unwrap();
    lock.execute(
            "INSERT INTO billing_subscriptions(stripe_subscription_id,account_id,stripe_customer_id,stripe_status,stripe_price_id,recognized_price) VALUES('sub_Guard2',$1,$2,'active','price_fixture1',true)",
            &[&account_id, &customer],
        )
        .await
        .unwrap();
    let mut attempts = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let app = app.clone();
        let request = request();
        attempts.spawn(async move { app.oneshot(request).await.unwrap().status() });
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    lock.commit().await.unwrap();
    let mut refused = 0;
    while let Some(result) = attempts.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::CONFLICT);
        refused += 1;
    }
    assert_eq!(refused, 4);
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        3,
        "refused checkout must never reach the provider"
    );
    server.abort();
    drop(db);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "creates test-mode Stripe Customer, Checkout, and Portal sessions; run explicitly"]
async fn real_stripe_sandbox_hosted_sessions_smoke() {
    let base_url = std::env::var("ZT_AUTH_TEST_DATABASE_URL")
        .expect("set ZT_AUTH_TEST_DATABASE_URL for an isolated PostgreSQL test database");
    let secret_key = std::env::var("ZT_STRIPE_TEST_SECRET_KEY")
        .expect("load a Stripe test-mode API key into ZT_STRIPE_TEST_SECRET_KEY");
    let price_id = std::env::var("ZT_STRIPE_TEST_PRICE_ID")
        .expect("set ZT_STRIPE_TEST_PRICE_ID to a recurring sandbox price");
    assert!(is_test_api_key(&secret_key));
    assert!(price_id.starts_with("price_"));

    let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let schema = format!("stripe_sandbox_smoke_{}", Uuid::new_v4().simple());
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
        include_str!("../../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
        include_str!("../../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
        include_str!("../../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
        include_str!("../../../../../deploy/compose/migrations/018_sealed_inbound_identity.sql"),
        include_str!("../../../../../deploy/compose/migrations/019_line_activation_contract.sql"),
        include_str!("../../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        include_str!("../../../../../deploy/compose/migrations/028_billing_provider_failures.sql"),
    ] {
        db.batch_execute(sql).await.unwrap();
    }
    let hasher = Arc::new(auth::TokenHasher::new(rand::random::<[u8; 32]>().to_vec()).unwrap());
    let email = format!("stripe-smoke-{}@example.test", Uuid::new_v4().simple());
    let password = Uuid::new_v4().to_string();
    let signup = auth::register(&mut db, &hasher, &email, &password)
        .await
        .unwrap();
    auth::verify_email(&mut db, &hasher, &signup.verification_token)
        .await
        .unwrap();
    let owner = auth::login(&db, &hasher, &email, &password).await.unwrap();
    let auth_state = AuthHttpState::new(
        db_url,
        hasher,
        "https://zrotext.example".into(),
        Arc::new(DisabledVerificationDispatcher),
    )
    .unwrap();
    let app = router(SessionState::new(auth_state, secret_key.clone(), price_id).unwrap());

    let checkout = app
        .clone()
        .oneshot(owner_request(
            "/checkout",
            &owner.token,
            &owner.csrf_token,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(checkout.status(), StatusCode::OK);
    let checkout_body: Value =
        serde_json::from_slice(&to_bytes(checkout.into_body(), 8192).await.unwrap()).unwrap();
    assert!(hosted_url(&checkout_body["url"], "checkout.stripe.com").is_ok());

    let customer_id = bound_customer(&db, signup.account_id)
        .await
        .unwrap()
        .expect("Checkout must bind a sandbox customer");
    let inspect = HttpClient::builder()
        .no_proxy()
        .https_only(true)
        .redirect(redirect::Policy::none())
        .retry(retry::never())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = inspect
        .get(format!("{STRIPE_API}/v1/customers/{customer_id}"))
        .bearer_auth(&secret_key)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    let customer: Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(customer["object"], "customer");
    assert_eq!(customer["livemode"], false);
    assert_eq!(
        customer["metadata"]["account_id"],
        signup.account_id.to_string()
    );

    let portal = app
        .oneshot(owner_request(
            "/portal",
            &owner.token,
            &owner.csrf_token,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(portal.status(), StatusCode::OK);
    let portal_body: Value =
        serde_json::from_slice(&to_bytes(portal.into_body(), 8192).await.unwrap()).unwrap();
    assert!(hosted_url(&portal_body["url"], "billing.stripe.com").is_ok());

    drop(db);
    setup
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}
