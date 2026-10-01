use super::*;
use crate::{auth, http_auth::DisabledVerificationDispatcher};
use axum::{
    body::{Body, Bytes, to_bytes},
    extract::{Form, Path, Query},
    http::{Request, StatusCode},
};
use std::{collections::HashMap, sync::Mutex};
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

async fn mock_no_open_checkouts() -> Json<Value> {
    Json(serde_json::json!({"object":"list","data":[],"has_more":false}))
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
            "customer":"cus_fixture1","return_url":"https://zrotext.example/billing","configuration":"bpc_fixture1",
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
    assert!(require_checkout_request_key(&headers).is_err());
    headers.insert("idempotency-key", "123".parse().unwrap());
    assert!(require_checkout_request_key(&headers).is_err());
    headers.insert(
        "idempotency-key",
        Uuid::new_v4().simple().to_string().parse().unwrap(),
    );
    assert!(require_checkout_request_key(&headers).is_err());
    headers.insert(
        "idempotency-key",
        Uuid::new_v4().to_string().parse().unwrap(),
    );
    assert!(require_checkout_request_key(&headers).is_ok());
    let profile = |price: &str, success: &str| {
        checkout_profile(price, success, "https://zrotext.example/billing/cancel")
    };
    let first = profile("price_fixture1", "https://zrotext.example/billing/success");
    assert_eq!(first.len(), 32);
    assert_eq!(
        first,
        profile("price_fixture1", "https://zrotext.example/billing/success")
    );
    assert_ne!(
        first,
        profile("price_fixture2", "https://zrotext.example/billing/success")
    );
    assert_ne!(
        first,
        profile("price_fixture1", "https://zrotext.example/new-success")
    );
}

#[test]
fn checkout_window_fixes_key_and_expiry_for_every_request_in_it() {
    let account_id = Uuid::new_v4();
    let profile = "0123456789abcdef0123456789abcdef";
    let start = 1_900_000_000 - 1_900_000_000 % CHECKOUT_WINDOW_SECS;
    let (window, expires_at) = checkout_window(start);
    let key = checkout_retry_key(account_id, profile, window);
    assert!(
        key.len() <= 255,
        "Stripe idempotency keys are at most 255 characters"
    );
    assert_eq!(
        key,
        format!("zt-checkout-v3-{account_id}-{profile}-{window}")
    );
    // Every instant in the window replays one key with identical parameters,
    // and Stripe's 30-minute minimum lifetime holds with margin to spare.
    for now in [
        start,
        start + 1,
        start + 900,
        start + CHECKOUT_WINDOW_SECS - 1,
    ] {
        assert_eq!(checkout_window(now), (window, expires_at));
        let lifetime = expires_at - now;
        assert!(lifetime > 30 * 60 + CHECKOUT_EXPIRY_MARGIN_SECS);
        assert!(lifetime <= 2 * CHECKOUT_WINDOW_SECS + CHECKOUT_EXPIRY_MARGIN_SECS);
    }
    // The next window uses a new key, so a completed or expired session is
    // not replayed indefinitely.
    let (next, next_expiry) = checkout_window(start + CHECKOUT_WINDOW_SECS);
    assert_eq!(next, window + 1);
    assert_eq!(next_expiry, expires_at + CHECKOUT_WINDOW_SECS);
    assert_ne!(checkout_retry_key(account_id, profile, next), key);
    // A session can still be open early in the next window, never after it.
    assert!(expires_at > start + CHECKOUT_WINDOW_SECS);
    assert!(expires_at < start + 3 * CHECKOUT_WINDOW_SECS);
}

/// One recorded Checkout creation: its form fields and idempotency key.
type CreateCall = (HashMap<String, String>, Option<String>);

/// A stateful Checkout provider for one customer: it lists, creates and
/// expires sessions and replays idempotency keys the way Stripe does.
#[derive(Default)]
struct FakeCheckouts {
    sessions: Mutex<Vec<Value>>,
    replays: Mutex<HashMap<String, Value>>,
    creates: Mutex<Vec<CreateCall>>,
    expired: Mutex<Vec<String>>,
}

impl FakeCheckouts {
    fn seed(&self, id: &str, created: i64, account_id: Uuid, profile: Option<&str>) {
        let mut metadata = serde_json::Map::new();
        if let Some(profile) = profile {
            metadata.insert("zt_checkout_profile".into(), profile.into());
        }
        self.sessions.lock().unwrap().push(serde_json::json!({
            "id": id, "object": "checkout.session", "livemode": false,
            "mode": "subscription", "status": "open", "customer": "cus_fixture1",
            "client_reference_id": account_id.to_string(), "created": created,
            "metadata": metadata, "url": format!("https://checkout.stripe.com/c/pay/{id}"),
        }));
    }

    fn complete(&self, id: &str) {
        for session in self.sessions.lock().unwrap().iter_mut() {
            if session["id"] == id {
                session["status"] = "complete".into();
            }
        }
    }

    fn open_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s["status"] == "open")
            .count()
    }
}

async fn fake_list(
    State(fake): State<Arc<FakeCheckouts>>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    assert_eq!(query["status"], "open");
    let data: Vec<Value> = fake
        .sessions
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s["status"] == "open" && s["customer"] == query["customer"].as_str())
        .cloned()
        .collect();
    Json(serde_json::json!({"object":"list","data":data,"has_more":false}))
}

async fn fake_create(
    State(fake): State<Arc<FakeCheckouts>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Json<Value> {
    let key = headers
        .get("idempotency-key")
        .map(|v| v.to_str().unwrap().to_owned());
    fake.creates
        .lock()
        .unwrap()
        .push((form.clone(), key.clone()));
    let key = key.expect("Checkout creation must carry an idempotency key");
    if let Some(replayed) = fake.replays.lock().unwrap().get(&key) {
        return Json(replayed.clone());
    }
    let mut sessions = fake.sessions.lock().unwrap();
    let id = format!("cs_test_fake{}", sessions.len() + 1);
    let session = serde_json::json!({
        "id": id, "object": "checkout.session", "livemode": false,
        "mode": form["mode"], "status": "open", "customer": form["customer"],
        "client_reference_id": form["client_reference_id"],
        "created": 1_000 + sessions.len() as i64,
        "expires_at": form["expires_at"].parse::<i64>().unwrap(),
        "metadata": {"zt_checkout_profile": form["metadata[zt_checkout_profile]"]},
        "url": format!("https://checkout.stripe.com/c/pay/{id}"),
    });
    sessions.push(session.clone());
    fake.replays.lock().unwrap().insert(key, session.clone());
    Json(session)
}

async fn fake_expire(
    State(fake): State<Arc<FakeCheckouts>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let mut sessions = fake.sessions.lock().unwrap();
    let session = sessions
        .iter_mut()
        .find(|s| s["id"] == id.as_str() && s["status"] == "open")
        .ok_or(StatusCode::BAD_REQUEST)?;
    session["status"] = "expired".into();
    fake.expired.lock().unwrap().push(id);
    Ok(Json(session.clone()))
}

async fn fake_stripe() -> (
    Arc<FakeCheckouts>,
    StripeClient,
    tokio::task::JoinHandle<()>,
) {
    let fake = Arc::new(FakeCheckouts::default());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/checkout/sessions", get(fake_list).post(fake_create))
        .route("/v1/checkout/sessions/{id}/expire", post(fake_expire))
        .with_state(fake.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = StripeClient {
        http: HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        secret_key: "rk_test_fixture123456".into(),
        api_base: format!("http://{address}"),
    };
    (fake, client, server)
}

fn fixture_profile() -> String {
    checkout_profile(
        "price_fixture1",
        "https://zrotext.example/billing/success",
        "https://zrotext.example/billing/cancel",
    )
}

fn fixture_params(account_id: Uuid, profile: &str) -> CheckoutParams<'_> {
    CheckoutParams {
        customer_id: "cus_fixture1",
        price_id: "price_fixture1",
        success_url: "https://zrotext.example/billing/success",
        cancel_url: "https://zrotext.example/billing/cancel",
        account_id,
        profile,
    }
}

#[tokio::test]
async fn repeated_checkout_reuses_the_one_open_session() {
    let (fake, stripe, server) = fake_stripe().await;
    let account_id = Uuid::new_v4();
    let profile = fixture_profile();
    let params = fixture_params(account_id, &profile);
    let start = 1_900_000_000 - 1_900_000_000 % CHECKOUT_WINDOW_SECS;
    let (window, expires_at) = checkout_window(start);

    let first = stripe
        .single_open_checkout(&params, start + 60)
        .await
        .unwrap();
    {
        let creates = fake.creates.lock().unwrap();
        assert_eq!(creates.len(), 1);
        let (form, key) = &creates[0];
        assert_eq!(
            key.as_deref(),
            Some(checkout_retry_key(account_id, &profile, window).as_str())
        );
        assert_eq!(form["expires_at"], expires_at.to_string());
        assert_eq!(form["metadata[zt_checkout_profile]"], profile);
        assert_eq!(form["client_reference_id"], account_id.to_string());
    }

    // A reload, a second tab or a return through the cancel page later in
    // the window, and a request in the next window while the session is
    // still open, all reach the same session without creating another.
    for now in [
        start + 61,
        start + CHECKOUT_WINDOW_SECS - 1,
        start + CHECKOUT_WINDOW_SECS + 600,
    ] {
        assert_eq!(
            stripe.single_open_checkout(&params, now).await.unwrap(),
            first
        );
    }
    assert_eq!(fake.creates.lock().unwrap().len(), 1);
    assert!(fake.expired.lock().unwrap().is_empty());
    assert_eq!(fake.open_count(), 1);

    // Once that session is no longer open, a later window opens a new one
    // under a new idempotency key.
    fake.complete(first.rsplit('/').next().unwrap());
    let later = start + 2 * CHECKOUT_WINDOW_SECS + 60;
    let second = stripe.single_open_checkout(&params, later).await.unwrap();
    assert_ne!(second, first);
    {
        let creates = fake.creates.lock().unwrap();
        assert_eq!(creates.len(), 2);
        assert_eq!(
            creates[1].1.as_deref(),
            Some(checkout_retry_key(account_id, &profile, window + 2).as_str())
        );
        assert_eq!(
            creates[1].0["expires_at"],
            checkout_window(later).1.to_string()
        );
    }
    assert_eq!(fake.open_count(), 1);
    server.abort();
}

#[tokio::test]
async fn checkout_expires_every_other_open_session_before_returning_one() {
    let (fake, stripe, server) = fake_stripe().await;
    let account_id = Uuid::new_v4();
    let profile = fixture_profile();
    let params = fixture_params(account_id, &profile);
    let now = 1_900_000_000;

    // A session opened before this guard existed (no profile), one opened
    // under another price configuration, and two matching sessions left by
    // a window-boundary race: only the oldest matching session survives.
    fake.seed("cs_test_legacy1", 10, account_id, None);
    fake.seed(
        "cs_test_otherprice1",
        20,
        account_id,
        Some("ffffffffffffffffffffffffffffffff"),
    );
    fake.seed("cs_test_newer1", 40, account_id, Some(&profile));
    fake.seed("cs_test_older1", 30, account_id, Some(&profile));
    let url = stripe.single_open_checkout(&params, now).await.unwrap();
    assert_eq!(url, "https://checkout.stripe.com/c/pay/cs_test_older1");
    let mut expired = fake.expired.lock().unwrap().clone();
    expired.sort();
    assert_eq!(
        expired,
        ["cs_test_legacy1", "cs_test_newer1", "cs_test_otherprice1"]
    );
    assert!(fake.creates.lock().unwrap().is_empty());
    assert_eq!(fake.open_count(), 1);

    // With only a foreign session open, it is expired and one new session is
    // created, so the account still ends with exactly one open session.
    fake.complete("cs_test_older1");
    fake.seed("cs_test_legacy2", 50, account_id, None);
    stripe.single_open_checkout(&params, now).await.unwrap();
    assert!(
        fake.expired
            .lock()
            .unwrap()
            .contains(&"cs_test_legacy2".to_owned())
    );
    assert_eq!(fake.creates.lock().unwrap().len(), 1);
    assert_eq!(fake.open_count(), 1);
    server.abort();
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
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
        .route(
            "/v1/checkout/sessions",
            get(mock_no_open_checkouts).post(mock_checkout),
        )
        .route("/v1/billing_portal/sessions", post(mock_portal))
        .route(
            "/v1/billing_portal/configurations/{id}",
            get(mock_configuration),
        )
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
    state = state
        .with_portal_configuration("bpc_fixture1".into())
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
            .starts_with(&format!("zt-checkout-v3-{}-", signup.account_id))
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
    // Rounds of exactly the per-account in-flight cap keep the requests
    // concurrent while every 429 comes from the session budget.
    let cap = crate::http_auth::preauth::ACCOUNT_IN_FLIGHT;
    let mut accepted = 0;
    let mut limited = 0;
    for round in 0..16 / cap {
        let mut attempts = tokio::task::JoinSet::new();
        for index in round * cap..(round + 1) * cap {
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
        while let Some(result) = attempts.join_next().await {
            match result.unwrap() {
                StatusCode::OK => accepted += 1,
                StatusCode::TOO_MANY_REQUESTS => limited += 1,
                status => panic!("unexpected hosted-session status: {status}"),
            }
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
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
        .route(
            "/v1/checkout/sessions",
            get(mock_no_open_checkouts).post(mock_checkout),
        )
        .route("/v1/billing_portal/sessions", post(mock_portal))
        .route(
            "/v1/billing_portal/configurations/{id}",
            get(mock_configuration),
        )
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
    state = state
        .with_portal_configuration("bpc_fixture1".into())
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
        include_str!("../../../../../deploy/compose/migrations/048_observer_memberships.sql"),
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
    let app = router(
        SessionState::new(auth_state, secret_key.clone(), price_id)
            .unwrap()
            .with_portal_configuration(
                std::env::var("STRIPE_TEST_PORTAL_CONFIGURATION_ID")
                    .expect("explicit TEST portal configuration required"),
            )
            .unwrap(),
    );

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

fn configuration_fixture() -> Value {
    serde_json::json!({"id":"bpc_fixture1","object":"billing_portal.configuration","active":true,"livemode":false,
        "features":{"invoice_history":{"enabled":true},"payment_method_update":{"enabled":true},"subscription_cancel":{"enabled":true,"mode":"at_period_end"}}})
}

async fn mock_configuration() -> Json<Value> {
    Json(configuration_fixture())
}

#[test]
fn selected_portal_requires_all_capabilities_and_exact_active_test_identity() {
    let good = configuration_fixture();
    validate_portal_configuration(&good, "bpc_fixture1").unwrap();
    for feature in [
        "invoice_history",
        "payment_method_update",
        "subscription_cancel",
    ] {
        let mut bad = good.clone();
        bad["features"][feature]["enabled"] = false.into();
        assert!(validate_portal_configuration(&bad, "bpc_fixture1").is_err());
    }
    for (field, value) in [
        ("id", serde_json::json!("bpc_other")),
        ("object", serde_json::json!("other")),
        ("active", false.into()),
        ("livemode", true.into()),
    ] {
        let mut bad = good.clone();
        bad[field] = value;
        assert!(validate_portal_configuration(&bad, "bpc_fixture1").is_err());
    }
    let mut bad = good.clone();
    bad["features"]["subscription_cancel"]["mode"] = "unknown".into();
    assert!(validate_portal_configuration(&bad, "bpc_fixture1").is_err());
    bad["features"]["subscription_cancel"]["mode"] = "immediately".into();
    validate_portal_configuration(&bad, "bpc_fixture1").unwrap();
    assert!(validate_portal_configuration(&serde_json::json!({}), "bpc_fixture1").is_err());
}

#[tokio::test]
async fn portal_provider_verification_precedes_session_creation_and_binds_configuration() {
    for invalid in [false, true] {
        let mut configuration = configuration_fixture();
        if invalid {
            configuration["livemode"] = true.into();
        }
        let mock = Arc::new(MockStripe {
            account_id: Uuid::new_v4(),
            calls: Mutex::new(Vec::new()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/v1/billing_portal/configurations/{id}",
                get(move || {
                    let value = configuration.clone();
                    async move { Json(value) }
                }),
            )
            .route("/v1/billing_portal/sessions", post(mock_portal))
            .with_state(mock.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = StripeClient {
            http: HttpClient::builder()
                .no_proxy()
                .redirect(redirect::Policy::none())
                .retry(retry::never())
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            secret_key: "rk_test_fixture123456".into(),
            api_base: format!("http://{address}"),
        };
        let result = client
            .create_portal(
                "cus_fixture1",
                "https://zrotext.example/billing",
                "bpc_fixture1",
            )
            .await;
        let calls = mock.calls.lock().unwrap();
        if invalid {
            assert!(result.is_err());
            assert!(calls.is_empty());
        } else {
            assert!(result.is_ok());
            assert_eq!(calls.len(), 1);
            assert!(calls[0].1.contains("configuration=bpc_fixture1"));
        }
        server.abort();
    }
}

#[tokio::test]
async fn portal_offline_or_changed_session_configuration_refuses_handoff() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/billing_portal/configurations/{id}", get(mock_configuration))
        .route("/v1/billing_portal/sessions", post(|| async { Json(serde_json::json!({"id":"bps_fixture1","object":"billing_portal.session","livemode":false,"configuration":"bpc_other","customer":"cus_fixture1","return_url":"https://zrotext.example/billing","url":"https://billing.stripe.com/p/session/test_fixture1"})) }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = StripeClient {
        http: HttpClient::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap(),
        secret_key: "rk_test_fixture123456".into(),
        api_base: format!("http://{address}"),
    };
    assert!(
        client
            .create_portal(
                "cus_fixture1",
                "https://zrotext.example/billing",
                "bpc_fixture1"
            )
            .await
            .is_err()
    );
    server.abort();
    server.await.ok();
    assert!(
        client
            .create_portal(
                "cus_fixture1",
                "https://zrotext.example/billing",
                "bpc_fixture1"
            )
            .await
            .is_err()
    );
}
