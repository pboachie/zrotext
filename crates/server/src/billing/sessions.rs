// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, test-mode Stripe-hosted Checkout and Customer Portal handoff.
//! Browser input never selects a Stripe customer, price, or return URL.

use super::{bind_customer, is_test_api_key, valid_id};
use crate::http_auth::{self, AuthHttpError, AuthHttpState};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use reqwest::{Client as HttpClient, redirect, retry};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

const STRIPE_API: &str = "https://api.stripe.com";
const MAX_RESPONSE_BYTES: usize = 32 * 1024;

#[derive(Clone)]
pub struct SessionState {
    auth: AuthHttpState,
    stripe: Arc<StripeClient>,
    checkout_price_id: String,
    success_url: String,
    cancel_url: String,
    portal_return_url: String,
}

impl SessionState {
    pub fn new(
        auth: AuthHttpState,
        secret_key: String,
        checkout_price_id: String,
    ) -> Result<Self, &'static str> {
        if !is_test_api_key(&secret_key) {
            return Err("Stripe hosted sessions require a test-mode key");
        }
        if valid_id(&checkout_price_id, "price_").is_err() {
            return Err("invalid Stripe Checkout price");
        }
        let origin = &auth.canonical_origin;
        let parsed = reqwest::Url::parse(origin).map_err(|_| "invalid hosted session origin")?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.as_str().trim_end_matches('/') != origin
        {
            return Err("invalid hosted session origin");
        }
        let http = HttpClient::builder()
            .no_proxy()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .retry(retry::never())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| "cannot configure Stripe test client")?;
        Ok(Self {
            success_url: format!("{origin}/billing/success"),
            cancel_url: format!("{origin}/billing/cancel"),
            portal_return_url: format!("{origin}/billing"),
            auth,
            stripe: Arc::new(StripeClient {
                http,
                secret_key,
                api_base: STRIPE_API.to_owned(),
            }),
            checkout_price_id,
        })
    }
}

struct StripeClient {
    http: HttpClient,
    secret_key: String,
    api_base: String,
}

enum StripeEndpoint {
    Customer,
    Checkout,
    Portal,
}

impl StripeEndpoint {
    fn path(&self) -> &'static str {
        match self {
            Self::Customer => "/v1/customers",
            Self::Checkout => "/v1/checkout/sessions",
            Self::Portal => "/v1/billing_portal/sessions",
        }
    }
}

pub fn router(state: SessionState) -> Router {
    Router::new()
        .route("/checkout", post(checkout))
        .route("/portal", post(portal))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(state))
}

/// Fixed browser destinations used by Stripe redirects. They deliberately
/// report no subscription status; only verified event reconciliation can do so.
pub fn return_router() -> Router {
    Router::new()
        .route("/billing/success", get(checkout_return))
        .route("/billing/cancel", get(cancel_return))
}

fn return_page(title: &'static str, message: &'static str) -> Response {
    (
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", "default-src 'none'; base-uri 'none'; form-action 'none'"),
            ("x-content-type-options", "nosniff"),
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
        ],
        Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title><main><h1>{title}</h1><p>{message}</p><p><a href=\"/billing\">Billing status</a></p></main></html>")),
    ).into_response()
}

async fn checkout_return() -> Response {
    return_page(
        "Checkout returned",
        "Stripe returned you to ZROtext. Your subscription and access remain pending until the server verifies and reconciles billing events.",
    )
}

async fn cancel_return() -> Response {
    return_page(
        "Checkout canceled",
        "The Checkout flow was canceled. No subscription or access change is confirmed by this page.",
    )
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[derive(Serialize)]
struct SessionUrl {
    url: String,
}

async fn checkout(
    State(state): State<Arc<SessionState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionUrl>, AuthHttpError> {
    if !body.is_empty() {
        return Err(AuthHttpError::BadRequest);
    }
    let db = connect(&state.auth.database_url).await?;
    let owner = http_auth::require_owner(
        &db,
        &state.auth.hasher,
        &state.auth.canonical_origin,
        &headers,
        true,
    )
    .await?;
    let account_id = owner.tenant.account_id();
    let retry_key = checkout_retry_key(
        &headers,
        account_id,
        &state.checkout_price_id,
        &state.success_url,
        &state.cancel_url,
    )?;
    let customer_id = match bound_customer(&db, account_id).await? {
        Some(id) => id,
        None => {
            let id = state.stripe.create_customer(account_id).await?;
            // The webhook foundation serializes this binding with event ingress.
            let mut db = db;
            bind_customer(&mut db, account_id, &id)
                .await
                .map_err(|_| AuthHttpError::Unavailable)?;
            bound_customer(&db, account_id)
                .await?
                .ok_or(AuthHttpError::Unavailable)?
        }
    };
    let url = state
        .stripe
        .create_checkout(
            &customer_id,
            &state.checkout_price_id,
            &state.success_url,
            &state.cancel_url,
            account_id,
            &retry_key,
        )
        .await?;
    Ok(Json(SessionUrl { url }))
}

async fn portal(
    State(state): State<Arc<SessionState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionUrl>, AuthHttpError> {
    if !body.is_empty() {
        return Err(AuthHttpError::BadRequest);
    }
    let db = connect(&state.auth.database_url).await?;
    let owner = http_auth::require_owner(
        &db,
        &state.auth.hasher,
        &state.auth.canonical_origin,
        &headers,
        true,
    )
    .await?;
    let customer_id = bound_customer(&db, owner.tenant.account_id())
        .await?
        .ok_or(AuthHttpError::NotFound)?;
    let url = state
        .stripe
        .create_portal(&customer_id, &state.portal_return_url)
        .await?;
    Ok(Json(SessionUrl { url }))
}

fn checkout_retry_key(
    headers: &HeaderMap,
    account_id: Uuid,
    price_id: &str,
    success_url: &str,
    cancel_url: &str,
) -> Result<String, AuthHttpError> {
    let value = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHttpError::BadRequest)?;
    let uuid = Uuid::parse_str(value).map_err(|_| AuthHttpError::BadRequest)?;
    if uuid.get_version_num() != 4 || uuid.to_string() != value {
        return Err(AuthHttpError::BadRequest);
    }
    let mut digest = Sha256::new();
    digest.update(b"zt-checkout-profile-v1\0");
    for value in [price_id, success_url, cancel_url] {
        digest.update(value.as_bytes());
        digest.update(b"\0");
    }
    let profile = digest.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("zt-checkout-v2-{account_id}-{profile}-{uuid}"))
}

async fn connect(database_url: &str) -> Result<Client, AuthHttpError> {
    let (db, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(db)
}

async fn bound_customer(db: &Client, account_id: Uuid) -> Result<Option<String>, AuthHttpError> {
    db.query_opt(
        "SELECT stripe_customer_id FROM billing_customers WHERE account_id=$1",
        &[&account_id],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)
    .map(|row| row.map(|row| row.get(0)))
}

impl StripeClient {
    async fn post(
        &self,
        endpoint: StripeEndpoint,
        form: &[(&str, String)],
        key: Option<&str>,
    ) -> Result<Value, AuthHttpError> {
        let mut request = self
            .http
            .post(format!("{}{}", self.api_base, endpoint.path()))
            .bearer_auth(&self.secret_key)
            .form(form);
        if let Some(key) = key {
            request = request.header("Idempotency-Key", key);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| AuthHttpError::Unavailable)?;
        if !response.status().is_success() {
            return Err(AuthHttpError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthHttpError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(AuthHttpError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| AuthHttpError::Unavailable)
    }

    async fn create_customer(&self, account_id: Uuid) -> Result<String, AuthHttpError> {
        let result = self
            .post(
                StripeEndpoint::Customer,
                &[("metadata[account_id]", account_id.to_string())],
                Some(&format!("zt-customer-v1-{account_id}")),
            )
            .await?;
        if result["object"] != "customer"
            || result["livemode"] != false
            || result["metadata"]["account_id"] != account_id.to_string()
        {
            return Err(AuthHttpError::Unavailable);
        }
        valid_id(
            result["id"].as_str().ok_or(AuthHttpError::Unavailable)?,
            "cus_",
        )
        .map(str::to_owned)
        .map_err(|_| AuthHttpError::Unavailable)
    }

    async fn create_checkout(
        &self,
        customer_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
        account_id: Uuid,
        retry_key: &str,
    ) -> Result<String, AuthHttpError> {
        let result = self
            .post(
                StripeEndpoint::Checkout,
                &[
                    ("mode", "subscription".into()),
                    ("customer", customer_id.into()),
                    ("line_items[0][price]", price_id.into()),
                    ("line_items[0][quantity]", "1".into()),
                    ("success_url", success_url.into()),
                    ("cancel_url", cancel_url.into()),
                    ("client_reference_id", account_id.to_string()),
                    (
                        "subscription_data[metadata][account_id]",
                        account_id.to_string(),
                    ),
                ],
                Some(retry_key),
            )
            .await?;
        if result["object"] != "checkout.session"
            || result["livemode"] != false
            || result["mode"] != "subscription"
            || result["customer"] != customer_id
            || result["client_reference_id"] != account_id.to_string()
        {
            return Err(AuthHttpError::Unavailable);
        }
        valid_id(
            result["id"].as_str().ok_or(AuthHttpError::Unavailable)?,
            "cs_test_",
        )
        .map_err(|_| AuthHttpError::Unavailable)?;
        hosted_url(&result["url"], "checkout.stripe.com")
    }

    async fn create_portal(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<String, AuthHttpError> {
        let result = self
            .post(
                StripeEndpoint::Portal,
                &[
                    ("customer", customer_id.into()),
                    ("return_url", return_url.into()),
                ],
                None,
            )
            .await?;
        if result["object"] != "billing_portal.session"
            || result["livemode"] != false
            || result["customer"] != customer_id
            || result["return_url"] != return_url
        {
            return Err(AuthHttpError::Unavailable);
        }
        valid_id(
            result["id"].as_str().ok_or(AuthHttpError::Unavailable)?,
            "bps_",
        )
        .map_err(|_| AuthHttpError::Unavailable)?;
        hosted_url(&result["url"], "billing.stripe.com")
    }
}

fn hosted_url(value: &Value, host: &str) -> Result<String, AuthHttpError> {
    let raw = value.as_str().ok_or(AuthHttpError::Unavailable)?;
    if raw.len() > 4096 {
        return Err(AuthHttpError::Unavailable);
    }
    let url = reqwest::Url::parse(raw).map_err(|_| AuthHttpError::Unavailable)?;
    if url.scheme() != "https"
        || url.host_str() != Some(host)
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AuthHttpError::Unavailable);
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
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
    async fn owner_checkout_portal_bind_customer_and_reject_cross_tenant() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
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
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
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
        let mut with_client_price =
            owner_request("/checkout", &owner.token, &owner.csrf_token, true);
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
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!(
                "../../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"
            ),
            include_str!("../../../../deploy/compose/migrations/008_stripe_billing_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/009_webhook_manual_replay.sql"),
            include_str!("../../../../deploy/compose/migrations/010_billing_test_entitlement.sql"),
            include_str!("../../../../deploy/compose/migrations/011_billing_payment_holds.sql"),
            include_str!("../../../../deploy/compose/migrations/012_auth_abuse_limits.sql"),
            include_str!("../../../../deploy/compose/migrations/013_owner_mfa.sql"),
            include_str!("../../../../deploy/compose/migrations/014_owner_mfa_failure_budget.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
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
}
