// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in, test-mode Stripe-hosted Checkout and Customer Portal handoff.
//! Browser input never selects a Stripe customer, price, or return URL.

use super::{bind_customer, is_test_api_key, valid_id};
use crate::auth::abuse_limits::{self, Limit};
use crate::http_auth::{self, AuthHttpError, AuthHttpState};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use reqwest::{Client as HttpClient, redirect, retry};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio_postgres::Client;
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
            ("content-security-policy", "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
            ("x-content-type-options", "nosniff"),
            ("strict-transport-security", "max-age=63072000; includeSubDomains"),
        ],
        Html(format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title><main><h1>{title}</h1><p>{message}</p><p><a href=\"/billing\">Billing status</a></p></main><footer><a href=\"/source\">Source code for this server</a></footer></html>")),
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

#[derive(Serialize)]
struct SessionRefusal {
    code: &'static str,
}

async fn checkout(
    State(state): State<Arc<SessionState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AuthHttpError> {
    if !body.is_empty() {
        return Err(AuthHttpError::BadRequest);
    }
    let mut db = connect(&state.auth.database_url).await?;
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
    // One nonterminal subscription per account: a second live subscription
    // projects an ambiguous entitlement of zero outbound quota and a zero
    // device cap. Refuse before any Stripe work and before spending the
    // shared session budget.
    if subscription_exists(&mut db, account_id).await? {
        return Ok((
            StatusCode::CONFLICT,
            Json(SessionRefusal {
                code: "subscription_exists",
            }),
        )
            .into_response());
    }
    consume_session_budget(&db, &state, account_id).await?;
    let customer_id = match bound_customer(&db, account_id).await? {
        Some(id) => id,
        None => {
            let id = state.stripe.create_customer(account_id).await?;
            // The webhook foundation serializes this binding with event ingress.
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
    Ok(Json(SessionUrl { url }).into_response())
}

/// Whether the account already holds a nonterminal subscription or a
/// subscription whose reconciled state is not yet known. The check runs under
/// reconciliation's per-account advisory lock, so it can never interleave
/// with an in-flight projection and observe half-committed billing state.
async fn subscription_exists(db: &mut Client, account_id: Uuid) -> Result<bool, AuthHttpError> {
    let tx = db
        .transaction()
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 2))",
        &[&account_id.to_string()],
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?;
    let blocked: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status NOT IN ('canceled','incomplete_expired','provider_deleted')) OR EXISTS(SELECT 1 FROM billing_reconciliations WHERE account_id=$1 AND dirty_generation>processed_generation)",
            &[&account_id],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
        .get(0);
    tx.commit().await.map_err(|_| AuthHttpError::Unavailable)?;
    Ok(blocked)
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
    consume_session_budget(&db, &state, owner.tenant.account_id()).await?;
    let url = state
        .stripe
        .create_portal(&customer_id, &state.portal_return_url)
        .await?;
    Ok(Json(SessionUrl { url }))
}

// Shared across routes, owner sessions and API instances. Charge only after
// owner/CSRF and request validation, but before any external provider work.
async fn consume_session_budget(
    db: &Client,
    state: &SessionState,
    account_id: Uuid,
) -> Result<(), AuthHttpError> {
    if abuse_limits::consume(
        db,
        &state.auth.hasher,
        Limit::BillingSession,
        Some(&account_id.to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        Ok(())
    } else {
        Err(AuthHttpError::TooManyRequests)
    }
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
    let (db, connection) = crate::runtime_db::connect(database_url)
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
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests;
