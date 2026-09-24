// SPDX-License-Identifier: AGPL-3.0-only
//! Private synthetic-alpha message routes. The caller can select only a short
//! test-case identifier; this module constructs the fixed plaintext body.
//! Never mount as a general customer message-content endpoint.

use crate::{
    alpha_policy::AlphaPolicy,
    auth::{self, AuthError, Scope, TokenHasher},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::{DeliveryStore, NewMessage, StoreError};
use zrotext_domain::MessageState;

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_BODY_BYTES: usize = 1024;

#[derive(Clone)]
pub struct MessagesHttpState {
    database_url: String,
    hasher: Arc<TokenHasher>,
    policy: Arc<AlphaPolicy>,
    metered: bool,
    idempotency_days: i32,
}

impl MessagesHttpState {
    /// The runtime supplies a fail-closed policy with consented account and
    /// recipient allowlists from private configuration.
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        policy: Arc<AlphaPolicy>,
        metered: bool,
    ) -> Result<Self, &'static str> {
        if database_url.is_empty() {
            return Err("message database URL is required");
        }
        Ok(Self {
            database_url,
            hasher,
            policy,
            metered,
            idempotency_days: 7,
        })
    }

    pub fn with_idempotency_days(mut self, days: i32) -> Self {
        self.idempotency_days = days;
        self
    }
}

pub fn router(state: MessagesHttpState) -> Router {
    Router::new()
        .route("/messages", post(accept))
        .route("/messages/{message_id}", get(status))
        .route("/messages/{message_id}/cancel", post(cancel))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(no_store_response))
        .with_state(Arc::new(state))
}

async fn no_store_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

#[derive(Debug)]
enum MessageHttpError {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    QueueFull,
    RateLimited,
    QuotaExceeded,
    BillingPending,
    PaymentHold,
    Unavailable,
}

impl IntoResponse for MessageHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "conflict"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::QueueFull => (StatusCode::TOO_MANY_REQUESTS, "queue_full"),
            Self::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
            Self::BillingPending => (StatusCode::SERVICE_UNAVAILABLE, "billing_pending"),
            Self::PaymentHold => (StatusCode::PAYMENT_REQUIRED, "payment_hold"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let mut response = (status, Json(ErrorBody { code })).into_response();
        if status == StatusCode::TOO_MANY_REQUESTS || code == "billing_pending" {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                if code == "billing_pending" {
                    "10"
                } else {
                    "60"
                }
                .parse()
                .expect("static retry-after"),
            );
        }
        response
    }
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

fn map_auth(error: AuthError) -> MessageHttpError {
    match error {
        AuthError::Unauthorized | AuthError::InvalidCredentials => MessageHttpError::Unauthorized,
        AuthError::Forbidden | AuthError::EmailNotVerified => MessageHttpError::Forbidden,
        AuthError::InvalidInput => MessageHttpError::BadRequest,
        AuthError::Database(_) | AuthError::Password | AuthError::Crypto => {
            MessageHttpError::Unavailable
        }
        AuthError::MfaRequired { .. } | AuthError::RateLimited => MessageHttpError::Unauthorized,
    }
}

fn map_store(error: StoreError) -> MessageHttpError {
    match error {
        StoreError::InvalidInput => MessageHttpError::BadRequest,
        StoreError::IdempotencyConflict
        | StoreError::MessageIdConflict
        | StoreError::InvalidTransition => MessageHttpError::Conflict,
        StoreError::NotFound | StoreError::Revoked => MessageHttpError::NotFound,
        StoreError::Database(_) | StoreError::DispatchDisabled | StoreError::StaleFence => {
            MessageHttpError::Unavailable
        }
        StoreError::PaymentHold => MessageHttpError::PaymentHold,
        StoreError::QuotaNotConfigured => MessageHttpError::BillingPending,
        StoreError::QuotaExceeded => MessageHttpError::QuotaExceeded,
        StoreError::DeviceBusy | StoreError::EventIdConflict => MessageHttpError::Conflict,
        StoreError::QueueFull => MessageHttpError::QueueFull,
    }
}

async fn connect(database_url: &str) -> Result<Client, MessageHttpError> {
    let (client, connection) = crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| MessageHttpError::Unavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn bearer(headers: &HeaderMap) -> Result<&str, MessageHttpError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(MessageHttpError::Unauthorized)?;
    if values.next().is_some() {
        return Err(MessageHttpError::Unauthorized);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(' '))
        .ok_or(MessageHttpError::Unauthorized)
}

fn idempotency_key(headers: &HeaderMap) -> Result<&str, MessageHttpError> {
    let mut values = headers.get_all(IDEMPOTENCY_HEADER).iter();
    let value = values.next().ok_or(MessageHttpError::BadRequest)?;
    if values.next().is_some() {
        return Err(MessageHttpError::BadRequest);
    }
    value
        .to_str()
        .ok()
        .filter(|value| {
            (1..=128).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        })
        .ok_or(MessageHttpError::BadRequest)
}

fn valid_e164(number: &str) -> bool {
    number.starts_with('+')
        && (3..=16).contains(&number.len())
        && number.as_bytes()[1] != b'0'
        && number.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

#[cfg(test)]
fn now_ms() -> Result<i64, MessageHttpError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MessageHttpError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| MessageHttpError::Unavailable)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptBody {
    client_message_id: Uuid,
    device_id: Uuid,
    recipient_e164: String,
    test_case_id: String,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct AcceptedBody {
    message_id: Uuid,
    created: bool,
}

async fn accept(
    State(state): State<Arc<MessagesHttpState>>,
    headers: HeaderMap,
    Json(body): Json<AcceptBody>,
) -> Result<Response, MessageHttpError> {
    if !state.policy.enabled() {
        return Err(MessageHttpError::NotFound);
    }
    let token = bearer(&headers)?;
    let key = idempotency_key(&headers)?;
    if !valid_e164(&body.recipient_e164)
        || body.test_case_id.is_empty()
        || body.test_case_id.len() > 32
        || !body
            .test_case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(MessageHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, token)
        .await
        .map_err(map_auth)?;
    principal
        .require(Scope::MessagesSend, Some(body.device_id))
        .map_err(map_auth)?;
    let account_id = principal.tenant.account_id();
    if !state.policy.allows(account_id, &body.recipient_e164) {
        return Err(MessageHttpError::NotFound);
    }
    let active = client
        .query_opt(
            "SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL",
            &[&account_id, &body.device_id],
        )
        .await
        .map_err(|_| MessageHttpError::Unavailable)?
        .is_some();
    if !active {
        return Err(MessageHttpError::NotFound);
    }
    // Spend outside the delivery transaction: cancellation, failed storage and
    // exact retries must not refund abuse attempts. Account identity makes this
    // shared across API keys, devices and server processes.
    if !auth::abuse_limits::consume(
        &client,
        &state.hasher,
        auth::abuse_limits::Limit::OutboundAccept,
        Some(&account_id.to_string()),
    )
    .await
    .map_err(|_| MessageHttpError::Unavailable)?
    {
        return Err(MessageHttpError::RateLimited);
    }
    let synthetic_body = format!("ZROtext synthetic test: {}", body.test_case_id);
    let input = NewMessage {
        account_id,
        client_message_id: body.client_message_id,
        device_id: body.device_id,
        idempotency_key: key,
        recipient_e164: &body.recipient_e164,
        synthetic_payload: synthetic_body.as_bytes(),
        expires_at_ms: body.expires_at_ms,
    };
    let mut store = DeliveryStore::with_idempotency_days(&mut client, state.idempotency_days);
    let outcome = store
        .accept_alpha(input, state.metered)
        .await
        .map_err(map_store)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedBody {
            message_id: outcome.message_id,
            created: outcome.created,
        }),
    )
        .into_response())
}

#[derive(Serialize)]
struct StatusBody {
    message_id: Uuid,
    device_id: Uuid,
    state: MessageState,
    state_version: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

async fn status(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<StatusBody>, MessageHttpError> {
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, bearer(&headers)?)
        .await
        .map_err(map_auth)?;
    let snapshot = DeliveryStore::new(&mut client)
        .status(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
        .ok_or(MessageHttpError::NotFound)?;
    principal
        .require(Scope::MessagesRead, Some(snapshot.device_id))
        .map_err(map_auth)?;
    Ok(Json(StatusBody {
        message_id,
        device_id: snapshot.device_id,
        state: snapshot.state,
        state_version: snapshot.state_version,
        created_at_ms: snapshot.created_at_ms,
        updated_at_ms: snapshot.updated_at_ms,
    }))
}

async fn cancel(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, MessageHttpError> {
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, bearer(&headers)?)
        .await
        .map_err(map_auth)?;
    let snapshot = DeliveryStore::new(&mut client)
        .status(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
        .ok_or(MessageHttpError::NotFound)?;
    principal
        .require(Scope::MessagesSend, Some(snapshot.device_id))
        .map_err(map_auth)?;
    if DeliveryStore::new(&mut client)
        .cancel(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(MessageHttpError::NotFound)
    }
}

#[cfg(test)]
use tokio_postgres::NoTls;
#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    fn post(path: &str, token: &str, key: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(IDEMPOTENCY_HEADER, key)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get(path: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    async fn owner(
        client: &mut Client,
        hasher: &TokenHasher,
        email: &str,
    ) -> (Uuid, Uuid, String, String, String) {
        let signup = auth::register(client, hasher, email, "correct horse 123")
            .await
            .unwrap();
        assert!(
            auth::verify_email(client, hasher, &signup.verification_token)
                .await
                .unwrap()
        );
        let session = auth::login(client, hasher, email, "correct horse 123")
            .await
            .unwrap();
        let principal = auth::authenticate_session(client, hasher, &session.token)
            .await
            .unwrap();
        let device_id = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'fixture')",
                &[&device_id, &signup.account_id],
            )
            .await
            .unwrap();
        let send = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesSend],
            Some(device_id),
            None,
        )
        .await
        .unwrap();
        let read = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesRead],
            Some(device_id),
            None,
        )
        .await
        .unwrap();
        let unbound_send = auth::create_api_key(
            client,
            hasher,
            &principal,
            &[Scope::MessagesSend],
            None,
            None,
        )
        .await
        .unwrap();
        (
            signup.account_id,
            device_id,
            send.token,
            read.token,
            unbound_send.token,
        )
    }

    #[test]
    fn bearer_and_case_id_inputs_are_strict() {
        let mut headers = HeaderMap::new();
        assert!(bearer(&headers).is_err());
        headers.append(header::AUTHORIZATION, "Bearer ztk_one".parse().unwrap());
        headers.append(header::AUTHORIZATION, "Bearer ztk_two".parse().unwrap());
        assert!(bearer(&headers).is_err());
        assert!(valid_e164("+15555550101"));
        assert!(!valid_e164("+0123"));
        assert!(!valid_e164("+1 555"));
    }

    #[tokio::test]
    async fn billing_denials_have_distinct_http_codes() {
        for (error, status, code, retry_after) in [
            (
                StoreError::QuotaNotConfigured,
                StatusCode::SERVICE_UNAVAILABLE,
                "billing_pending",
                Some("10"),
            ),
            (
                StoreError::PaymentHold,
                StatusCode::PAYMENT_REQUIRED,
                "payment_hold",
                None,
            ),
        ] {
            let response = map_store(error).into_response();
            assert_eq!(response.status(), status);
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .map(|value| value.to_str().unwrap()),
                retry_after
            );
            let body = to_bytes(response.into_body(), 2048).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
                code
            );
        }
    }

    #[tokio::test]
    async fn postgres_alpha_http_accept_status_cancel_are_tenant_and_device_scoped() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("http_messages_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let url = format!("{base_url}?options=-csearch_path%3D{schema}");
        let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
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
            include_str!("../../../../deploy/compose/migrations/015_webhook_kek_commitments.sql"),
            include_str!("../../../../deploy/compose/migrations/016_auth_abuse_atomic.sql"),
            include_str!("../../../../deploy/compose/migrations/017_billing_device_caps.sql"),
            include_str!("../../../../deploy/compose/migrations/021_billing_payment_grace.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        let hasher = Arc::new(TokenHasher::new(crate::test_keys::key(51)).unwrap());
        let (account_a, device_a, send_a, read_a, unbound_send_a) =
            owner(&mut client, &hasher, "owner-a@example.test").await;
        let (_, device_b, _send_b, read_b, _) =
            owner(&mut client, &hasher, "owner-b@example.test").await;
        let policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                Some(&account_a.to_string()),
                Some("+15555550101"),
            )
            .unwrap(),
        );
        let app =
            router(MessagesHttpState::new(url.clone(), hasher.clone(), policy, false).unwrap());
        let message_id = Uuid::new_v4();
        let input = serde_json::json!({
            "client_message_id":message_id,
            "device_id":device_a,
            "recipient_e164":"+15555550101",
            "test_case_id":"case_1",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let missing_auth = Request::builder()
            .method("POST")
            .uri("/messages")
            .header(IDEMPOTENCY_HEADER, "case-0")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(input.to_string()))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(missing_auth).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "case-1", input.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let accepted: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(accepted["message_id"], message_id.to_string());
        assert_eq!(accepted["created"], true);
        assert!(!String::from_utf8_lossy(&data).contains("+15555550101"));
        assert!(!String::from_utf8_lossy(&data).contains("synthetic test"));
        let saved: String = client
            .query_one(
                "SELECT convert_from(transport_payload,'UTF8') FROM messages WHERE id=$1",
                &[&message_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(saved, "ZROtext synthetic test: case_1");
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "case-1", input.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let replay: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(replay["created"], false);
        let expiring = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":device_a,
            "recipient_e164":"+15555550101",
            "test_case_id":"expires_soon",
            "expires_at_ms":now_ms().unwrap()+5_000
        });
        let expiry = expiring["expires_at_ms"].as_i64().unwrap();
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "expires-soon", expiring.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&data).unwrap()["created"],
            true
        );
        tokio::time::sleep(std::time::Duration::from_millis(
            (expiry - now_ms().unwrap() + 10).max(0) as u64,
        ))
        .await;
        let response = app
            .clone()
            .oneshot(post("/messages", &send_a, "expires-soon", expiring.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let expired_replay: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(expired_replay["message_id"], expiring["client_message_id"]);
        assert_eq!(expired_replay["created"], false);
        let mut changed_expired = expiring.clone();
        changed_expired["test_case_id"] = "changed".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "expires-soon", changed_expired))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let mut changed_expiry = expiring.clone();
        changed_expiry["expires_at_ms"] = (now_ms().unwrap() + 16 * 60 * 1000).into();
        assert_eq!(
            app.clone()
                .oneshot(post(
                    "/messages",
                    &send_a,
                    "expires-soon",
                    changed_expiry.clone()
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        changed_expiry["client_message_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "too-far-future", changed_expiry))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let mut new_expired = expiring.clone();
        new_expired["client_message_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "new-expired", new_expired))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            app.clone()
                .oneshot(post(
                    "/messages",
                    &send_a,
                    "new-expired-same-id",
                    expiring.clone()
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let counts = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1)",
                &[&account_a],
            )
            .await
            .unwrap();
        assert_eq!(
            (0..3)
                .map(|index| counts.get::<_, i64>(index))
                .collect::<Vec<_>>(),
            vec![2; 3],
            "expired retry created a second dispatch"
        );
        let mut changed = input.clone();
        changed["test_case_id"] = "changed".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-1", changed))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let mut bad_device = input.clone();
        bad_device["client_message_id"] = Uuid::new_v4().to_string().into();
        bad_device["device_id"] = device_b.to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-2", bad_device.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &unbound_send_a, "case-2", bad_device))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let mut wrong_number = input.clone();
        wrong_number["client_message_id"] = Uuid::new_v4().to_string().into();
        wrong_number["recipient_e164"] = "+15555550102".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-3", wrong_number))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &read_a, "case-4", input.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut arbitrary_plaintext = input.clone();
        arbitrary_plaintext["test_case_id"] = "hello world".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-5", arbitrary_plaintext))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        let path = format!("/messages/{message_id}");
        let response = app.clone().oneshot(get(&path, &read_a)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data = to_bytes(response.into_body(), 2048).await.unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(snapshot["state"], "queued");
        assert!(!String::from_utf8_lossy(&data).contains("+15555550101"));
        assert!(!String::from_utf8_lossy(&data).contains("synthetic test"));
        assert_eq!(
            app.clone()
                .oneshot(get(&path, &read_b))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let response = app
            .clone()
            .oneshot(post(
                &format!("{path}/cancel"),
                &send_a,
                "unused",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            app.clone()
                .oneshot(post(
                    &format!("{path}/cancel"),
                    &send_a,
                    "unused",
                    serde_json::json!({})
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        // Strict JSON and case identifiers cannot carry arbitrary message text.
        for bad_case in [
            "hello world",
            "../escape",
            "case\nsecond",
            "case\0",
            "';DROP TABLE messages;--",
            "a".repeat(33).as_str(),
        ] {
            let mut malformed = input.clone();
            malformed["test_case_id"] = bad_case.into();
            assert_eq!(
                app.clone()
                    .oneshot(post("/messages", &send_a, "bad-case", malformed))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let mut unknown = input.clone();
        unknown["body"] = "arbitrary message".into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "unknown", unknown))
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        let mut oversized = input.clone();
        oversized["test_case_id"] = "a".repeat(2048).into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "oversized", oversized))
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        // Terminal messages free queue slots, but must not reset the admission
        // budget. Rotate keys, message IDs and devices under the same account.
        let rotated_device = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'budget fixture')",
                &[&rotated_device, &account_a],
            )
            .await
            .unwrap();
        client
            .execute(
                "DELETE FROM auth_abuse_counters WHERE scope='alpha_send'",
                &[],
            )
            .await
            .unwrap();
        for index in 0..60 {
            let mut churn = input.clone();
            let id = Uuid::new_v4();
            churn["client_message_id"] = id.to_string().into();
            let token = if index % 2 == 0 {
                &send_a
            } else {
                &unbound_send_a
            };
            if index % 2 == 1 {
                churn["device_id"] = rotated_device.to_string().into();
            }
            assert_eq!(
                app.clone()
                    .oneshot(post("/messages", token, &format!("churn-{index}"), churn))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::ACCEPTED
            );
            assert_eq!(
                app.clone()
                    .oneshot(post(
                        &format!("/messages/{id}/cancel"),
                        token,
                        "unused",
                        serde_json::json!({})
                    ))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NO_CONTENT
            );
        }
        let before: i64 = client
            .query_one(
                "SELECT count(*) FROM messages WHERE account_id=$1",
                &[&account_a],
            )
            .await
            .unwrap()
            .get(0);
        let mut denied = input.clone();
        denied["client_message_id"] = Uuid::new_v4().to_string().into();
        let denied_response = app
            .clone()
            .oneshot(post("/messages", &unbound_send_a, "churn-overflow", denied))
            .await
            .unwrap();
        assert_eq!(denied_response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(denied_response.headers()[header::RETRY_AFTER], "60");
        let after: i64 = client
            .query_one(
                "SELECT count(*) FROM messages WHERE account_id=$1",
                &[&account_a],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after);
        // Even an exact replay is an admission attempt when the budget is spent.
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-1", input.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Losing the budget relation must fail closed before storing a message.
        client
            .batch_execute("ALTER TABLE auth_abuse_counters RENAME TO unavailable_abuse_counters")
            .await
            .unwrap();
        let mut unavailable = input.clone();
        unavailable["client_message_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post(
                    "/messages",
                    &send_a,
                    "budget-unavailable",
                    unavailable
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        client
            .batch_execute("ALTER TABLE unavailable_abuse_counters RENAME TO auth_abuse_counters")
            .await
            .unwrap();
        let after_failure: i64 = client
            .query_one(
                "SELECT count(*) FROM messages WHERE account_id=$1",
                &[&account_a],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(before, after_failure);

        client
            .execute(
                "UPDATE devices SET revoked_at=now() WHERE account_id=$1 AND id=$2",
                &[&account_a, &device_a],
            )
            .await
            .unwrap();
        let mut revoked_device_input = input.clone();
        revoked_device_input["client_message_id"] = Uuid::new_v4().to_string().into();
        assert_eq!(
            app.clone()
                .oneshot(post("/messages", &send_a, "case-7", revoked_device_input))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        let (metered_account, metered_device, metered_send, _, _) =
            owner(&mut client, &hasher, "owner-metered@example.test").await;
        client
            .execute(
                "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',0,'stripe_test')",
                &[&metered_account],
            )
            .await
            .unwrap();
        let metered_policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                Some(&metered_account.to_string()),
                Some("+15555550101"),
            )
            .unwrap(),
        );
        let metered = router(
            MessagesHttpState::new(url.clone(), hasher.clone(), metered_policy.clone(), true)
                .unwrap(),
        );
        let metered_input = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":metered_device,
            "recipient_e164":"+15555550101",
            "test_case_id":"empty_quota",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let response = metered
            .oneshot(post(
                "/messages",
                &metered_send,
                "metered-zero",
                metered_input,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
            "quota_exceeded"
        );
        let counts: Vec<i64> = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1),
                        (SELECT count(*) FROM usage_ledger WHERE account_id=$1)",
                &[&metered_account],
            )
            .await
            .map(|row| (0..4).map(|index| row.get(index)).collect())
            .unwrap();
        assert_eq!(counts, vec![0, 0, 0, 0]);
        client
            .execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_persistedtest')",
                &[&metered_account],
            )
            .await
            .unwrap();
        let billing_off = router(
            MessagesHttpState::new(url.clone(), hasher.clone(), metered_policy, false).unwrap(),
        );
        let restart_input = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":metered_device,
            "recipient_e164":"+15555550101",
            "test_case_id":"billing_off",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let response = billing_off
            .clone()
            .oneshot(post(
                "/messages",
                &metered_send,
                "billed-after-restart",
                restart_input,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
            "billing_pending"
        );
        let row = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1),
                        (SELECT count(*) FROM usage_ledger WHERE account_id=$1)",
                &[&metered_account],
            )
            .await
            .unwrap();
        assert_eq!(
            (0..4)
                .map(|index| row.get::<_, i64>(index))
                .collect::<Vec<_>>(),
            vec![0; 4]
        );
        // Billing ingress holds the customer before inserting a risk event.
        // Admission must wait on that customer without holding an account lock
        // that would block the event's account FK KEY SHARE lock.
        let (mut ingress, ingress_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { ingress_connection.await.unwrap() });
        let risk_ingress = ingress.transaction().await.unwrap();
        let ingress_pid: i32 = risk_ingress
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        risk_ingress
            .query_one(
                "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR UPDATE",
                &[&metered_account],
            )
            .await
            .unwrap();
        let risk_input = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":metered_device,
            "recipient_e164":"+15555550101",
            "test_case_id":"risk_ingress",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let risk_send = metered_send.clone();
        let mut admission = tokio::spawn(async move {
            billing_off
                .oneshot(post("/messages", &risk_send, "risk-ingress", risk_input))
                .await
                .unwrap()
        });
        let mut waiting_on_customer = false;
        for _ in 0..200 {
            let blocked: i64 = client
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE query LIKE '%SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE%'
                       AND wait_event_type='Lock'
                       AND $1 = ANY(pg_blocking_pids(pid))",
                    &[&ingress_pid],
                )
                .await
                .unwrap()
                .get(0);
            if blocked > 0 {
                waiting_on_customer = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(
            waiting_on_customer,
            "alpha did not wait on the customer lock"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut admission)
                .await
                .is_err()
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            risk_ingress.execute(
                "INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) \
                 VALUES('evt_lockrisk1','charge.dispute.created',$1,decode(repeat('ab',32),'hex'),'queued')",
                &[&metered_account],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        risk_ingress
            .execute(
                "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
                 VALUES('evt_lockrisk1','ch_lockrisk1','dispute',$1)",
                &[&metered_account],
            )
            .await
            .unwrap();
        risk_ingress.commit().await.unwrap();
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), admission)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
            "payment_hold"
        );
        let risk_counts = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1),
                        (SELECT count(*) FROM usage_ledger WHERE account_id=$1)",
                &[&metered_account],
            )
            .await
            .unwrap();
        assert_eq!(
            (0..4)
                .map(|index| risk_counts.get::<_, i64>(index))
                .collect::<Vec<_>>(),
            vec![0; 4]
        );
        let (active_account, active_device, active_send, _, _) =
            owner(&mut client, &hasher, "owner-active@example.test").await;
        client
            .execute(
                "INSERT INTO usage_quota_policies(account_id,metric,limit_units,source) VALUES($1,'outbound_message',1,'stripe_test')",
                &[&active_account],
            )
            .await
            .unwrap();
        let active_policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                Some(&active_account.to_string()),
                Some("+15555550101"),
            )
            .unwrap(),
        );
        let active_app = router(
            MessagesHttpState::new(url.clone(), hasher.clone(), active_policy, true).unwrap(),
        );
        let active_input = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":active_device,
            "recipient_e164":"+15555550101",
            "test_case_id":"active_quota",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        assert_eq!(
            active_app
                .oneshot(post(
                    "/messages",
                    &active_send,
                    "active-quota",
                    active_input
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        let active_counts = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1),
                        (SELECT count(*) FROM usage_ledger WHERE account_id=$1 AND entry_kind='reserve')",
                &[&active_account],
            )
            .await
            .unwrap();
        assert_eq!(
            (0..4)
                .map(|index| active_counts.get::<_, i64>(index))
                .collect::<Vec<_>>(),
            vec![1; 4]
        );
        let (race_account, race_device, race_send, _, _) =
            owner(&mut client, &hasher, "owner-race@example.test").await;
        // Let admission observe no binding, then stop it on the account lock.
        // A new binding can commit while this KEY SHARE guard is held.
        let (mut account_blocker, blocker_connection) =
            tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { blocker_connection.await.unwrap() });
        let account_guard = account_blocker.transaction().await.unwrap();
        let blocker_pid: i32 = account_guard
            .query_one("SELECT pg_backend_pid()", &[])
            .await
            .unwrap()
            .get(0);
        account_guard
            .query_one(
                "SELECT id FROM accounts WHERE id=$1 FOR KEY SHARE",
                &[&race_account],
            )
            .await
            .unwrap();
        let (mut binder, binder_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { binder_connection.await.unwrap() });
        let binding = binder.transaction().await.unwrap();
        binding
            .query_one(
                "SELECT id FROM accounts WHERE id=$1 FOR KEY SHARE",
                &[&race_account],
            )
            .await
            .unwrap();
        let race_policy = Arc::new(
            AlphaPolicy::parse(
                Some("true"),
                Some(&race_account.to_string()),
                Some("+15555550101"),
            )
            .unwrap(),
        );
        let race_app = router(
            MessagesHttpState::new(url.clone(), hasher.clone(), race_policy, false).unwrap(),
        );
        let race_input = serde_json::json!({
            "client_message_id":Uuid::new_v4(),
            "device_id":race_device,
            "recipient_e164":"+15555550101",
            "test_case_id":"binding_race",
            "expires_at_ms":now_ms().unwrap()+600_000
        });
        let request = tokio::spawn(async move {
            race_app
                .oneshot(post("/messages", &race_send, "binding-race", race_input))
                .await
                .unwrap()
        });
        let mut waiting_on_account = false;
        for _ in 0..200 {
            let blocked: i64 = client
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE query LIKE '%SELECT id FROM accounts WHERE id=$1 FOR UPDATE%'
                       AND wait_event_type='Lock'
                       AND $1 = ANY(pg_blocking_pids(pid))",
                    &[&blocker_pid],
                )
                .await
                .unwrap()
                .get(0);
            if blocked > 0 {
                waiting_on_account = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(waiting_on_account, "alpha did not wait on the account lock");
        binding
            .execute(
                "INSERT INTO billing_customers(account_id,stripe_customer_id) VALUES($1,'cus_racetest')",
                &[&race_account],
            )
            .await
            .unwrap();
        binding.commit().await.unwrap();
        let (mut race_risk, risk_connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { risk_connection.await.unwrap() });
        let risk_tx = race_risk.transaction().await.unwrap();
        risk_tx
            .query_one(
                "SELECT account_id FROM billing_customers WHERE account_id=$1 FOR UPDATE",
                &[&race_account],
            )
            .await
            .unwrap();
        account_guard.commit().await.unwrap();
        // The account lock fences further binding inserts. A plain MVCC
        // recheck can see the committed binding while risk ingress holds the
        // customer; a locking recheck would wait on the risk transaction.
        let response = tokio::time::timeout(std::time::Duration::from_secs(5), request)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            risk_tx.execute(
                "INSERT INTO billing_events(stripe_event_id,event_type,account_id,body_sha256,disposition) \
                 VALUES('evt_bindrisk1','charge.dispute.created',$1,decode(repeat('cd',32),'hex'),'queued')",
                &[&race_account],
            ),
        )
        .await
        .unwrap()
        .unwrap();
        risk_tx
            .execute(
                "INSERT INTO billing_risk_events(stripe_event_id,stripe_charge_id,risk_kind,account_id) \
                 VALUES('evt_bindrisk1','ch_bindrisk1','dispute',$1)",
                &[&race_account],
            )
            .await
            .unwrap();
        risk_tx.commit().await.unwrap();
        let race_counts = client
            .query_one(
                "SELECT (SELECT count(*) FROM messages WHERE account_id=$1),
                        (SELECT count(*) FROM dispatch_jobs WHERE account_id=$1),
                        (SELECT count(*) FROM idempotency_keys WHERE account_id=$1),
                        (SELECT count(*) FROM usage_ledger WHERE account_id=$1)",
                &[&race_account],
            )
            .await
            .unwrap();
        assert_eq!(
            (0..4)
                .map(|index| race_counts.get::<_, i64>(index))
                .collect::<Vec<_>>(),
            vec![0; 4]
        );
        let disabled = router(
            MessagesHttpState::new(
                url,
                hasher,
                Arc::new(AlphaPolicy::parse(None, None, None).unwrap()),
                false,
            )
            .unwrap(),
        );
        assert_eq!(
            disabled
                .oneshot(post("/messages", &send_a, "case-6", input))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
