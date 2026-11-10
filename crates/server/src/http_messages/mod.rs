// SPDX-License-Identifier: AGPL-3.0-only
//! Private synthetic-alpha message routes. The caller can select only a short
//! test-case identifier; this module constructs the fixed plaintext body.
//! Never mount as a general customer message-content endpoint.

use crate::api_json::ApiJson;
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
#[cfg(test)]
use tokio_postgres::Client;
use tokio_postgres::types::Type;
use uuid::Uuid;
use zrotext_delivery_store::{NewMessage, StoreError};
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
    RecipientSuppressed,
    LineNotReady {
        code: &'static str,
        label: Option<String>,
    },
    Unavailable,
}

impl IntoResponse for MessageHttpError {
    fn into_response(self) -> Response {
        let (status, code, line_label) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request", None),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Conflict => (StatusCode::CONFLICT, "conflict", None),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None),
            Self::QueueFull => (StatusCode::TOO_MANY_REQUESTS, "queue_full", None),
            Self::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded", None),
            Self::BillingPending => (StatusCode::SERVICE_UNAVAILABLE, "billing_pending", None),
            Self::PaymentHold => (StatusCode::PAYMENT_REQUIRED, "payment_hold", None),
            Self::RecipientSuppressed => (StatusCode::FORBIDDEN, "recipient_suppressed", None),
            Self::LineNotReady { code, label } => (StatusCode::CONFLICT, code, label),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable", None),
        };
        let mut response = (status, Json(ErrorBody { code, line_label })).into_response();
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
    #[serde(skip_serializing_if = "Option::is_none")]
    line_label: Option<String>,
}

fn map_auth(error: AuthError) -> MessageHttpError {
    match error {
        AuthError::Unauthorized | AuthError::InvalidCredentials => MessageHttpError::Unauthorized,
        AuthError::Forbidden | AuthError::EmailNotVerified | AuthError::SmsOwnerKeyActive => {
            MessageHttpError::Forbidden
        }
        // API-key routes never consult seat state; a conflict is not a
        // credential failure, so it fails closed as an authorization error.
        AuthError::Conflict => MessageHttpError::Forbidden,
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
        StoreError::Database(_)
        | StoreError::DispatchDisabled
        | StoreError::StaleFence
        | StoreError::RuntimeIdentityUnavailable => MessageHttpError::Unavailable,
        StoreError::PaymentHold => MessageHttpError::PaymentHold,
        StoreError::QuotaNotConfigured => MessageHttpError::BillingPending,
        StoreError::QuotaExceeded => MessageHttpError::QuotaExceeded,
        StoreError::RecipientSuppressed => MessageHttpError::RecipientSuppressed,
        StoreError::DeviceBusy | StoreError::EventIdConflict => MessageHttpError::Conflict,
        StoreError::QueueFull => MessageHttpError::QueueFull,
        // The addressed line's not-ready policy refused before acceptance;
        // the response names the stable code and the resolved label.
        StoreError::LineNotReady { code, label } => MessageHttpError::LineNotReady { code, label },
        StoreError::PolicyCorrupt => MessageHttpError::Unavailable,
    }
}

async fn connect(database_url: &str) -> Result<crate::runtime_db::PooledClient, MessageHttpError> {
    crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| MessageHttpError::Unavailable)
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

/// A line label is an owner-chosen name: short, single-line, printable,
/// trimmed. It addresses immutable line identity at admission and never
/// carries a SIM slot, subscription identifier, ICCID, IMSI or phone number.
fn valid_line_label(label: &str) -> bool {
    let trimmed = label.trim();
    (1..=64).contains(&label.chars().count())
        && !trimmed.is_empty()
        && label == trimmed
        && label.chars().all(|c| !c.is_control())
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
    /// Owner-named line label (ADR 0004). Absent keeps line-free routing.
    #[serde(default)]
    line: Option<String>,
    /// Decline fallback for this message even when the addressed line's
    /// policy names a fallback line.
    #[serde(default)]
    no_fallback: bool,
}

#[derive(Serialize)]
struct AcceptedBody {
    message_id: Uuid,
    created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_label: Option<String>,
}

/// The API key of an accept request, authenticated from headers alone before
/// the body is read, plus the account's in-flight slot. The same stateless
/// checks as before run first, in the same order; the pooled client used for
/// the key lookup is released before the body is read.
struct AcceptAuth {
    principal: auth::ApiPrincipal,
    _slot: crate::http_auth::preauth::AccountSlot,
}

impl axum::extract::FromRequestParts<Arc<MessagesHttpState>> for AcceptAuth {
    type Rejection = MessageHttpError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<MessagesHttpState>,
    ) -> Result<Self, MessageHttpError> {
        if !state.policy.enabled() {
            return Err(MessageHttpError::NotFound);
        }
        let token = bearer(&parts.headers)?;
        idempotency_key(&parts.headers)?;
        let principal = {
            let client = connect(&state.database_url).await?;
            auth::authenticate_api_key(&client, &state.hasher, token)
                .await
                .map_err(map_auth)?
        };
        let _slot =
            crate::http_auth::preauth::AccountSlot::try_acquire(principal.tenant.account_id())
                .ok_or(MessageHttpError::RateLimited)?;
        Ok(Self { principal, _slot })
    }
}

async fn accept(
    State(state): State<Arc<MessagesHttpState>>,
    headers: HeaderMap,
    auth: AcceptAuth,
    ApiJson(body): ApiJson<AcceptBody>,
) -> Result<Response, MessageHttpError> {
    let key = idempotency_key(&headers)?;
    if !valid_e164(&body.recipient_e164)
        || body.test_case_id.is_empty()
        || body.test_case_id.len() > 32
        || !body
            .test_case_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || body
            .line
            .as_ref()
            .is_some_and(|label| !valid_line_label(label))
    {
        return Err(MessageHttpError::BadRequest);
    }
    let principal = &auth.principal;
    principal
        .require(Scope::MessagesSend, Some(body.device_id))
        .map_err(map_auth)?;
    let mut client = connect(&state.database_url).await?;
    let account_id = principal.tenant.account_id();
    if !state.policy.allows(account_id, &body.recipient_e164) {
        return Err(MessageHttpError::NotFound);
    }
    let active = client
        .query_typed_opt(
            "SELECT 1 FROM devices WHERE account_id=$1 AND id=$2 AND revoked_at IS NULL",
            &[(&account_id, Type::UUID), (&body.device_id, Type::UUID)],
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
        line_label: body.line.as_deref(),
        no_fallback: body.no_fallback,
    };
    let mut store = client.delivery_store_with_idempotency_days(state.idempotency_days);
    let outcome = store
        .accept_alpha(input, state.metered, principal.bound_device())
        .await
        .map_err(map_store)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedBody {
            message_id: outcome.message_id,
            created: outcome.created,
            line_label: outcome.line_label,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    line_label: Option<String>,
}

async fn status(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<StatusBody>, MessageHttpError> {
    // A missing or malformed header is rejected before taking a pooled slot.
    let token = bearer(&headers)?;
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, token)
        .await
        .map_err(map_auth)?;
    let snapshot = client
        .delivery_store()
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
        line_label: snapshot.line_label,
    }))
}

async fn cancel(
    State(state): State<Arc<MessagesHttpState>>,
    Path(message_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, MessageHttpError> {
    let token = bearer(&headers)?;
    let mut client = connect(&state.database_url).await?;
    let principal = auth::authenticate_api_key(&client, &state.hasher, token)
        .await
        .map_err(map_auth)?;
    let snapshot = client
        .delivery_store()
        .status(principal.tenant.account_id(), message_id)
        .await
        .map_err(map_store)?
        .ok_or(MessageHttpError::NotFound)?;
    principal
        .require(Scope::MessagesSend, Some(snapshot.device_id))
        .map_err(map_auth)?;
    if client
        .delivery_store()
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
mod tests;
