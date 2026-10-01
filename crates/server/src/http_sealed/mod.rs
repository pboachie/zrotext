// SPDX-License-Identifier: AGPL-3.0-only
//! Sealed v1 message admission route. The route exists only when the runtime
//! mounts it behind `SEALED_ADMISSION_ENABLED`; off — the default — leaves the
//! path absent and no sealed code path runs. The request body is one complete
//! opaque sealed envelope: never JSON, never plaintext, never a translated
//! alternative. Acceptance queues exact bytes toward the bound device; it is
//! never carrier evidence and never an execution grant.

use crate::{
    auth::{self, AuthError, TokenHasher},
    sealed_inbound::upload::{self, UploadContext, UploadError},
    sealed_outbound::{self, AdmitError, WriterContext},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;
use zrotext_delivery_store::StoreError;

/// The only accepted request content type, byte-exact with no parameters.
pub(crate) const SEALED_CONTENT_TYPE: &str = "application/vnd.zrotext.sealed.v1";
/// Request-body cap shared with the envelope pre-allocation bound.
const MAX_BODY_BYTES: usize = 36_864;
/// Envelope bounds from the sealed v1 contract: kind-01 outbound and
/// kind-02 inbound share the floor; inbound tops out lower.
const MIN_ENVELOPE_BYTES: usize = 426;
const MAX_ENVELOPE_BYTES: usize = 34_213;
const MAX_INBOUND_ENVELOPE_BYTES: usize = 34_082;
const IDEMPOTENCY_HEADER: &str = "idempotency-key";

mod lifecycle;

#[derive(Clone)]
pub struct SealedHttpState {
    database_url: String,
    hasher: Arc<TokenHasher>,
    enabled: bool,
    site_id: Arc<str>,
    deployment_epoch: i64,
    billing_enabled: bool,
}

impl SealedHttpState {
    pub fn new(
        database_url: String,
        hasher: Arc<TokenHasher>,
        site_id: String,
        deployment_epoch: i64,
        billing_enabled: bool,
    ) -> Result<Self, &'static str> {
        if database_url.is_empty() {
            return Err("message database URL is required");
        }
        if site_id.is_empty() {
            return Err("site id is required");
        }
        if deployment_epoch <= 0 {
            return Err("deployment epoch must be positive");
        }
        Ok(Self {
            database_url,
            hasher,
            enabled: true,
            site_id: site_id.into(),
            deployment_epoch,
            billing_enabled,
        })
    }

    /// The unmounted default: every request fails closed before any other
    /// state is consulted.
    pub fn disabled(database_url: String, hasher: Arc<TokenHasher>) -> Self {
        Self {
            database_url,
            hasher,
            enabled: false,
            site_id: "".into(),
            deployment_epoch: 0,
            billing_enabled: false,
        }
    }
}

pub fn router(state: SealedHttpState) -> Router {
    Router::new()
        .route("/messages", post(accept).get(lifecycle::list))
        .route("/messages/{message_id}", get(lifecycle::status))
        .route("/messages/{message_id}/cancel", post(lifecycle::cancel))
        .route("/inbound-events", post(accept_inbound))
        .merge(resources::routes())
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
enum SealedHttpError {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    IdempotencyConflict,
    UnsupportedMediaType,
    RateLimited,
    QueueFull,
    QuotaExceeded,
    BillingPending,
    Unavailable,
    StaleEvent,
    EventIdConflict,
    SequenceConflict,
    CancellationConflict,
}

impl IntoResponse for SealedHttpError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::BadRequest => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::IdempotencyConflict => (StatusCode::CONFLICT, "idempotency_conflict"),
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type")
            }
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::QueueFull => (StatusCode::TOO_MANY_REQUESTS, "queue_full"),
            Self::QuotaExceeded => (StatusCode::TOO_MANY_REQUESTS, "quota_exceeded"),
            Self::BillingPending => (StatusCode::SERVICE_UNAVAILABLE, "billing_pending"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::StaleEvent => (StatusCode::BAD_REQUEST, "stale_event"),
            Self::EventIdConflict => (StatusCode::CONFLICT, "event_id_conflict"),
            Self::SequenceConflict => (StatusCode::CONFLICT, "sequence_conflict"),
            Self::CancellationConflict => (StatusCode::CONFLICT, "cancellation_conflict"),
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

fn map_auth(error: AuthError) -> SealedHttpError {
    match error {
        AuthError::Unauthorized | AuthError::InvalidCredentials => SealedHttpError::Unauthorized,
        AuthError::Forbidden | AuthError::EmailNotVerified | AuthError::SmsOwnerKeyActive => {
            SealedHttpError::Forbidden
        }
        // Only the seat-invitation routes raise Conflict; sealed routes never do.
        AuthError::InvalidInput | AuthError::Conflict => SealedHttpError::BadRequest,
        AuthError::Database(_) | AuthError::Password | AuthError::Crypto => {
            SealedHttpError::Unavailable
        }
        AuthError::MfaRequired { .. } | AuthError::RateLimited => SealedHttpError::Unauthorized,
    }
}

fn map_admit(error: AdmitError) -> SealedHttpError {
    match error {
        AdmitError::Invalid | AdmitError::Verification(_) => SealedHttpError::BadRequest,
        AdmitError::Forbidden | AdmitError::Authority(_) => SealedHttpError::Forbidden,
        AdmitError::RateLimited => SealedHttpError::RateLimited,
        AdmitError::Queue(error) => map_store(error),
        AdmitError::Database(_) => SealedHttpError::Unavailable,
    }
}

fn map_upload(error: UploadError) -> SealedHttpError {
    match error {
        UploadError::InvalidClaims | UploadError::Verification(_) => SealedHttpError::BadRequest,
        UploadError::Forbidden | UploadError::Authority(_) => SealedHttpError::Forbidden,
        UploadError::StaleEvent => SealedHttpError::StaleEvent,
        UploadError::EventConflict => SealedHttpError::EventIdConflict,
        UploadError::SequenceConflict => SealedHttpError::SequenceConflict,
        UploadError::BudgetExhausted => SealedHttpError::RateLimited,
        UploadError::Database(_) => SealedHttpError::Unavailable,
    }
}

fn map_store(error: StoreError) -> SealedHttpError {
    match error {
        StoreError::InvalidInput => SealedHttpError::BadRequest,
        // A stored message identity under a different unsigned digest is the
        // Q6 conflict; exact replays never reach this arm (created: false).
        StoreError::MessageIdConflict
        | StoreError::IdempotencyConflict
        | StoreError::InvalidTransition
        | StoreError::DeviceBusy
        | StoreError::EventIdConflict => SealedHttpError::IdempotencyConflict,
        StoreError::NotFound | StoreError::Revoked => SealedHttpError::Forbidden,
        StoreError::Database(_) | StoreError::DispatchDisabled | StoreError::StaleFence => {
            SealedHttpError::Unavailable
        }
        StoreError::PaymentHold | StoreError::QuotaNotConfigured => SealedHttpError::BillingPending,
        StoreError::QuotaExceeded => SealedHttpError::QuotaExceeded,
        StoreError::RecipientSuppressed => SealedHttpError::Forbidden,
        StoreError::QueueFull => SealedHttpError::QueueFull,
    }
}

async fn connect(database_url: &str) -> Result<crate::runtime_db::PooledClient, SealedHttpError> {
    crate::runtime_db::connect(database_url)
        .await
        .map_err(|_| SealedHttpError::Unavailable)
}

fn bearer(headers: &HeaderMap) -> Result<&str, SealedHttpError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(SealedHttpError::Unauthorized)?;
    if values.next().is_some() {
        return Err(SealedHttpError::Unauthorized);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(' '))
        .ok_or(SealedHttpError::Unauthorized)
}

/// One content-type header, byte-exact with the sealed media type and no
/// parameters. Anything else is refused before authentication so the route
/// never reads a body it cannot admit.
fn sealed_content_type(headers: &HeaderMap) -> Result<(), SealedHttpError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values.next().ok_or(SealedHttpError::UnsupportedMediaType)?;
    if values.next().is_some() {
        return Err(SealedHttpError::UnsupportedMediaType);
    }
    if value.as_bytes() != SEALED_CONTENT_TYPE.as_bytes() {
        return Err(SealedHttpError::UnsupportedMediaType);
    }
    Ok(())
}

/// Idempotency is the unsigned envelope digest (Q6); a caller-supplied key
/// would silently change retry semantics, so its presence is refused.
fn reject_idempotency_key(headers: &HeaderMap) -> Result<(), SealedHttpError> {
    if headers.contains_key(IDEMPOTENCY_HEADER) {
        return Err(SealedHttpError::BadRequest);
    }
    Ok(())
}

/// The API key of a sealed submission, authenticated from headers alone before
/// the envelope body is read, plus the account's in-flight slot. The stateless
/// refusals (disabled route, media type, idempotency key, bearer shape) run in
/// order before any pooled connection is taken.
struct SealedAcceptAuth {
    principal: auth::ApiPrincipal,
    _slot: crate::http_auth::preauth::AccountSlot,
}

impl axum::extract::FromRequestParts<Arc<SealedHttpState>> for SealedAcceptAuth {
    type Rejection = SealedHttpError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<SealedHttpState>,
    ) -> Result<Self, SealedHttpError> {
        if !state.enabled {
            return Err(SealedHttpError::NotFound);
        }
        sealed_content_type(&parts.headers)?;
        reject_idempotency_key(&parts.headers)?;
        let token = bearer(&parts.headers)?;
        let principal = {
            let client = connect(&state.database_url).await?;
            auth::authenticate_api_key(&client, &state.hasher, token)
                .await
                .map_err(map_auth)?
        };
        let _slot =
            crate::http_auth::preauth::AccountSlot::try_acquire(principal.tenant.account_id())
                .ok_or(SealedHttpError::RateLimited)?;
        Ok(Self { principal, _slot })
    }
}

/// The resource-group extractor: the same enabled gate, bearer authentication
/// and account slot as the admission extractor, but no sealed content type —
/// resource reads are ordinary GETs and carry no envelope body.
struct SealedResourceAuth {
    principal: auth::ApiPrincipal,
    _slot: crate::http_auth::preauth::AccountSlot,
}

impl axum::extract::FromRequestParts<Arc<SealedHttpState>> for SealedResourceAuth {
    type Rejection = SealedHttpError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<SealedHttpState>,
    ) -> Result<Self, SealedHttpError> {
        if !state.enabled {
            return Err(SealedHttpError::NotFound);
        }
        let token = bearer(&parts.headers)?;
        let principal = {
            let client = connect(&state.database_url).await?;
            auth::authenticate_api_key(&client, &state.hasher, token)
                .await
                .map_err(map_auth)?
        };
        let _slot =
            crate::http_auth::preauth::AccountSlot::try_acquire(principal.tenant.account_id())
                .ok_or(SealedHttpError::RateLimited)?;
        Ok(Self { principal, _slot })
    }
}

#[derive(Serialize)]
struct AcceptedBody {
    message_id: Uuid,
    created: bool,
}

async fn accept(
    State(state): State<Arc<SealedHttpState>>,
    headers: HeaderMap,
    auth: SealedAcceptAuth,
    body: axum::body::Bytes,
) -> Result<Response, SealedHttpError> {
    reject_idempotency_key(&headers)?;
    if !(MIN_ENVELOPE_BYTES..=MAX_ENVELOPE_BYTES).contains(&body.len()) {
        return Err(SealedHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let outcome = sealed_outbound::admit_candidate02(
        &mut client,
        &auth.principal,
        &state.hasher,
        WriterContext {
            site_id: &state.site_id,
            deployment_epoch: state.deployment_epoch,
            billing_enabled: state.billing_enabled,
        },
        &body,
    )
    .await
    .map_err(map_admit)?;
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
struct InboundAcceptedBody {
    event_id: Uuid,
    created: bool,
}

/// `POST /v1/sealed/inbound-events` (#538): one complete kind-02 envelope
/// captured by a device. Identity is the phone-allocated event id; the
/// (device, device_sequence) fence and the unsigned digest classify replay
/// versus conflict. Acceptance is durable storage only.
async fn accept_inbound(
    State(state): State<Arc<SealedHttpState>>,
    _auth: SealedAcceptAuth,
    body: axum::body::Bytes,
) -> Result<Response, SealedHttpError> {
    if !(MIN_ENVELOPE_BYTES..=MAX_INBOUND_ENVELOPE_BYTES).contains(&body.len()) {
        return Err(SealedHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let outcome = upload::upload_inbound02(
        &mut client,
        &_auth.principal,
        &state.hasher,
        UploadContext {
            site_id: &state.site_id,
            deployment_epoch: state.deployment_epoch,
        },
        &body,
    )
    .await
    .map_err(map_upload)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(InboundAcceptedBody {
            event_id: outcome.event_id,
            created: outcome.created,
        }),
    )
        .into_response())
}

mod resources;

#[cfg(test)]
mod tests;
