// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in service HTTP transport, not an MCP remote endpoint or owner authority.
use crate::auth::{AuthError, TokenHasher};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::{sync::Arc, time::Duration};

const BODY_LIMIT: usize = 65_536;
const RESPONSE_LIMIT: usize = 131_072;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct WorkflowHttpState {
    pub database_url: String,
    pub hasher: Arc<TokenHasher>,
}
pub fn router(state: WorkflowHttpState, enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/workflow/tools", get(readiness).post(call))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().expect("static header"));
    response
}
pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str, AuthError> {
    if headers.contains_key(header::COOKIE) || headers.contains_key(header::ORIGIN) {
        return Err(AuthError::Unauthorized);
    }
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let token = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AuthError::Unauthorized)?;
    if values.next().is_some() || !super::authentication::credential_shape(token) {
        return Err(AuthError::Unauthorized);
    }
    Ok(token)
}
pub(crate) fn refusal(error: AuthError) -> Response {
    let (status, code) = match error {
        AuthError::InvalidInput => (StatusCode::BAD_REQUEST, "invalid_request"),
        AuthError::Unauthorized | AuthError::InvalidCredentials | AuthError::MfaRequired { .. } => {
            (StatusCode::UNAUTHORIZED, "unauthorized")
        }
        AuthError::Forbidden | AuthError::EmailNotVerified => (StatusCode::FORBIDDEN, "forbidden"),
        AuthError::Conflict | AuthError::SmsOwnerKeyActive => (StatusCode::CONFLICT, "conflict"),
        AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        AuthError::Database(_) | AuthError::Password | AuthError::Crypto => {
            (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    };
    (status, Json(serde_json::json!({"error":{"code":code}}))).into_response()
}
pub(crate) fn response(value: impl Serialize) -> Response {
    match serde_json::to_vec(&value) {
        Ok(body) if body.len() <= RESPONSE_LIMIT => {
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
        _ => refusal(AuthError::Crypto),
    }
}
async fn readiness(State(state): State<Arc<WorkflowHttpState>>, request: Request) -> Response {
    let result = tokio::time::timeout(DEADLINE, async move {
        if request.uri().query().is_some() {
            return Err(AuthError::InvalidInput);
        }
        let token = zeroize::Zeroizing::new(bearer(request.headers())?.to_owned());
        let mut client = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        let principal = super::authenticate(&client, &state.hasher, &token).await?;
        super::readiness::read(&mut client, &principal).await
    })
    .await;
    match result {
        Ok(Ok(value)) => response(value),
        Ok(Err(error)) => refusal(error),
        Err(_) => refusal(AuthError::Crypto),
    }
}
async fn call(State(state): State<Arc<WorkflowHttpState>>, request: Request) -> Response {
    let result = tokio::time::timeout(DEADLINE, async move {
        if request.uri().query().is_some() {
            return Err(AuthError::InvalidInput);
        }
        let token = zeroize::Zeroizing::new(bearer(request.headers())?.to_owned());
        let mut client = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        let principal = super::authenticate(&client, &state.hasher, &token).await?;
        if request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next().map(str::trim) != Some("application/json"))
        {
            return Err(AuthError::InvalidInput);
        }
        let bytes = to_bytes(request.into_body(), BODY_LIMIT)
            .await
            .map_err(|_| AuthError::InvalidInput)?;
        let body: super::contracts::Request =
            serde_json::from_slice(&bytes).map_err(|_| AuthError::InvalidInput)?;
        body.validate().map_err(|_| AuthError::InvalidInput)?;
        super::call(&mut client, &principal, body).await
    })
    .await;
    match result {
        Ok(Ok(value)) => response(value),
        Ok(Err(error)) => refusal(error),
        Err(_) => refusal(AuthError::Crypto),
    }
}

#[cfg(test)]
mod tests;
