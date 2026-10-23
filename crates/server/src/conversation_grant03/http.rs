// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit bounded signed-fetch composition. No owner bearer, cookie or
//! received runtime selector supplies access; startup leaves this unmounted.
use super::*;
use crate::auth::{TokenHasher, abuse_limits};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct FetchState03 {
    database_url: String,
    site: String,
    deployment: u64,
    origin: String,
    hasher: Arc<TokenHasher>,
    capacity: Arc<Semaphore>,
}
impl FetchState03 {
    /// Independently checked startup inputs, never fields from the request.
    pub fn new(
        database_url: String,
        site: String,
        deployment: u64,
        origin: String,
        hasher: Arc<TokenHasher>,
    ) -> std::result::Result<Self, &'static str> {
        if database_url.is_empty()
            || site.is_empty()
            || site.len() > 256
            || deployment == 0
            || deployment > i64::MAX as u64
            || site.chars().any(char::is_control)
        {
            return Err("profile03 fetch configuration invalid");
        }
        crate::sealed_payload_election03::adapter_contract::origin_digest(&origin)?;
        Ok(Self {
            database_url,
            site,
            deployment,
            origin,
            hasher,
            capacity: Arc::new(Semaphore::new(8)),
        })
    }
}
pub async fn router(state: FetchState03) -> std::result::Result<Router, &'static str> {
    let db = crate::runtime_db::connect_device(&state.database_url)
        .await
        .map_err(|_| "profile03 fetch database unavailable")?;
    crate::conversation_profile03_grant_storage::require(&*db)
        .await
        .map_err(|_| "profile03 fetch schema unavailable")?;
    crate::conversation_reviewed_send03_storage::require_v2(&*db)
        .await
        .map_err(|_| "profile03 reviewed intent V2 schema unavailable")?;
    crate::conversation_profile03_effect_storage::require(&*db)
        .await
        .map_err(|_| "profile03 original actor schema unavailable")?;
    Ok(routes(state))
}
fn routes(state: FetchState03) -> Router {
    Router::new()
        .route("/v1/sealed/dispatch/envelope03", post(retrieve))
        .with_state(state)
}
async fn retrieve(State(state): State<FetchState03>, request: Request) -> Response {
    response(handle(&state, request).await)
}
fn response(result: std::result::Result<serde_json::Value, StatusCode>) -> Response {
    let (status, value) = match result {
        Ok(value) => (StatusCode::OK, value),
        Err(status) => {
            let error = match status {
                StatusCode::BAD_REQUEST => "invalid_request",
                StatusCode::NOT_FOUND => "not_found",
                StatusCode::TOO_MANY_REQUESTS => "rate_limited",
                _ => "temporarily_unavailable",
            };
            (status, serde_json::json!({"error":error}))
        }
    };
    let mut result = (status, Json(value)).into_response();
    result
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    result
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    result
}
async fn handle(
    state: &FetchState03,
    request: Request,
) -> std::result::Result<serde_json::Value, StatusCode> {
    let _permit = state
        .capacity
        .try_acquire()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let (parts, body) = request.into_parts();
    // Native proof is the sole request credential. Refuse browser and bearer
    // ambient authority before parsing, without changing any legacy route.
    if parts.headers.contains_key(header::AUTHORIZATION)
        || parts.headers.contains_key(header::COOKIE)
        || parts.headers.contains_key(header::ORIGIN)
        || parts.headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            != Some("application/json")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let bytes = tokio::time::timeout(Duration::from_secs(5), to_bytes(body, 4096))
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let request = Fetch03::parse(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut db = crate::runtime_db::connect_device(&state.database_url)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::conversation_profile03_grant_storage::require(&*db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::conversation_reviewed_send03_storage::require_v2(&*db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    crate::conversation_profile03_effect_storage::require(&*db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let anonymous = abuse_limits::consume_profile_fetch(&db, &state.hasher, None)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let serving = FetchServing03 {
        site: &state.site,
        deployment: state.deployment,
        origin: &state.origin,
    };
    // This cheap retained/enrolled signature proof permits only the independent
    // verified budget. The full held fetch below repeats proof and every current
    // predicate; no detached preflight result becomes effect authority.
    match preflight(&db, serving, &request).await {
        Ok(()) => {}
        Err(Error::Database(_) | Error::Unavailable) => {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(_) => {
            return Err(if anonymous {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::TOO_MANY_REQUESTS
            });
        }
    }
    let who = request.grant().claims();
    let subject = format!("{}:{}", who.account_id, who.device_id);
    if !abuse_limits::consume_profile_fetch(&db, &state.hasher, Some(&subject))
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let reply = fetch(&mut db, serving, &request)
        .await
        .map_err(|error| match error {
            Error::Database(_) | Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::NOT_FOUND,
        })?;
    if serde_json::to_vec(&reply)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .len()
        > 192 * 1024
    {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests;
