// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted authenticated issuer caller. Dependencies are not accepted state.

use crate::{
    auth::{AuthError, TokenHasher, mfa::MfaCipher},
    contact_reader_issuer::{Error, lifecycle, model},
    http_auth::{
        AuthHttpError, preauth::AccountSlot, require_owner, require_owner_read,
        require_owner_read_headers,
    },
};
use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::{sync::Arc, time::Duration};
use tokio::time::{Instant, timeout, timeout_at};
use uuid::Uuid;

const PREFIX: &str = "/v1/owner/contact-reader-issuance";
pub struct OwnerContactIssuanceState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub mfa_cipher: Arc<MfaCipher>,
    pub canonical_origin: String,
}
pub fn router(state: OwnerContactIssuanceState) -> Router {
    Router::new()
        .route(&format!("{PREFIX}/intents"), post(call))
        .route(&format!("{PREFIX}/intents/lookup"), post(call))
        .route(&format!("{PREFIX}/{{authorization}}/complete"), post(call))
        .route(&format!("{PREFIX}/{{authorization}}/cancel"), post(call))
        .route(&format!("{PREFIX}/withdraw"), post(call))
        .route(
            &format!("{PREFIX}/{{authorization}}"),
            get(call).head(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}
async fn no_store(request: Request, next: Next) -> Response {
    let mut r = next.run(request).await;
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
pub(crate) fn error(e: Error) -> AuthHttpError {
    match e {
        Error::Invalid => AuthHttpError::BadRequest,
        Error::NotFound => AuthHttpError::NotFound,
        Error::Conflict => AuthHttpError::Conflict,
        Error::Unavailable | Error::Database(_) => AuthHttpError::Unavailable,
        Error::Authentication(AuthError::Database(_)) => AuthHttpError::Unavailable,
        Error::Authentication(AuthError::RateLimited) => AuthHttpError::TooManyRequests,
        Error::Authentication(_) => AuthHttpError::Unauthorized,
    }
}
fn id(raw: &str) -> Result<Uuid, AuthHttpError> {
    let id = Uuid::parse_str(raw).map_err(|_| AuthHttpError::BadRequest)?;
    if id.is_nil() || raw.len() != 36 || id.to_string() != raw {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(id)
}
enum Operation {
    Create,
    Lookup,
    Complete(Uuid),
    Cancel(Uuid),
    Withdraw,
    Status(Uuid, i64),
}
fn operation(method: &Method, path: &str, query: Option<&str>) -> Result<Operation, AuthHttpError> {
    let suffix = path.strip_prefix(PREFIX).ok_or(AuthHttpError::BadRequest)?;
    if *method == Method::GET {
        let authorization = id(suffix.strip_prefix('/').ok_or(AuthHttpError::BadRequest)?)?;
        let generation = model::status_query(query).map_err(error)?;
        return Ok(Operation::Status(authorization, generation));
    }
    if *method != Method::POST || query.is_some() {
        return Err(AuthHttpError::BadRequest);
    }
    match suffix {
        "/intents" => Ok(Operation::Create),
        "/intents/lookup" => Ok(Operation::Lookup),
        "/withdraw" => Ok(Operation::Withdraw),
        _ => {
            let (raw, tail) = suffix
                .strip_prefix('/')
                .and_then(|p| p.split_once('/'))
                .ok_or(AuthHttpError::BadRequest)?;
            let authorization = id(raw)?;
            match tail {
                "complete" => Ok(Operation::Complete(authorization)),
                "cancel" => Ok(Operation::Cancel(authorization)),
                _ => Err(AuthHttpError::BadRequest),
            }
        }
    }
}
pub(crate) fn headers(headers: &HeaderMap, post: bool) -> Result<(), AuthHttpError> {
    // GET preserves actual content-read Cookie plus session-bound CSRF policy.
    require_owner_read_headers(headers)?;
    if headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return Err(AuthHttpError::BadRequest);
    }
    for name in [
        "cookie",
        "x-zrotext-csrf",
        "origin",
        "content-type",
        "content-length",
    ] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(AuthHttpError::BadRequest);
        }
    }
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthHttpError::BadRequest)?;
    for name in [
        crate::http_auth::SESSION_COOKIE,
        crate::http_auth::CSRF_COOKIE,
    ] {
        if cookie
            .split(';')
            .filter_map(|p| p.trim().split_once('='))
            .filter(|(key, _)| *key == name)
            .count()
            != 1
        {
            return Err(AuthHttpError::BadRequest);
        }
    }
    if post {
        if headers.get(header::CONTENT_TYPE).map(HeaderValue::as_bytes)
            != Some(b"application/json".as_slice())
        {
            return Err(AuthHttpError::BadRequest);
        }
        if !headers.contains_key(header::ORIGIN) {
            return Err(AuthHttpError::Forbidden);
        }
    }
    if let Some(v) = headers.get(header::CONTENT_LENGTH) {
        let text = v.to_str().map_err(|_| AuthHttpError::BadRequest)?;
        let n: usize = text.parse().map_err(|_| AuthHttpError::BadRequest)?;
        if text != n.to_string() || n > model::MAX_BODY || (!post && n != 0) {
            return Err(AuthHttpError::BadRequest);
        }
    }
    Ok(())
}
async fn call(State(state): State<Arc<OwnerContactIssuanceState>>, request: Request) -> Response {
    let deadline = Instant::now() + Duration::from_secs(10);
    match timeout_at(deadline, execute(&state, request, deadline)).await {
        Ok(Ok(r)) if Instant::now() < deadline => r,
        Ok(Err(e)) => e.into_response(),
        _ => AuthHttpError::Unavailable.into_response(),
    }
}
async fn execute(
    state: &OwnerContactIssuanceState,
    request: Request,
    deadline: Instant,
) -> Result<Response, AuthHttpError> {
    if !crate::sealed_root_enrollment::canonical_origin(&state.canonical_origin) {
        return Err(AuthHttpError::Unavailable);
    }
    let (parts, body) = request.into_parts();
    let post = parts.method == Method::POST;
    let op = operation(&parts.method, parts.uri.path(), parts.uri.query())?;
    headers(&parts.headers, post)?;
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    // Coarse session activity update finishes before any issuer transaction.
    let owner = if post {
        require_owner(
            &client,
            &state.auth_hasher,
            &state.canonical_origin,
            &parts.headers,
            true,
        )
        .await?
    } else {
        require_owner_read(&client, &state.auth_hasher, &parts.headers).await?
    };
    let _account_slot = AccountSlot::try_acquire(owner.tenant.account_id())
        .ok_or(AuthHttpError::TooManyRequests)?;
    let raw = timeout(
        Duration::from_secs(1),
        to_bytes(body, if post { model::MAX_BODY } else { 0 }),
    )
    .await
    .map_err(|_| AuthHttpError::BadRequest)?
    .map_err(|_| AuthHttpError::BadRequest)?;
    let result = match op {
        Operation::Create => {
            lifecycle::create(
                &mut client,
                &state.auth_hasher,
                &owner,
                &state.canonical_origin,
                model::parse(&raw).map_err(error)?,
            )
            .await
        }
        Operation::Lookup => {
            lifecycle::lookup(
                &mut client,
                &owner,
                &state.canonical_origin,
                model::parse(&raw).map_err(error)?,
            )
            .await
        }
        Operation::Complete(id) => {
            lifecycle::complete(
                &mut client,
                &state.auth_hasher,
                &state.mfa_cipher,
                &owner,
                &state.canonical_origin,
                id,
                model::parse(&raw).map_err(error)?,
            )
            .await
        }
        Operation::Cancel(id) => {
            lifecycle::cancel(&mut client, &owner, id, model::parse(&raw).map_err(error)?).await
        }
        Operation::Withdraw => {
            lifecycle::withdraw(&mut client, &owner, model::parse(&raw).map_err(error)?).await
        }
        Operation::Status(id, g) => lifecycle::status(&mut client, &owner, id, g).await,
    }
    .map_err(error)?;
    let bytes = model::encode(&result).map_err(error)?;
    if Instant::now() >= deadline {
        return Err(AuthHttpError::Unavailable);
    }
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

#[cfg(test)]
mod tests;
