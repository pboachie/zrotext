// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit default-off startup composition. No model owner authority.
use super::super::http::{WorkflowHttpState, bearer, refusal, response};
use super::*;
use crate::{http_auth::preauth::OwnerMutation, http_owner_conversations::OwnerConversationsState};
use axum::{
    Json, Router,
    body::{Bytes, to_bytes},
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{HeaderMap, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};

#[derive(Deserialize)]
#[serde(
    tag = "operation",
    content = "params",
    deny_unknown_fields,
    rename_all = "snake_case"
)]
pub enum RequestBody {
    Current {
        context_id: Uuid,
        policy_id: Uuid,
    },
    Admit(Invocation),
    AdmitOriginal(Box<OriginalAdmit>),
    CurrentOriginal {
        call_id: Uuid,
    },
    Produced {
        context_id: Uuid,
        call_id: Uuid,
        archive_ciphertext_digest: String,
    },
    Resume {
        call_id: Uuid,
    },
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
enum ResultBody {
    Policy(Policy),
    Call(Call),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Withdraw {
    policy_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportQuery {
    section: super::lifecycle::Section,
    before: Option<String>,
}

fn credential(headers: &HeaderMap, name: &str) -> Result<zeroize::Zeroizing<String>, AuthError> {
    let values = headers.get_all(name);
    if values.iter().count() != 1 {
        return Err(AuthError::Unauthorized);
    }
    let value = values
        .iter()
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;
    if !super::super::authentication::credential_shape(value) {
        return Err(AuthError::Unauthorized);
    }
    Ok(zeroize::Zeroizing::new(value.to_owned()))
}
fn original_credential(
    headers: &HeaderMap,
) -> Result<Option<zeroize::Zeroizing<String>>, AuthError> {
    let values = headers.get_all("x-zrotext-original-reader");
    if values.iter().count() == 0 {
        return Ok(None);
    }
    if values.iter().count() != 1 {
        return Err(AuthError::Unauthorized);
    }
    let value = values
        .iter()
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;
    if !crate::original_reply::credential_shape(value) {
        return Err(AuthError::Unauthorized);
    }
    Ok(Some(zeroize::Zeroizing::new(value.to_owned())))
}
async fn authenticate_original(
    db: &Client,
    hasher: &crate::auth::TokenHasher,
    token: Option<&str>,
) -> Result<Option<crate::original_reply::Principal>, AuthError> {
    match token {
        Some(token) => Ok(Some(
            crate::original_reply::authenticate(db, hasher, token)
                .await
                .map_err(error)?,
        )),
        None => Ok(None),
    }
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
pub fn router(state: WorkflowHttpState, enabled: bool) -> Router {
    router_with_original(state, enabled, false)
}
pub fn router_with_original(
    state: WorkflowHttpState,
    enabled: bool,
    original_enabled: bool,
) -> Router {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/workflow/routines", post(call))
        .layer(middleware::from_fn_with_state(
            original_enabled,
            original_gate,
        ))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}
/// Includes the existing owner-only encrypted context publication service.
/// This does not expose a publication path to either integration credential.
pub fn owner_router(state: OwnerConversationsState, enabled: bool) -> Router {
    owner_router_with_original(state, enabled, false)
}
pub fn owner_router_with_original(
    state: OwnerConversationsState,
    enabled: bool,
    original_enabled: bool,
) -> Router {
    if !enabled {
        return Router::new();
    }
    let publication = owner::context::http::router(state.clone());
    let openings = crate::workflow_runtime::openings::http::router(state.clone());
    Router::new()
        .route("/v1/owner/workflow/routines/policy", post(configure))
        .route("/v1/owner/workflow/routines/output", post(bind))
        .route("/v1/owner/workflow/routines/withdraw", post(withdraw))
        .route("/v1/owner/workflow/routines/export", get(export))
        .layer(middleware::from_fn_with_state(
            original_enabled,
            original_gate,
        ))
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
        .merge(publication)
        .merge(openings)
}
// Run before authentication extractors: disabling original ingress must also
// disable alternate original execution paths, while keeping ordinary routines.
async fn original_gate(State(enabled): State<bool>, request: Request, next: Next) -> Response {
    if enabled {
        return next.run(request).await;
    }
    if request.headers().contains_key("x-zrotext-original-reader") {
        return refusal(AuthError::Forbidden);
    }
    let policy = request.uri().path() == "/v1/owner/workflow/routines/policy";
    if policy || request.uri().path() == "/v1/workflow/routines" {
        let (parts, body) = request.into_parts();
        let Ok(bytes) = to_bytes(body, 8192).await else {
            return refusal(AuthError::InvalidInput);
        };
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            let original = if policy {
                value
                    .get("original_input")
                    .is_some_and(|binding| !binding.is_null())
            } else {
                matches!(
                    value.get("operation").and_then(|v| v.as_str()),
                    Some("admit_original" | "current_original")
                )
            };
            if original {
                return refusal(AuthError::Forbidden);
            }
        }
        return next
            .run(Request::from_parts(parts, axum::body::Body::from(bytes)))
            .await;
    }
    next.run(request).await
}

#[cfg(test)]
mod tests;
async fn export(
    State(state): State<Arc<OwnerConversationsState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Response {
    let result = async {
        let (mut db, owner) = owner::context::http::reader(&state, &headers)
            .await
            .map_err(error)?;
        super::lifecycle::export(&mut db, &owner, query.section, query.before)
            .await
            .map_err(error)
    }
    .await;
    match result {
        Ok(value) => response(value),
        Err(e) => refusal(e),
    }
}
async fn call(State(state): State<Arc<WorkflowHttpState>>, request: Request) -> Response {
    let result = tokio::time::timeout(Duration::from_secs(10), async move {
        if request.uri().query().is_some() {
            return Err(AuthError::InvalidInput);
        }
        let primary = zeroize::Zeroizing::new(bearer(request.headers())?.to_owned());
        if request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        {
            return Err(AuthError::InvalidInput);
        }
        let extra = if request.headers().contains_key("x-zrotext-routine-input") {
            Some(credential(request.headers(), "x-zrotext-routine-input")?)
        } else {
            None
        };
        let original_token = original_credential(request.headers())?;
        let body = to_bytes(request.into_body(), 8192)
            .await
            .map_err(|_| AuthError::InvalidInput)?;
        let body: RequestBody =
            serde_json::from_slice(&body).map_err(|_| AuthError::InvalidInput)?;
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        let principal = super::super::authenticate(&db, &state.hasher, &primary).await?;
        let original = authenticate_original(
            &db,
            &state.hasher,
            original_token.as_deref().map(|token| token.as_str()),
        )
        .await?;
        if !matches!(body, RequestBody::Resume { .. }) && extra.is_some() {
            return Err(AuthError::InvalidInput);
        }
        match body {
            RequestBody::Current {
                context_id,
                policy_id,
            } => Ok(ResultBody::Policy(
                super::current_with_original(
                    &mut db,
                    &principal,
                    original.as_ref(),
                    context_id,
                    policy_id,
                )
                .await?,
            )),
            RequestBody::Admit(v) => Ok(ResultBody::Call(
                super::admit(&mut db, &principal, v).await?,
            )),
            RequestBody::AdmitOriginal(v) => Ok(ResultBody::Call(
                super::admit_original(
                    &mut db,
                    &principal,
                    original.as_ref().ok_or(AuthError::Unauthorized)?,
                    *v,
                )
                .await?,
            )),
            RequestBody::CurrentOriginal { call_id } => Ok(ResultBody::Call(
                super::current_original(
                    &mut db,
                    &principal,
                    original.as_ref().ok_or(AuthError::Unauthorized)?,
                    call_id,
                )
                .await?,
            )),
            RequestBody::Produced {
                context_id,
                call_id,
                archive_ciphertext_digest,
            } => Ok(ResultBody::Call(
                super::produced_with_original(
                    &mut db,
                    &principal,
                    original.as_ref(),
                    context_id,
                    call_id,
                    archive_ciphertext_digest,
                )
                .await?,
            )),
            RequestBody::Resume { call_id } => {
                let input = super::super::authenticate(
                    &db,
                    &state.hasher,
                    &extra.ok_or(AuthError::Unauthorized)?,
                )
                .await?;
                Ok(ResultBody::Call(
                    super::output::resume_with_original(
                        &mut db,
                        &input,
                        &principal,
                        original.as_ref(),
                        call_id,
                    )
                    .await?,
                ))
            }
        }
    })
    .await;
    match result {
        Ok(Ok(value)) => response(value),
        Ok(Err(e)) => refusal(e),
        Err(_) => refusal(AuthError::Crypto),
    }
}
async fn configure(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let result = async {
        let token = credential(&headers, "x-zrotext-routine-input")?;
        if headers.contains_key("x-zrotext-routine-output") {
            return Err(AuthError::InvalidInput);
        }
        let policy =
            serde_json::from_slice::<Policy>(&bytes).map_err(|_| AuthError::InvalidInput)?;
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        let principal = super::super::authenticate(&db, &state.auth_hasher, &token).await?;
        let original_token = original_credential(&headers)?;
        let original = authenticate_original(
            &db,
            &state.auth_hasher,
            original_token.as_deref().map(|token| token.as_str()),
        )
        .await?;
        super::configure_with_original(&mut db, &owner, &principal, original.as_ref(), policy).await
    }
    .await;
    match result {
        Ok(()) => response(serde_json::json!({"configured":true})),
        Err(e) => refusal(e),
    }
}
async fn bind(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let result = async {
        let input = credential(&headers, "x-zrotext-routine-input")?;
        let output = credential(&headers, "x-zrotext-routine-output")?;
        let binding =
            serde_json::from_slice::<OutputBinding>(&bytes).map_err(|_| AuthError::InvalidInput)?;
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        let input = super::super::authenticate(&db, &state.auth_hasher, &input).await?;
        let output = super::super::authenticate(&db, &state.auth_hasher, &output).await?;
        let original_token = original_credential(&headers)?;
        let original = authenticate_original(
            &db,
            &state.auth_hasher,
            original_token.as_deref().map(|token| token.as_str()),
        )
        .await?;
        super::output::bind_with_original(
            &mut db,
            &owner,
            &input,
            &output,
            original.as_ref(),
            binding,
        )
        .await
    }
    .await;
    match result {
        Ok(value) => response(ResultBody::Call(value)),
        Err(e) => refusal(e),
    }
}
async fn withdraw(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Json(body): Json<Withdraw>,
) -> Response {
    let result = async {
        let mut db = crate::runtime_db::connect(&state.database_url)
            .await
            .map_err(|_| AuthError::Crypto)?;
        super::withdraw(&mut db, &owner, body.policy_id).await
    }
    .await;
    match result {
        Ok(()) => response(serde_json::json!({"withdrawn":true})),
        Err(e) => refusal(e),
    }
}
