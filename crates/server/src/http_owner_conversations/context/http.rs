// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted candidate router. Main does not enable this capability.
use super::{ConversationError, ExceptionInput, SessionPrincipal, lifecycle, wire};
use crate::{
    http_auth, http_auth::preauth::OwnerMutation, http_owner_conversations::OwnerConversationsState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/workflow/contexts", post(write))
        .route("/v1/owner/workflow/contexts/{id}", get(read))
        .route("/v1/owner/workflow/contexts/{id}/exceptions", get(queue))
        .route("/v1/owner/workflow/exceptions", post(exception))
        .route("/v1/owner/workflow/exceptions/{id}/resolve", post(resolve))
        .layer(DefaultBodyLimit::max(wire::MAX_ENVELOPE))
        .layer(middleware::from_fn(super::super::no_store))
        .with_state(Arc::new(state))
}
#[derive(Serialize)]
struct Revision {
    revision: i64,
}
#[derive(Serialize)]
struct Exception {
    exception_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadQuery {
    revision: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueQuery {
    before: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    request_id: Uuid,
    expected_revision: i64,
}

fn one<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ConversationError> {
    if headers.get_all(name).iter().count() != 1 {
        return Err(ConversationError::Invalid);
    }
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(ConversationError::Invalid)
}
pub(crate) async fn connection(
    state: &OwnerConversationsState,
) -> Result<crate::runtime_db::PooledClient, ConversationError> {
    crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)
}
pub(crate) async fn reader(
    state: &OwnerConversationsState,
    headers: &HeaderMap,
) -> Result<(crate::runtime_db::PooledClient, SessionPrincipal), ConversationError> {
    http_auth::require_owner_read_headers(headers).map_err(|_| ConversationError::Forbidden)?;
    let client = connection(state).await?;
    let owner = http_auth::require_owner_read(&client, &state.auth_hasher, headers)
        .await
        .map_err(|_| ConversationError::Forbidden)?;
    Ok((client, owner))
}
async fn write(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    headers: HeaderMap,
    bytes: Bytes,
) -> Result<Json<Revision>, ConversationError> {
    if one(&headers, "content-type")? != "application/vnd.zrotext.workflow-context.v1" {
        return Err(ConversationError::Invalid);
    }
    let request = one(&headers, "idempotency-key")?;
    if request.len() != 36 {
        return Err(ConversationError::Invalid);
    }
    let request = Uuid::parse_str(request).map_err(|_| ConversationError::Invalid)?;
    let expected = one(&headers, "x-zrotext-context-revision")?;
    if expected.is_empty()
        || expected.len() > 3
        || !expected.bytes().all(|v| v.is_ascii_digit())
        || (expected.len() > 1 && expected.starts_with('0'))
    {
        return Err(ConversationError::Invalid);
    }
    let expected = expected.parse().map_err(|_| ConversationError::Invalid)?;
    wire::parse(&bytes)?;
    let mut client = connection(&state).await?;
    let revision = super::write(&mut client, &owner, request, expected, &bytes).await?;
    Ok(Json(Revision { revision }))
}
async fn read(
    State(state): State<Arc<OwnerConversationsState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<ReadQuery>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Vec<u8>), ConversationError> {
    if query.revision.is_some_and(|v| !(1..=128).contains(&v)) {
        return Err(ConversationError::Invalid);
    }
    let (mut client, owner) = reader(&state, &headers).await?;
    Ok((
        [(
            header::CONTENT_TYPE,
            "application/vnd.zrotext.workflow-context.v1",
        )],
        super::read(&mut client, &owner, id, query.revision).await?,
    ))
}
async fn queue(
    State(state): State<Arc<OwnerConversationsState>>,
    Path(id): Path<Uuid>,
    Query(query): Query<QueueQuery>,
    headers: HeaderMap,
) -> Result<Json<lifecycle::ExceptionsPage>, ConversationError> {
    let (mut client, owner) = reader(&state, &headers).await?;
    Ok(Json(
        lifecycle::exceptions(&mut client, &owner, id, query.before).await?,
    ))
}
async fn exception(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    crate::api_json::ApiJson(input): crate::api_json::ApiJson<ExceptionInput>,
) -> Result<Json<Exception>, ConversationError> {
    let mut client = connection(&state).await?;
    Ok(Json(Exception {
        exception_id: super::exception(&mut client, &owner, input).await?,
    }))
}
async fn resolve(
    State(state): State<Arc<OwnerConversationsState>>,
    Path(id): Path<Uuid>,
    OwnerMutation(owner, _slot): OwnerMutation,
    crate::api_json::ApiJson(input): crate::api_json::ApiJson<Resolve>,
) -> Result<(StatusCode, Json<Revision>), ConversationError> {
    let mut client = connection(&state).await?;
    Ok((
        StatusCode::OK,
        Json(Revision {
            revision: super::resolve(
                &mut client,
                &owner,
                id,
                input.request_id,
                input.expected_revision,
            )
            .await?,
        }),
    ))
}
