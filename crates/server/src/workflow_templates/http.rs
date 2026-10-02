// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted candidate router. Main does not enable this capability.
use super::{ConversationError, SessionPrincipal, wire};
use crate::{
    http_auth, http_auth::preauth::OwnerMutation, http_owner_conversations::OwnerConversationsState,
};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, header},
    middleware,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

pub fn router(state: OwnerConversationsState, enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/v1/owner/workflow/templates", get(list).post(write))
        .route("/v1/owner/workflow/templates/{id}", get(read))
        .layer(DefaultBodyLimit::max(wire::MAX_ENVELOPE))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

#[derive(Serialize)]
struct Revision {
    revision: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadQuery {
    revision: Option<i64>,
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
    if one(&headers, "content-type")? != "application/vnd.zrotext.workflow-template.v1" {
        return Err(ConversationError::Invalid);
    }
    let request = one(&headers, "idempotency-key")?;
    if request.len() != 36 {
        return Err(ConversationError::Invalid);
    }
    let request = Uuid::parse_str(request).map_err(|_| ConversationError::Invalid)?;
    let expected = one(&headers, "x-zrotext-template-revision")?;
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
            "application/vnd.zrotext.workflow-template.v1",
        )],
        super::read(&mut client, &owner, id, query.revision).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    interval_id: Uuid,
    after: Option<Uuid>,
}
async fn list(
    State(state): State<Arc<OwnerConversationsState>>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Json<super::TemplatesPage>, ConversationError> {
    let (mut client, owner) = reader(&state, &headers).await?;
    Ok(Json(
        super::list(&mut client, &owner, query.interval_id, query.after).await?,
    ))
}

async fn no_store(
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut response = if request.headers().contains_key(header::AUTHORIZATION) {
        axum::http::StatusCode::UNAUTHORIZED.into_response()
    } else {
        next.run(request).await
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
