// SPDX-License-Identifier: AGPL-3.0-only
//! Default-off browser-session projection; never an agent or API-key grant.
use super::preauth::{MemberMutation, OwnerMutation};
use super::{AuthHttpError, AuthHttpState, connect, map_auth, require_member, require_owner_read};
use crate::{
    api_json::ApiJson,
    auth::{
        SessionPrincipal,
        abuse_limits::{self, Limit},
        collaboration as drafts,
    },
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn router() -> Router<Arc<AuthHttpState>> {
    Router::new()
        .route("/collaboration/grants", get(list_grants).post(grant))
        .route("/collaboration/grants/{grant_id}", delete(revoke))
        .route("/collaboration/drafts", get(list_own).post(create))
        .route(
            "/collaboration/drafts/{draft_id}",
            get(read_own).delete(delete_own),
        )
        .route("/collaboration/export", get(export))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantBody {
    user_id: Uuid,
    role: String,
    confirm_widening: bool,
    current_password: String,
    code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftBody {
    draft_id: Uuid,
    ciphertext_base64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportQuery {
    before: Option<Uuid>,
}

async fn charge(
    client: &tokio_postgres::Client,
    state: &AuthHttpState,
    principal: &SessionPrincipal,
    limit: Limit,
) -> Result<(), AuthHttpError> {
    let subject = format!("{}:{}", principal.tenant.account_id(), principal.user_id);
    if !abuse_limits::consume(client, &state.hasher, limit, Some(&subject))
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    Ok(())
}

async fn grant(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<GrantBody>,
) -> Result<Response, AuthHttpError> {
    if body.role != drafts::ROLE || !body.confirm_widening {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    charge(&client, &state, &owner, Limit::CollaborationGrant).await?;
    let _permit = state.hash_permit().await?;
    let value = drafts::grant_with_proof(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        &owner,
        drafts::GrantRequest {
            target: body.user_id,
            confirmed: body.confirm_widening,
            password: &body.current_password,
            code: body.code.as_deref(),
        },
    )
    .await
    .map_err(map_auth)?;
    Ok((StatusCode::CREATED, Json(value)).into_response())
}
async fn list_grants(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    super::require_owner_read_headers(&headers)?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner_read(&client, &state.hasher, &headers).await?;
    charge(&client, &state, &owner, Limit::CollaborationDraft).await?;
    Ok(Json(serde_json::json!({"grants":drafts::list_grants(&mut client,&owner).await.map_err(map_auth)?})).into_response())
}
async fn revoke(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(id): Path<Uuid>,
) -> Result<Response, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    charge(&client, &state, &owner, Limit::CollaborationGrant).await?;
    if !drafts::revoke(&mut client, &owner, id)
        .await
        .map_err(map_auth)?
    {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}
async fn create(
    State(state): State<Arc<AuthHttpState>>,
    MemberMutation(member, _slot): MemberMutation,
    ApiJson(body): ApiJson<DraftBody>,
) -> Result<Response, AuthHttpError> {
    let bytes = drafts::decode_ciphertext(&body.ciphertext_base64).map_err(map_auth)?;
    let mut client = connect(&state.database_url).await?;
    charge(&client, &state, &member, Limit::CollaborationDraft).await?;
    let (value, created) = drafts::create(&mut client, &member, body.draft_id, bytes)
        .await
        .map_err(map_auth)?;
    Ok((
        if created {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        },
        Json(value),
    )
        .into_response())
}
async fn read(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    id: Option<Uuid>,
) -> Result<Response, AuthHttpError> {
    super::require_owner_read_headers(&headers)?;
    let mut client = connect(&state.database_url).await?;
    let member = require_member(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    charge(&client, &state, &member, Limit::CollaborationDraft).await?;
    let values = drafts::own_drafts(&mut client, &member, id)
        .await
        .map_err(map_auth)?;
    if id.is_some() {
        return Ok(match values.into_iter().next() {
            Some(value) => Json(value).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        });
    }
    Ok(Json(serde_json::json!({"drafts":values})).into_response())
}
async fn list_own(
    state: State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Response, AuthHttpError> {
    read(state, headers, None).await
}
async fn read_own(
    state: State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Response, AuthHttpError> {
    read(state, headers, Some(id)).await
}
async fn delete_own(
    State(state): State<Arc<AuthHttpState>>,
    MemberMutation(member, _slot): MemberMutation,
    Path(id): Path<Uuid>,
) -> Result<Response, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    charge(&client, &state, &member, Limit::CollaborationDraft).await?;
    drafts::delete_own(&mut client, &member, id)
        .await
        .map_err(map_auth)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
async fn export(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> Result<Response, AuthHttpError> {
    super::require_owner_read_headers(&headers)?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner_read(&client, &state.hasher, &headers).await?;
    charge(&client, &state, &owner, Limit::CollaborationDraft).await?;
    Ok(Json(
        drafts::export(&mut client, &owner, query.before)
            .await
            .map_err(map_auth)?,
    )
    .into_response())
}

#[cfg(test)]
mod tests;
