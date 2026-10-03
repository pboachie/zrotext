// SPDX-License-Identifier: AGPL-3.0-only
//! Current owner password/MFA issuance; original access grants no effect permission.
use super::{AuthHttpError, AuthHttpState, OwnerMutation, connect, map_auth};
use crate::{
    api_json::ApiJson,
    auth::abuse_limits::{self, Limit},
    original_reply,
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Create {
    current_password: String,
    code: String,
    interval_id: Uuid,
    connector_id: Uuid,
    read_grant_id: Uuid,
    reader_key_id: String,
    expires_at_ms: i64,
}
#[derive(Serialize)]
pub(super) struct Created {
    grant_id: Uuid,
    token: String,
}
pub(super) async fn create(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<Create>,
) -> Result<(StatusCode, Json<Created>), AuthHttpError> {
    if input.current_password.is_empty()
        || input.current_password.len() > 1024
        || input.code.is_empty()
        || input.code.len() > 128
    {
        return Err(AuthHttpError::BadRequest);
    }
    let key = crate::http_owner_conversations::context::decisions::descriptor::decode_digest(
        &input.reader_key_id,
    )
    .map_err(|_| AuthHttpError::BadRequest)?;
    let cipher = state
        .mfa_cipher
        .as_deref()
        .ok_or(AuthHttpError::Unavailable)?;
    let mut client = connect(&state.database_url).await?;
    if !abuse_limits::consume(
        &client,
        &state.hasher,
        Limit::ApiKeyCreate,
        Some(&owner.tenant.account_id().to_string()),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    let _permit = state.hash_permit().await?;
    let password = Zeroizing::new(input.current_password);
    let code = Zeroizing::new(input.code);
    let request = original_reply::GrantRequest {
        interval_id: input.interval_id,
        connector_id: input.connector_id,
        read_grant_id: input.read_grant_id,
        reader_key_id: key,
        expires_at_ms: input.expires_at_ms,
    };
    let issued = original_reply::issue(
        &mut client,
        &owner,
        &state.hasher,
        cipher,
        &password,
        &code,
        &request,
    )
    .await
    .map_err(map_auth)?;
    Ok((
        StatusCode::CREATED,
        Json(Created {
            grant_id: issued.grant_id,
            token: issued.token.to_string(),
        }),
    ))
}
pub(super) async fn revoke(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    Path(grant): Path<Uuid>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    original_reply::withdraw(&mut client, &owner, grant)
        .await
        .map_err(map_auth)?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn request(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(input): ApiJson<original_reply::consumption::ActiveRequest>,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    original_reply::consumption::register_request(&mut client, &owner, &input)
        .await
        .map_err(|e| match e {
            crate::http_owner_conversations::ConversationError::Database(_) => {
                AuthHttpError::Unavailable
            }
            crate::http_owner_conversations::ConversationError::Invalid => {
                AuthHttpError::BadRequest
            }
            crate::http_owner_conversations::ConversationError::Conflict => AuthHttpError::Conflict,
            _ => AuthHttpError::Forbidden,
        })?;
    Ok(StatusCode::CREATED)
}
