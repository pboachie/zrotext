// SPDX-License-Identifier: AGPL-3.0-only
//! Owner setup for narrow shared-service credentials; never a recipe credential input.
use super::{AuthHttpError, AuthHttpState, OwnerMutation, connect, map_auth};
use crate::{
    api_json::ApiJson,
    auth::abuse_limits::{self, Limit},
    http_owner_conversations::context::wire,
    workflow_runtime::{self, GrantRequest, Operation, Permissions, Purpose},
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBody {
    current_password: String,
    code: String,
    connector_id: Uuid,
    context_id: Uuid,
    contact_id: Uuid,
    purpose: Purpose,
    permissions: Vec<Operation>,
    signer_key_id: Option<String>,
    expires_at_ms: i64,
    content_envelope_base64url: Option<String>,
}

#[derive(Serialize)]
pub(super) struct Created {
    grant_id: Uuid,
    token: String,
}

impl CreateBody {
    fn grant(&self) -> Result<GrantRequest, AuthHttpError> {
        if self.permissions.len() > 7
            || self.current_password.is_empty()
            || self.current_password.len() > 1024
            || self.code.is_empty()
            || self.code.len() > 128
        {
            return Err(AuthHttpError::BadRequest);
        }
        let permissions =
            Permissions::new(&self.permissions).map_err(|_| AuthHttpError::BadRequest)?;
        let signer = self
            .signer_key_id
            .as_ref()
            .map(|value| {
                let bytes = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| AuthHttpError::BadRequest)?;
                if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != *value {
                    return Err(AuthHttpError::BadRequest);
                }
                bytes.try_into().map_err(|_| AuthHttpError::BadRequest)
            })
            .transpose()?;
        let content_envelope = self
            .content_envelope_base64url
            .as_ref()
            .map(|value| {
                if value.len() > wire::MAX_ENVELOPE.div_ceil(3) * 4 {
                    return Err(AuthHttpError::BadRequest);
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(value)
                    .map_err(|_| AuthHttpError::BadRequest)?;
                if bytes.len() > wire::MAX_ENVELOPE || URL_SAFE_NO_PAD.encode(&bytes) != *value {
                    return Err(AuthHttpError::BadRequest);
                }
                Ok(bytes)
            })
            .transpose()?;
        Ok(GrantRequest {
            connector: self.connector_id,
            context: self.context_id,
            contact: self.contact_id,
            purpose: self.purpose,
            permissions,
            signer,
            expires_ms: self.expires_at_ms,
            content_envelope,
        })
    }
}

pub(super) async fn create(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<CreateBody>,
) -> Result<(StatusCode, Json<Created>), AuthHttpError> {
    let grant = body.grant()?;
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
    let password = Zeroizing::new(body.current_password);
    let code = Zeroizing::new(body.code);
    let issued = workflow_runtime::issue_grant(
        &mut client,
        &owner,
        &state.hasher,
        cipher,
        &password,
        &code,
        &grant,
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
    if grant.is_nil() {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    workflow_runtime::revoke_grant(&mut client, &owner, grant)
        .await
        .map_err(map_auth)?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
