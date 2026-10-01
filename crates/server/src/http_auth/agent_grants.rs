// SPDX-License-Identifier: AGPL-3.0-only
//! Default-off owner-confirmed authority; no approval from received content.

use super::{
    AuthHttpError, AuthHttpState, OwnerMutation, connect, map_auth, require_owner,
    require_session_cookie,
};
use crate::{
    api_json::ApiJson,
    auth::{
        abuse_limits::{self, Limit},
        agent_grants as grants,
    },
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateBody {
    current_password: String,
    code: Option<String>,
    grant: grants::GrantRequest,
}

#[derive(Serialize)]
pub(super) struct Created {
    grant_id: Uuid,
    key_id: Uuid,
    token: String,
    public_prefix: String,
    segment_limit: u8,
}

async fn budget(
    client: &tokio_postgres::Client,
    state: &AuthHttpState,
    account: Uuid,
    limit: Limit,
) -> Result<(), AuthHttpError> {
    if !abuse_limits::consume(client, &state.hasher, limit, Some(&account.to_string()))
        .await
        .map_err(|_| AuthHttpError::Unavailable)?
    {
        return Err(AuthHttpError::TooManyRequests);
    }
    Ok(())
}

pub(super) async fn create(
    State(state): State<Arc<AuthHttpState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<CreateBody>,
) -> Result<(StatusCode, Json<Created>), AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    budget(
        &client,
        &state,
        owner.tenant.account_id(),
        Limit::ApiKeyCreate,
    )
    .await?;
    let _permit = state.hash_permit().await?;
    let (grant_id, key) = grants::create(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        grants::OwnerProof {
            owner: &owner,
            password: &body.current_password,
            code: body.code.as_deref(),
        },
        body.grant,
    )
    .await
    .map_err(map_auth)?;
    Ok((
        StatusCode::CREATED,
        Json(Created {
            grant_id,
            key_id: key.id,
            token: key.token,
            public_prefix: key.public_prefix,
            segment_limit: 1,
        }),
    ))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    before: Option<Uuid>,
}

pub(super) async fn list(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<grants::GrantPage>, AuthHttpError> {
    require_session_cookie(&headers)?;
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    Ok(Json(
        grants::list(&client, &owner, query.before)
            .await
            .map_err(map_auth)?
            .ok_or(AuthHttpError::NotFound)?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProofBody {
    current_password: String,
    code: Option<String>,
}

async fn withdraw(
    state: &AuthHttpState,
    owner: &crate::auth::SessionPrincipal,
    grant: Uuid,
    body: ProofBody,
    takeover: bool,
) -> Result<StatusCode, AuthHttpError> {
    let mut client = connect(&state.database_url).await?;
    budget(
        &client,
        state,
        owner.tenant.account_id(),
        Limit::PasswordChange,
    )
    .await?;
    let _permit = state.hash_permit().await?;
    grants::revoke(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        grants::OwnerProof {
            owner,
            password: &body.current_password,
            code: body.code.as_deref(),
        },
        grant,
        takeover,
    )
    .await
    .map_err(map_auth)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn revoke(
    State(state): State<Arc<AuthHttpState>>,
    Path(grant): Path<Uuid>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<ProofBody>,
) -> Result<StatusCode, AuthHttpError> {
    withdraw(&state, &owner, grant, body, false).await
}
pub(super) async fn takeover(
    State(state): State<Arc<AuthHttpState>>,
    Path(grant): Path<Uuid>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<ProofBody>,
) -> Result<StatusCode, AuthHttpError> {
    withdraw(&state, &owner, grant, body, true).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalBody {
    current_password: String,
    code: Option<String>,
    action_id: Uuid,
    envelope_b64: String,
    not_before_ms: i64,
}
#[derive(Serialize)]
pub(super) struct ApprovalView {
    action_id: Uuid,
    action_digest_b64: String,
}

pub(super) async fn approve(
    State(state): State<Arc<AuthHttpState>>,
    Path(grant): Path<Uuid>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(body): ApiJson<ApprovalBody>,
) -> Result<Json<ApprovalView>, AuthHttpError> {
    if body.envelope_b64.len() > 34_213_usize.div_ceil(3) * 4 {
        return Err(AuthHttpError::BadRequest);
    }
    let bytes = STANDARD
        .decode(&body.envelope_b64)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if !(426..=34_213).contains(&bytes.len()) || STANDARD.encode(&bytes) != body.envelope_b64 {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    budget(
        &client,
        &state,
        owner.tenant.account_id(),
        Limit::PasswordChange,
    )
    .await?;
    let _permit = state.hash_permit().await?;
    let digest = grants::approve(
        &mut client,
        state.mfa_cipher.as_deref(),
        &state.hasher,
        grants::OwnerProof {
            owner: &owner,
            password: &body.current_password,
            code: body.code.as_deref(),
        },
        grants::ApprovalRequest {
            grant,
            action: body.action_id,
            envelope: &bytes,
            not_before_ms: body.not_before_ms,
        },
    )
    .await
    .map_err(map_auth)?;
    Ok(Json(ApprovalView {
        action_id: body.action_id,
        action_digest_b64: STANDARD.encode(digest),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn approval_body_never_accepts_caller_approval_or_plaintext() {
        let body = serde_json::json!({"current_password":"synthetic-passphrase","action_id":Uuid::from_u128(1),"envelope_b64":"AQ==","not_before_ms":1,"approved":true});
        assert!(serde_json::from_value::<ApprovalBody>(body).is_err());
        let body = serde_json::json!({"current_password":"synthetic-passphrase","action_id":Uuid::from_u128(1),"envelope_b64":"AQ==","not_before_ms":1,"plaintext":"synthetic"});
        assert!(serde_json::from_value::<ApprovalBody>(body).is_err());
    }

    #[tokio::test]
    async fn default_off_routes_never_reach_database_or_body() {
        let state = AuthHttpState::new(
            "unavailable-test-database".into(),
            Arc::new(crate::auth::TokenHasher::new(vec![3; 32]).unwrap()),
            "https://owner.example.test".into(),
            Arc::new(super::super::DisabledVerificationDispatcher),
        )
        .unwrap();
        let router = super::super::router(state);
        for route in [
            "/agent-grants",
            "/agent-grants/00000000-0000-0000-0000-000000000001/revoke",
            "/agent-grants/00000000-0000-0000-0000-000000000001/approvals",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .body(Body::from("untrusted body"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }
    #[tokio::test]
    async fn enabled_owner_mutations_reject_missing_session_before_parsing_body() {
        let state = AuthHttpState::new(
            "unavailable-test-database".into(),
            Arc::new(crate::auth::TokenHasher::new(vec![3; 32]).unwrap()),
            "https://owner.example.test".into(),
            Arc::new(super::super::DisabledVerificationDispatcher),
        )
        .unwrap()
        .with_agent_grants_enabled();
        let router = super::super::router(state);
        for route in [
            "/agent-grants",
            "/agent-grants/00000000-0000-0000-0000-000000000001/revoke",
            "/agent-grants/00000000-0000-0000-0000-000000000001/takeover",
            "/agent-grants/00000000-0000-0000-0000-000000000001/approvals",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .header("content-type", "application/json")
                        .body(Body::from("invalid JSON"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }
}

#[cfg(test)]
#[path = "agent_grants/db_tests.rs"]
mod db_tests;
