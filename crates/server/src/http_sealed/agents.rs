// SPDX-License-Identifier: AGPL-3.0-only
//! Dedicated scoped agent admission. Ordinary API routes reject these keys.

use super::{
    AcceptedBody, MAX_ENVELOPE_BYTES, MIN_ENVELOPE_BYTES, SealedHttpError, SealedHttpState, bearer,
    connect, map_admit, map_auth, reject_idempotency_key, sealed_content_type,
};
use crate::{
    agent_authority::{Operation, store},
    auth::agent_grants,
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::outbound,
    sealed_outbound::{self, WriterContext},
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn routes() -> Router<Arc<SealedHttpState>> {
    Router::new()
        .route("/agent/actions/{action_id}/messages", post(submit))
        .route("/agent/messages/{message_id}", get(metadata))
        .route("/agent/messages/{message_id}/content", get(content))
        .route("/agent/actions/{action_id}/draft", post(draft))
}

struct AgentSendAuth {
    principal: agent_grants::AgentPrincipal,
    _slot: crate::http_auth::preauth::AccountSlot,
}
impl axum::extract::FromRequestParts<Arc<SealedHttpState>> for AgentSendAuth {
    type Rejection = SealedHttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<SealedHttpState>,
    ) -> Result<Self, Self::Rejection> {
        if !state.enabled || !state.agent_enabled {
            return Err(SealedHttpError::NotFound);
        }
        sealed_content_type(&parts.headers)?;
        reject_idempotency_key(&parts.headers)?;
        let token = bearer(&parts.headers)?;
        let client = connect(&state.database_url).await?;
        let principal = agent_grants::authenticate_agent(&client, &state.hasher, token)
            .await
            .map_err(map_auth)?;
        principal.require(Operation::Send).map_err(map_auth)?;
        let slot = crate::http_auth::preauth::AccountSlot::try_acquire(principal.account)
            .ok_or(SealedHttpError::RateLimited)?;
        Ok(Self {
            principal,
            _slot: slot,
        })
    }
}

async fn submit(
    State(state): State<Arc<SealedHttpState>>,
    Path(action): Path<String>,
    headers: HeaderMap,
    auth: AgentSendAuth,
    body: axum::body::Bytes,
) -> Result<Response, SealedHttpError> {
    reject_idempotency_key(&headers)?;
    let action_id = Uuid::parse_str(&action).map_err(|_| SealedHttpError::BadRequest)?;
    if action_id.is_nil()
        || action_id.to_string() != action
        || !(MIN_ENVELOPE_BYTES..=MAX_ENVELOPE_BYTES).contains(&body.len())
    {
        return Err(SealedHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let outcome = sealed_outbound::admit_agent_candidate02(
        &mut client,
        &auth.principal,
        &state.hasher,
        WriterContext {
            site_id: &state.site_id,
            deployment_epoch: state.deployment_epoch,
            billing_enabled: state.billing_enabled,
        },
        &body,
        action_id,
    )
    .await
    .map_err(map_admit)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedBody {
            message_id: outcome.message_id,
            created: outcome.created,
        }),
    )
        .into_response())
}

struct AgentOperationAuth<const OP: u8> {
    principal: agent_grants::AgentPrincipal,
    _slot: crate::http_auth::preauth::AccountSlot,
}
impl<const OP: u8> axum::extract::FromRequestParts<Arc<SealedHttpState>>
    for AgentOperationAuth<OP>
{
    type Rejection = SealedHttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<SealedHttpState>,
    ) -> Result<Self, Self::Rejection> {
        if !state.enabled || !state.agent_enabled {
            return Err(SealedHttpError::NotFound);
        }
        if OP == 2 {
            sealed_content_type(&parts.headers)?;
        }
        reject_idempotency_key(&parts.headers)?;
        let token = bearer(&parts.headers)?;
        let client = connect(&state.database_url).await?;
        let principal = agent_grants::authenticate_agent(&client, &state.hasher, token)
            .await
            .map_err(map_auth)?;
        principal
            .require(match OP {
                0 => Operation::Metadata,
                1 => Operation::ReadContent,
                2 => Operation::Draft,
                _ => return Err(SealedHttpError::Forbidden),
            })
            .map_err(map_auth)?;
        let slot = crate::http_auth::preauth::AccountSlot::try_acquire(principal.account)
            .ok_or(SealedHttpError::RateLimited)?;
        Ok(Self {
            principal,
            _slot: slot,
        })
    }
}
fn map_store(error: store::StoreError) -> SealedHttpError {
    match error {
        store::StoreError::Denied => SealedHttpError::Forbidden,
        store::StoreError::Database(_) => SealedHttpError::Unavailable,
    }
}
fn canonical_id(text: &str) -> Result<Uuid, SealedHttpError> {
    let id = Uuid::parse_str(text).map_err(|_| SealedHttpError::BadRequest)?;
    if id.is_nil() || id.to_string() != text {
        return Err(SealedHttpError::BadRequest);
    }
    Ok(id)
}
fn not_before(headers: &HeaderMap) -> Result<i64, SealedHttpError> {
    let mut values = headers.get_all("x-zrotext-not-before-ms").iter();
    let text = values
        .next()
        .ok_or(SealedHttpError::BadRequest)?
        .to_str()
        .map_err(|_| SealedHttpError::BadRequest)?;
    if values.next().is_some()
        || text.is_empty()
        || text.len() > 19
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SealedHttpError::BadRequest);
    }
    let value = text
        .parse::<i64>()
        .map_err(|_| SealedHttpError::BadRequest)?;
    if value <= 0 {
        return Err(SealedHttpError::BadRequest);
    }
    Ok(value)
}

#[derive(Serialize)]
struct DraftView {
    action_id: Uuid,
    message_id: Uuid,
    unsigned_digest_b64: String,
    action_digest_b64: String,
    approved: bool,
    queued: bool,
}
async fn draft(
    State(state): State<Arc<SealedHttpState>>,
    Path(action): Path<String>,
    headers: HeaderMap,
    auth: AgentOperationAuth<2>,
    body: axum::body::Bytes,
) -> Result<Json<DraftView>, SealedHttpError> {
    let action_id = canonical_id(&action)?;
    let timing = not_before(&headers)?;
    if !(MIN_ENVELOPE_BYTES..=MAX_ENVELOPE_BYTES).contains(&body.len()) {
        return Err(SealedHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let action = store::validate_agent_draft(
        &tx,
        &state.hasher,
        &auth.principal,
        action_id,
        &body,
        timing,
    )
    .await
    .map_err(map_store)?;
    let view = DraftView {
        action_id: action.action,
        message_id: action.message,
        unsigned_digest_b64: STANDARD.encode(action.unsigned_envelope),
        action_digest_b64: STANDARD.encode(action.digest()),
        approved: false,
        queued: false,
    };
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(view))
}

async fn scope<'tx, 'connection>(
    tx: &'tx tokio_postgres::Transaction<'connection>,
    principal: &agent_grants::AgentPrincipal,
    operation: Operation,
) -> Result<
    (
        outbound::CurrentAuthority<'tx, 'connection>,
        store::LockedGrant,
    ),
    SealedHttpError,
> {
    let mut authority = outbound::lock_current(tx, principal.account)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
        &[&principal.account],
    )
    .await
    .map_err(|_| SealedHttpError::Unavailable)?
    .ok_or(SealedHttpError::Forbidden)?;
    let grant = store::load(
        tx,
        principal.account,
        principal.grant_id,
        principal.key_id,
        operation,
    )
    .await
    .map_err(map_store)?;
    authority
        .authorize_agent_reader(&grant.connector_key, 0)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    Ok((authority, grant))
}
#[derive(Serialize)]
struct MessageView {
    message_id: Uuid,
    device_id: Uuid,
    state: String,
    state_version: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
}
async fn metadata(
    State(state): State<Arc<SealedHttpState>>,
    Path(message): Path<String>,
    auth: AgentOperationAuth<0>,
) -> Result<Json<MessageView>, SealedHttpError> {
    let message = canonical_id(&message)?;
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let (mut authority, grant) = scope(&tx, &auth.principal, Operation::Metadata).await?;
    let row=tx.query_opt(
        "SELECT m.id,m.device_id,m.state,m.state_version,(extract(epoch FROM m.created_at)*1000)::bigint,(extract(epoch FROM m.updated_at)*1000)::bigint,(extract(epoch FROM m.expires_at)*1000)::bigint FROM messages m JOIN agent_authority_actions a ON a.account_id=m.account_id AND a.message_id=m.id AND a.grant_id=m.agent_grant_id JOIN agent_authority_approvals p ON p.account_id=a.account_id AND p.action_id=a.action_id AND p.grant_id=a.grant_id AND p.action_digest=a.action_digest AND p.message_id=m.id AND p.device_id=m.device_id AND p.line_id=m.sealed_line_id AND p.binding_generation=m.sealed_binding_generation AND p.unsigned_digest=m.request_digest WHERE m.account_id=$1 AND m.id=$2 AND m.device_id=$3 AND m.sealed_line_id=$4 AND m.sealed_binding_generation=$5 AND p.recipient_digest=$6 AND m.transport_mode='sealed_candidate02' FOR SHARE OF m,a,p",
        &[&auth.principal.account,&message,&auth.principal.device_id,&grant.policy.line,&grant.policy.binding_generation,&grant.policy.recipient.as_slice()],
    ).await.map_err(|_|SealedHttpError::Unavailable)?.ok_or(SealedHttpError::NotFound)?;
    authority
        .authorize_agent_reader(&grant.connector_key, 0)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    store::load(
        &tx,
        auth.principal.account,
        auth.principal.grant_id,
        auth.principal.key_id,
        Operation::Metadata,
    )
    .await
    .map_err(map_store)?;
    let view = MessageView {
        message_id: row.get(0),
        device_id: row.get(1),
        state: row.get(2),
        state_version: row.get(3),
        created_at_ms: row.get(4),
        updated_at_ms: row.get(5),
        expires_at_ms: row.get(6),
    };
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(view))
}

async fn content(
    State(state): State<Arc<SealedHttpState>>,
    Path(message): Path<String>,
    auth: AgentOperationAuth<1>,
) -> Result<Response, SealedHttpError> {
    let message = canonical_id(&message)?;
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let (mut authority, grant) = scope(&tx, &auth.principal, Operation::ReadContent).await?;
    let row=tx.query_opt(
        "SELECT m.transport_payload,m.request_digest FROM messages m JOIN agent_authority_actions a ON a.account_id=m.account_id AND a.message_id=m.id AND a.grant_id=m.agent_grant_id JOIN agent_authority_approvals p ON p.account_id=a.account_id AND p.action_id=a.action_id AND p.grant_id=a.grant_id AND p.action_digest=a.action_digest AND p.message_id=m.id AND p.device_id=m.device_id AND p.line_id=m.sealed_line_id AND p.binding_generation=m.sealed_binding_generation AND p.unsigned_digest=m.request_digest WHERE m.account_id=$1 AND m.id=$2 AND m.device_id=$3 AND m.sealed_line_id=$4 AND m.sealed_binding_generation=$5 AND p.recipient_digest=$6 AND m.transport_mode='sealed_candidate02' AND m.transport_payload IS NOT NULL FOR SHARE OF m,a,p",
        &[&auth.principal.account,&message,&auth.principal.device_id,&grant.policy.line,&grant.policy.binding_generation,&grant.policy.recipient.as_slice()],
    ).await.map_err(|_|SealedHttpError::Unavailable)?.ok_or(SealedHttpError::NotFound)?;
    let bytes: Vec<u8> = row.get(0);
    let reader = grant
        .policy
        .reader_identity
        .ok_or(SealedHttpError::Forbidden)?;
    let reader_row=tx.query_opt(
        "SELECT c.key_id FROM connector_registrations c JOIN connector_keys k ON k.account_id=c.account_id AND k.connector_id=c.connector_id AND k.key_id=c.key_id WHERE c.account_id=$1 AND c.connector_id=$2 AND c.state='active' AND c.manifest_generation=$3 AND c.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.retired_ms IS NULL AND k.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint AND k.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint FOR SHARE OF c,k",
        &[&auth.principal.account,&reader,&authority.generation()],
    ).await.map_err(|_|SealedHttpError::Unavailable)?.ok_or(SealedHttpError::Forbidden)?;
    let reader_key: [u8; 32] = reader_row
        .get::<_, Vec<u8>>(0)
        .try_into()
        .map_err(|_| SealedHttpError::Forbidden)?;
    tx.query_opt("SELECT grant_id FROM connector_grants WHERE account_id=$1 AND connector_id=$2 AND line_id=$3 AND kind='read' AND read_directions & 4=4 AND cardinality(conversation_restriction)=0 AND revoked_ms IS NULL AND expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY created_ms DESC,grant_id DESC LIMIT 1 FOR SHARE",&[&auth.principal.account,&reader,&grant.policy.line]).await.map_err(|_|SealedHttpError::Unavailable)?.ok_or(SealedHttpError::Forbidden)?;
    authority
        .authorize_agent_reader(&reader_key, 4)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    let claims = sealed_envelope::parse(&bytes, Profile::Draft02Candidate)
        .map_err(|_| SealedHttpError::Forbidden)?;
    if claims.kind != Kind::Outbound
        || claims.account_id != auth.principal.account.as_bytes()
        || claims.message_id != message.as_bytes()
        || claims.device_id != auth.principal.device_id.as_bytes()
        || claims.line_id != grant.policy.line.as_bytes()
        || claims.signer_key_id != grant.signer_key
        || !claims
            .wraps
            .iter()
            .any(|wrap| wrap.role == 3 && wrap.key_id == reader_key)
    {
        return Err(SealedHttpError::Forbidden);
    }
    let recipients = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap
                    .key_id
                    .try_into()
                    .map_err(|_| SealedHttpError::Forbidden)?,
            })
        })
        .collect::<Result<Vec<_>, SealedHttpError>>()?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Outbound,
        account_id: *auth.principal.account.as_bytes(),
        device_id: *auth.principal.device_id.as_bytes(),
        line_id: *grant.policy.line.as_bytes(),
        message_id: *message.as_bytes(),
        signer_key_id: grant.signer_key,
        peer: claims.peer,
        recipients: &recipients,
    };
    let context = authority
        .context(&wanted)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    let verified =
        sealed_envelope::verify(&bytes, &context).map_err(|_| SealedHttpError::Forbidden)?;
    let peer = std::str::from_utf8(claims.peer).map_err(|_| SealedHttpError::Forbidden)?;
    if row.get::<_, Vec<u8>>(1) != verified.unsigned_digest()
        || state
            .hasher
            .agent_recipient_digest(auth.principal.account, peer)
            != grant.policy.recipient
    {
        return Err(SealedHttpError::Forbidden);
    }
    store::load(
        &tx,
        auth.principal.account,
        auth.principal.grant_id,
        auth.principal.key_id,
        Operation::ReadContent,
    )
    .await
    .map_err(map_store)?;
    authority
        .authorize_agent_reader(&reader_key, 4)
        .await
        .map_err(|_| SealedHttpError::Forbidden)?;
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, super::SEALED_CONTENT_TYPE)],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    #[tokio::test]
    async fn dormant_agent_submission_does_not_authenticate_or_read_a_body() {
        let state = SealedHttpState::disabled(
            "unused".into(),
            Arc::new(crate::auth::TokenHasher::new(vec![41; 32]).unwrap()),
        );
        let response = super::super::router(state)
            .oneshot(
                Request::post(format!("/agent/actions/{}/messages", Uuid::new_v4()))
                    .body(Body::from("not an envelope"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[axum::http::header::CACHE_CONTROL],
            "no-store"
        );
    }
}

#[cfg(test)]
#[path = "agents/operation_tests.rs"]
mod operation_tests;
