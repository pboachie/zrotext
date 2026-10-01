// SPDX-License-Identifier: AGPL-3.0-only
//! Metadata-only lifecycle of the existing sealed queue. No envelope fetch,
//! decryption, dispatch, or second admission path is introduced here.
use super::{SealedHttpError, SealedHttpState, bearer, connect, map_auth};
use crate::auth::{self, Scope};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

const PAGE_SIZE: i64 = 20;

pub(super) struct LifecycleAuth {
    pub(super) principal: auth::ApiPrincipal,
    pub(super) _slot: crate::http_auth::preauth::AccountSlot,
}

impl axum::extract::FromRequestParts<Arc<SealedHttpState>> for LifecycleAuth {
    type Rejection = SealedHttpError;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<SealedHttpState>,
    ) -> Result<Self, Self::Rejection> {
        if !state.enabled {
            return Err(SealedHttpError::NotFound);
        }
        let token = bearer(&parts.headers)?;
        let client = connect(&state.database_url).await?;
        let principal = auth::authenticate_api_key(&client, &state.hasher, token)
            .await
            .map_err(map_auth)?;
        let _slot =
            crate::http_auth::preauth::AccountSlot::try_acquire(principal.tenant.account_id())
                .ok_or(SealedHttpError::RateLimited)?;
        Ok(Self { principal, _slot })
    }
}

/// Recheck authority under shared row locks until the read/cancel commits.
/// A key revoked after header authentication must not authorize a mutation.
pub(super) async fn authorize(
    tx: &Transaction<'_>,
    auth: &LifecycleAuth,
    scope: Scope,
) -> Result<Option<Uuid>, SealedHttpError> {
    let row = tx.query_opt(
        "SELECT k.bound_device_id FROM api_keys k JOIN memberships m ON (m.account_id,m.user_id)=(k.account_id,k.created_by_user_id) JOIN users u ON u.id=k.created_by_user_id JOIN accounts a ON a.id=k.account_id WHERE k.id=$1 AND k.account_id=$2 AND m.role='owner' AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp()) AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL AND $3=ANY(k.scopes) FOR SHARE OF k,m,u,a",
        &[&auth.principal.key_id, &auth.principal.tenant.account_id(), &scope.as_str()],
    ).await.map_err(|_| SealedHttpError::Unavailable)?.ok_or(SealedHttpError::Forbidden)?;
    Ok(row.get(0))
}

#[derive(Serialize)]
pub(super) struct MessageMetadata {
    message_id: Uuid,
    device_id: Uuid,
    state: String,
    state_version: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
}

fn metadata(row: &Row) -> MessageMetadata {
    MessageMetadata {
        message_id: row.get(0),
        device_id: row.get(1),
        state: row.get(2),
        state_version: row.get(3),
        created_at_ms: row.get(4),
        updated_at_ms: row.get(5),
        expires_at_ms: row.get(6),
    }
}
const SELECT_METADATA: &str = "SELECT id,device_id,state,state_version,(extract(epoch FROM created_at)*1000)::bigint,(extract(epoch FROM updated_at)*1000)::bigint,(extract(epoch FROM expires_at)*1000)::bigint FROM messages";

pub(super) async fn status(
    State(state): State<Arc<SealedHttpState>>,
    auth: LifecycleAuth,
    message: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
) -> Result<Json<MessageMetadata>, SealedHttpError> {
    let Path(message_id) = message.map_err(|_| SealedHttpError::BadRequest)?;
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let bound = authorize(&tx, &auth, Scope::MessagesRead).await?;
    let sql = format!(
        "{SELECT_METADATA} WHERE account_id=$1 AND id=$2 AND transport_mode='sealed_candidate02' AND ($3::uuid IS NULL OR device_id=$3)"
    );
    let row = tx
        .query_opt(
            &sql,
            &[&auth.principal.tenant.account_id(), &message_id, &bound],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?
        .ok_or(SealedHttpError::NotFound)?;
    let result = metadata(&row);
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    cursor: Option<Uuid>,
}
#[derive(Serialize)]
pub(super) struct MessagePage {
    messages: Vec<MessageMetadata>,
    next_cursor: Option<Uuid>,
}

pub(super) async fn list(
    State(state): State<Arc<SealedHttpState>>,
    auth: LifecycleAuth,
    query: Result<Query<ListQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<MessagePage>, SealedHttpError> {
    let Query(query) = query.map_err(|_| SealedHttpError::BadRequest)?;
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let bound = authorize(&tx, &auth, Scope::MessagesRead).await?;
    let account_id = auth.principal.tenant.account_id();
    let cursor_time: Option<std::time::SystemTime> = if let Some(cursor) = query.cursor {
        Some(tx.query_opt("SELECT created_at FROM messages WHERE account_id=$1 AND id=$2 AND transport_mode='sealed_candidate02' AND ($3::uuid IS NULL OR device_id=$3)", &[&account_id, &cursor, &bound]).await.map_err(|_| SealedHttpError::Unavailable)?.ok_or(SealedHttpError::NotFound)?.get(0))
    } else {
        None
    };
    let sql = format!(
        "{SELECT_METADATA} WHERE account_id=$1 AND transport_mode='sealed_candidate02' AND ($2::uuid IS NULL OR device_id=$2) AND ($3::timestamptz IS NULL OR (created_at,id)<($3,$4::uuid)) ORDER BY created_at DESC,id DESC LIMIT $5"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &account_id,
                &bound,
                &cursor_time,
                &query.cursor,
                &(PAGE_SIZE + 1),
            ],
        )
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let messages: Vec<_> = rows.iter().take(PAGE_SIZE as usize).map(metadata).collect();
    let next_cursor =
        (rows.len() > PAGE_SIZE as usize).then(|| messages.last().expect("full page").message_id);
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(MessagePage {
        messages,
        next_cursor,
    }))
}

pub(super) async fn cancel(
    State(state): State<Arc<SealedHttpState>>,
    auth: LifecycleAuth,
    message: Result<Path<Uuid>, axum::extract::rejection::PathRejection>,
    body: axum::body::Bytes,
) -> Result<Json<MessageMetadata>, SealedHttpError> {
    let Path(message_id) = message.map_err(|_| SealedHttpError::BadRequest)?;
    if !body.is_empty() {
        return Err(SealedHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let tx = client
        .transaction()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let bound = authorize(&tx, &auth, Scope::MessagesSend).await?;
    let account_id = auth.principal.tenant.account_id();
    let visible = tx.query_opt("SELECT id FROM messages WHERE account_id=$1 AND id=$2 AND transport_mode='sealed_candidate02' AND ($3::uuid IS NULL OR device_id=$3)", &[&account_id, &message_id, &bound]).await.map_err(|_| SealedHttpError::Unavailable)?;
    if visible.is_none() {
        return Err(SealedHttpError::NotFound);
    }
    let cancelled = zrotext_delivery_store::cancel_in_transaction(&tx, account_id, message_id)
        .await
        .map_err(|error| match error {
            zrotext_delivery_store::StoreError::InvalidTransition => {
                SealedHttpError::CancellationConflict
            }
            _ => SealedHttpError::Unavailable,
        })?;
    if !cancelled {
        // A visible message without its durable queue job is damaged state,
        // never proof that it has been cancelled.
        return Err(SealedHttpError::Unavailable);
    }
    let sql = format!("{SELECT_METADATA} WHERE account_id=$1 AND id=$2");
    let row = tx
        .query_one(&sql, &[&account_id, &message_id])
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    let result = metadata(&row);
    tx.commit()
        .await
        .map_err(|_| SealedHttpError::Unavailable)?;
    Ok(Json(result))
}
