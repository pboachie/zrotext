// SPDX-License-Identifier: AGPL-3.0-only
//! Owner routes for SMS line activation. Dormant unless
//! `SMS_LINE_ACTIVATION_ENABLED=true`. The owner's SMS approval private key
//! never reaches the server; the browser signs `owner_statement_b64`.

use super::{
    AuthHttpError, AuthHttpState, CSRF_COOKIE, CSRF_HEADER, connect, cookie, map_auth,
    require_owner,
};
use crate::{
    auth::abuse_limits::{self, Limit},
    sealed_inbound::line_activation::exchange::{self, ExchangeError},
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
pub(super) struct OpenBody {
    device_id: Uuid,
}

#[derive(Serialize)]
pub(super) struct OpenResponse {
    challenge_id: Uuid,
    generation: i64,
    expires_at_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApproveBody {
    owner_signature_der_b64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListQuery {
    #[serde(default)]
    before: Option<Uuid>,
}

#[derive(Serialize)]
pub(super) struct LineSummary {
    line_id: Uuid,
    state: String,
    generation: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<String>,
    /// The bound phone was revoked; the line needs activating on another phone.
    #[serde(skip_serializing_if = "Option::is_none")]
    device_revoked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved_at_ms: Option<i64>,
    created_at_ms: i64,
}

#[derive(Serialize)]
pub(super) struct LinePage {
    lines: Vec<LineSummary>,
    next_cursor: Option<Uuid>,
}

const LINE_PAGE: i64 = 50;

#[derive(Serialize)]
pub(super) struct ViewResponse {
    status: &'static str,
    device_id: Uuid,
    generation: i64,
    expires_at_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    android_api_level: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_subscription_id: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_statement_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_signature_der_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_statement_b64: Option<String>,
}

fn map_exchange(error: ExchangeError) -> AuthHttpError {
    match error {
        ExchangeError::InvalidInput => AuthHttpError::BadRequest,
        ExchangeError::NotFound => AuthHttpError::NotFound,
        ExchangeError::Refused => AuthHttpError::Forbidden,
        ExchangeError::Database(_) => AuthHttpError::Unavailable,
    }
}

fn require_enabled(state: &AuthHttpState) -> Result<(), AuthHttpError> {
    if state.sms_line_activation_enabled {
        Ok(())
    } else {
        Err(AuthHttpError::NotFound)
    }
}

fn require_ids(ids: &[Uuid]) -> Result<(), AuthHttpError> {
    if ids.iter().any(Uuid::is_nil) {
        Err(AuthHttpError::BadRequest)
    } else {
        Ok(())
    }
}

async fn charge(
    client: &tokio_postgres::Client,
    state: &AuthHttpState,
    owner: &crate::auth::SessionPrincipal,
) -> Result<(), AuthHttpError> {
    let subject = owner.user_id.to_string();
    if abuse_limits::consume(
        client,
        &state.hasher,
        Limit::SmsLineActivation,
        Some(&subject),
    )
    .await
    .map_err(|_| AuthHttpError::Unavailable)?
    {
        Ok(())
    } else {
        Err(AuthHttpError::TooManyRequests)
    }
}

/// Opens a challenge for the line and an enrolled device. The device's live
/// stream receives it within a few seconds.
pub(super) async fn open(
    State(state): State<Arc<AuthHttpState>>,
    Path(line_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<OpenBody>,
) -> Result<(StatusCode, Json<OpenResponse>), AuthHttpError> {
    require_enabled(&state)?;
    require_ids(&[line_id, body.device_id])?;
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    charge(&client, &state, &owner).await?;
    let (challenge, expires_at_ms) = exchange::open(&mut client, &owner, line_id, body.device_id)
        .await
        .map_err(map_exchange)?;
    Ok((
        StatusCode::CREATED,
        Json(OpenResponse {
            challenge_id: challenge.id,
            generation: challenge.generation,
            expires_at_ms,
        }),
    ))
}

/// The signed-in owner's phone lines, newest first, with the phone and scope
/// of each line's active binding. Account-scoped and paginated.
pub(super) async fn list(
    State(state): State<Arc<AuthHttpState>>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Result<Json<LinePage>, AuthHttpError> {
    require_enabled(&state)?;
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let csrf_cookie = cookie(&headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    owner
        .require_csrf_token(&state.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let account_id = owner.tenant.account_id();
    let before = match query.before {
        Some(before) => Some(
            client
                .query_opt(
                    "SELECT created_at,id FROM phone_lines WHERE account_id=$1 AND id=$2",
                    &[&account_id, &before],
                )
                .await
                .map_err(|_| AuthHttpError::Unavailable)?
                .ok_or(AuthHttpError::NotFound)?,
        ),
        None => None,
    };
    let before_at: Option<std::time::SystemTime> = before.as_ref().map(|row| row.get(0));
    let before_id: Option<Uuid> = before.as_ref().map(|row| row.get(1));
    let rows = client
        .query(
            "SELECT l.id,l.state,l.current_binding_generation,b.purpose,b.device_id,d.display_name, \
               (extract(epoch FROM l.approved_at)*1000)::bigint, \
               (extract(epoch FROM l.created_at)*1000)::bigint, \
               CASE WHEN d.id IS NULL THEN NULL ELSE d.revoked_at IS NOT NULL END \
             FROM phone_lines l \
             LEFT JOIN device_line_bindings b ON (b.account_id,b.line_id,b.generation) \
               =(l.account_id,l.id,l.current_binding_generation) AND b.state='active' \
             LEFT JOIN devices d ON (d.account_id,d.id)=(b.account_id,b.device_id) \
             WHERE l.account_id=$1 \
               AND ($2::timestamptz IS NULL OR (l.created_at,l.id)<($2,$3::uuid)) \
             ORDER BY l.created_at DESC,l.id DESC LIMIT $4",
            &[&account_id, &before_at, &before_id, &(LINE_PAGE + 1)],
        )
        .await
        .map_err(|_| AuthHttpError::Unavailable)?;
    let has_more = rows.len() as i64 > LINE_PAGE;
    let lines: Vec<LineSummary> = rows
        .into_iter()
        .take(LINE_PAGE as usize)
        .map(|row| LineSummary {
            line_id: row.get(0),
            state: row.get(1),
            generation: row.get(2),
            purpose: row.get(3),
            device_id: row.get(4),
            device_name: row.get(5),
            device_revoked: row.get(8),
            approved_at_ms: row.get(6),
            created_at_ms: row.get(7),
        })
        .collect();
    let next_cursor = if has_more {
        lines.last().map(|line| line.line_id)
    } else {
        None
    };
    Ok(Json(LinePage { lines, next_cursor }))
}

pub(super) async fn view(
    State(state): State<Arc<AuthHttpState>>,
    Path((line_id, challenge_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<ViewResponse>, AuthHttpError> {
    require_enabled(&state)?;
    require_ids(&[line_id, challenge_id])?;
    let client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await?;
    let csrf_cookie = cookie(&headers, CSRF_COOKIE).ok_or(AuthHttpError::Forbidden)?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthHttpError::Forbidden)?;
    owner
        .require_csrf_token(&state.hasher, csrf_cookie, csrf_header)
        .map_err(map_auth)?;
    let view = exchange::view(&client, &owner, line_id, challenge_id)
        .await
        .map_err(map_exchange)?;
    Ok(Json(ViewResponse {
        status: view.status.label(),
        device_id: view.device_id,
        generation: view.generation,
        expires_at_ms: view.expires_at_ms,
        android_api_level: view.observation.map(|value| value.android_api_level),
        selected_subscription_id: view.observation.map(|value| value.selected_subscription_id),
        device_statement_b64: view.device_statement.map(|bytes| STANDARD.encode(bytes)),
        device_signature_der_b64: view
            .device_signature_der
            .map(|bytes| STANDARD.encode(bytes)),
        owner_statement_b64: view.owner_statement.map(|bytes| STANDARD.encode(bytes)),
    }))
}

/// Activates the line with the owner's P-256 ECDSA/SHA-256 canonical DER
/// signature over `owner_statement_b64`.
pub(super) async fn approve(
    State(state): State<Arc<AuthHttpState>>,
    Path((line_id, challenge_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<ApproveBody>,
) -> Result<StatusCode, AuthHttpError> {
    require_enabled(&state)?;
    require_ids(&[line_id, challenge_id])?;
    if body.owner_signature_der_b64.len() > 108 {
        return Err(AuthHttpError::BadRequest);
    }
    let signature = STANDARD
        .decode(&body.owner_signature_der_b64)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if !(8..=80).contains(&signature.len())
        || STANDARD.encode(&signature) != body.owner_signature_der_b64
    {
        return Err(AuthHttpError::BadRequest);
    }
    let mut client = connect(&state.database_url).await?;
    let owner = require_owner(
        &client,
        &state.hasher,
        &state.canonical_origin,
        &headers,
        true,
    )
    .await?;
    charge(&client, &state, &owner).await?;
    exchange::approve(&mut client, &owner, line_id, challenge_id, &signature)
        .await
        .map_err(map_exchange)?;
    Ok(StatusCode::NO_CONTENT)
}
