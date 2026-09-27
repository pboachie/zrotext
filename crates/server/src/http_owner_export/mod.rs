// SPDX-License-Identifier: AGPL-3.0-only
//! Owner data export: one takeout page with the account profile,
//! devices, messages and per-message events. Unlike the pilot timeline
//! this carries the recipient and transport payload, so responses are
//! always no-store and never cached. Full history pages through the
//! same `before` cursor semantics as the timeline.

use crate::{auth::TokenHasher, http_auth::require_owner};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::SystemTime};
#[cfg(test)]
use tokio_postgres::NoTls;
use tokio_postgres::Row;
use uuid::Uuid;

// One takeout page stays bounded; full-history exports walk the same
// before/next_cursor pagination as the pilot timeline.
const EXPORT_MESSAGE_LIMIT: usize = 500;

#[derive(Clone)]
pub struct OwnerExportState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

pub fn router(state: OwnerExportState) -> Router {
    Router::new()
        .route("/v1/owner/export", get(export_account))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportQuery {
    before: Option<Uuid>,
}

#[derive(Serialize)]
struct AccountView {
    account_id: Uuid,
    email: String,
    email_verified: bool,
    created_at_ms: i64,
}

#[derive(Serialize)]
struct DeviceView {
    device_id: Uuid,
    display_name: String,
    created_at_ms: i64,
    revoked_at_ms: Option<i64>,
}

#[derive(Serialize)]
struct MessageEventView {
    evidence_code: String,
    resulting_state: String,
    received_at_ms: i64,
    segment_index: Option<i32>,
    segment_count: Option<i32>,
}

// Content columns are nullable since migration 026: the retention worker
// scrubs the recipient and payload of old terminal messages while the
// message identity, state and events remain exportable.
#[derive(Serialize)]
struct MessageView {
    message_id: Uuid,
    device_id: Uuid,
    recipient_e164: Option<String>,
    transport_mode: String,
    transport_payload: Option<String>,
    payload_encoding: Option<PayloadEncoding>,
    content_scrubbed: bool,
    state: String,
    created_at_ms: i64,
    updated_at_ms: i64,
    expires_at_ms: i64,
    events: Vec<MessageEventView>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum PayloadEncoding {
    Utf8,
    Base64,
}

// Only the synthetic alpha transport carries text. A sealed envelope is a
// binary structure whose bytes may happen to decode as UTF-8, so it is
// always base64 to keep the representation independent of its content.
fn encode_payload(transport_mode: &str, payload: Vec<u8>) -> (String, PayloadEncoding) {
    if transport_mode == "synthetic_alpha" {
        match String::from_utf8(payload) {
            Ok(text) => return (text, PayloadEncoding::Utf8),
            Err(error) => return (STANDARD.encode(error.into_bytes()), PayloadEncoding::Base64),
        }
    }
    (STANDARD.encode(payload), PayloadEncoding::Base64)
}

fn message_view(row: &Row) -> Result<MessageView, tokio_postgres::Error> {
    let transport_mode: String = row.try_get(3)?;
    let recipient_e164: Option<String> = row.try_get(2)?;
    let payload: Option<Vec<u8>> = row.try_get(4)?;
    let content_scrubbed = recipient_e164.is_none() && payload.is_none();
    let (transport_payload, payload_encoding) = match payload {
        Some(bytes) => {
            let (text, encoding) = encode_payload(&transport_mode, bytes);
            (Some(text), Some(encoding))
        }
        None => (None, None),
    };
    Ok(MessageView {
        message_id: row.try_get(0)?,
        device_id: row.try_get(1)?,
        recipient_e164,
        transport_mode,
        transport_payload,
        payload_encoding,
        content_scrubbed,
        state: row.try_get(5)?,
        created_at_ms: row.try_get(6)?,
        updated_at_ms: row.try_get(7)?,
        expires_at_ms: row.try_get(8)?,
        events: Vec::new(),
    })
}

#[derive(Serialize)]
struct ExportView {
    generated_at_ms: i64,
    account: AccountView,
    devices: Vec<DeviceView>,
    messages: Vec<MessageView>,
    messages_truncated: bool,
    next_cursor: Option<Uuid>,
}

async fn export_account(
    State(state): State<Arc<OwnerExportState>>,
    Query(query): Query<ExportQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = crate::http_auth::require_session_cookie(&headers) {
        return error.into_response();
    }
    let Ok(client) = crate::runtime_db::connect(&state.database_url).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let principal = match require_owner(
        &client,
        &state.auth_hasher,
        &state.canonical_origin,
        &headers,
        false,
    )
    .await
    {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    let account_id = principal.tenant.account_id();
    let before_point: Option<(SystemTime, Uuid)> = if let Some(before) = query.before {
        match client
            .query_opt(
                "SELECT created_at FROM messages WHERE account_id=$1 AND id=$2",
                &[&account_id, &before],
            )
            .await
        {
            Ok(Some(row)) => Some((row.get(0), before)),
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    } else {
        None
    };
    let before_at = before_point.map(|point| point.0);
    let before_id = before_point.map(|point| point.1);
    let account = match client
        .query_opt(
            "SELECT a.id,u.email,(u.email_verified_at IS NOT NULL), \
             (extract(epoch FROM a.created_at)*1000)::bigint \
             FROM accounts a JOIN memberships m ON m.account_id=a.id \
             JOIN users u ON u.id=m.user_id WHERE a.id=$1 AND m.role='owner'",
            &[&account_id],
        )
        .await
    {
        Ok(Some(row)) => AccountView {
            account_id: row.get(0),
            email: row.get(1),
            email_verified: row.get(2),
            created_at_ms: row.get(3),
        },
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let device_rows = match client
        .query(
            "SELECT id,display_name,(extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM revoked_at)*1000)::bigint \
             FROM devices WHERE account_id=$1 ORDER BY created_at,id",
            &[&account_id],
        )
        .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|row| DeviceView {
                device_id: row.get(0),
                display_name: row.get(1),
                created_at_ms: row.get(2),
                revoked_at_ms: row.get(3),
            })
            .collect::<Vec<_>>(),
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let message_rows = match client
        .query(
            "SELECT id,device_id,recipient_e164,transport_mode, \
             transport_payload,state, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint, \
             (extract(epoch FROM expires_at)*1000)::bigint \
             FROM messages WHERE account_id=$1 AND \
             ($2::timestamptz IS NULL OR (created_at,id)<($2,$3::uuid)) \
             ORDER BY created_at DESC,id DESC LIMIT $4",
            &[
                &account_id,
                &before_at,
                &before_id,
                &(EXPORT_MESSAGE_LIMIT as i64 + 1),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let messages_truncated = message_rows.len() > EXPORT_MESSAGE_LIMIT;
    let mut messages = match message_rows
        .iter()
        .take(EXPORT_MESSAGE_LIMIT)
        .map(message_view)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(messages) => messages,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let ids: Vec<Uuid> = messages.iter().map(|message| message.message_id).collect();
    if !ids.is_empty() {
        let events = match client
            .query(
                "SELECT selected.id,e.evidence_code,e.resulting_state, \
                 (extract(epoch FROM e.received_at)*1000)::bigint, \
                 e.segment_index,e.segment_count \
                 FROM unnest($2::uuid[]) AS selected(id) \
                 JOIN message_events e \
                 ON e.account_id=$1 AND e.message_id=selected.id \
                 ORDER BY e.received_at,e.id",
                &[&account_id, &ids],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let positions: HashMap<Uuid, usize> = ids
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index))
            .collect();
        for row in events {
            let id: Uuid = row.get(0);
            let Some(&index) = positions.get(&id) else {
                continue;
            };
            messages[index].events.push(MessageEventView {
                evidence_code: row.get(1),
                resulting_state: row.get(2),
                received_at_ms: row.get(3),
                segment_index: row.get(4),
                segment_count: row.get(5),
            });
        }
    }
    let next_cursor = if messages_truncated {
        messages.last().map(|message| message.message_id)
    } else {
        None
    };
    Json(ExportView {
        generated_at_ms: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as i64)
            .unwrap_or_default(),
        account,
        devices: device_rows,
        messages,
        messages_truncated,
        next_cursor,
    })
    .into_response()
}

#[cfg(test)]
mod tests;
