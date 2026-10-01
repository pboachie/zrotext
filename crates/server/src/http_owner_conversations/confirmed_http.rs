// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-cookie confirmed queue adapter, mounted only by default-disabled composition.
use super::{
    ConversationError, OwnerConversationsState,
    send::{
        Confirmation,
        queue::{self, ConfirmedPacket, QueueError},
    },
};
use crate::{
    api_json::ApiJson,
    auth::TokenHasher,
    device_socket::DeviceSocketState,
    http_auth::preauth::{OwnerAuthState, OwnerMutation},
    inbound::InboundSession,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::{Arc, atomic::Ordering};
use zrotext_delivery_store::StoreError;

#[derive(Clone)]
struct AdapterState {
    owner: OwnerConversationsState,
    socket: DeviceSocketState,
    billing_enabled: bool,
}
impl OwnerAuthState for AdapterState {
    fn database_url(&self) -> &str {
        &self.owner.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.owner.auth_hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.owner.canonical_origin
    }
}

/// The socket placement and billing policy come only from trusted startup state.
/// Admission commits opaque content and proof; it does not execute on a phone.
pub fn router(
    owner: OwnerConversationsState,
    socket: DeviceSocketState,
    billing_enabled: bool,
) -> Router {
    Router::new()
        .route("/v1/owner/conversation/send", post(submit))
        .layer(DefaultBodyLimit::max(48 * 1024))
        .layer(middleware::from_fn(super::no_store))
        .with_state(Arc::new(AdapterState {
            owner,
            socket,
            billing_enabled,
        }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    envelope: String,
    confirmation: String,
    signature: String,
}
fn decode(value: &str, min: usize, max: usize) -> Result<Vec<u8>, ConversationError> {
    if value.len() > max.div_ceil(3) * 4 {
        return Err(ConversationError::Invalid);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| ConversationError::Invalid)?;
    if !(min..=max).contains(&bytes.len()) || STANDARD.encode(&bytes) != value {
        return Err(ConversationError::Invalid);
    }
    Ok(bytes)
}

async fn submit(
    State(state): State<Arc<AdapterState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(packet): ApiJson<Packet>,
) -> Response {
    match accept(&state, &owner, packet).await {
        Ok(outcome) => (StatusCode::ACCEPTED, Json(serde_json::json!({"message_id":outcome.message_id,"state":"queued","created":outcome.created}))).into_response(),
        Err(QueueError::Authorization(error)) => error.into_response(),
        Err(QueueError::Database(_)) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(QueueError::Store(error)) => match error {
            StoreError::InvalidInput => StatusCode::BAD_REQUEST,
            StoreError::IdempotencyConflict | StoreError::MessageIdConflict | StoreError::EventIdConflict | StoreError::InvalidTransition => StatusCode::CONFLICT,
            StoreError::Revoked | StoreError::StaleFence | StoreError::PaymentHold | StoreError::RecipientSuppressed => StatusCode::FORBIDDEN,
            StoreError::QueueFull | StoreError::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        }.into_response(),
    }
}

async fn accept(
    state: &AdapterState,
    owner: &crate::auth::SessionPrincipal,
    packet: Packet,
) -> Result<zrotext_delivery_store::AcceptOutcome, QueueError> {
    let socket = &state.socket;
    if state.owner.database_url != socket.database_url
        || socket.deployment_epoch <= 0
        || socket.draining.load(Ordering::Acquire)
    {
        return Err(ConversationError::Unavailable.into());
    }
    let envelope = decode(&packet.envelope, 1, 34_213)?;
    let confirmation = decode(&packet.confirmation, 297, 310)?;
    let signature = decode(&packet.signature, 64, 64)?;
    // Decode supplies only a selection ID, never an authenticated phone tuple.
    let device = Confirmation::decode(&confirmation)?.device;
    let mut db = crate::runtime_db::connect(&state.owner.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    // No row locks here: the atomic queue verifier acquires manifest-first locks
    // and independently rechecks this exact durable tuple before commit.
    let row = db
        .query_opt(
            "SELECT s.connection_epoch FROM device_sessions s \
        JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
        JOIN sites t ON t.site_id=s.site_id JOIN deployment_authority p ON p.singleton=TRUE \
        WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 \
        AND s.deployment_epoch=$5 AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL \
        AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$5 AND NOT pg_is_in_recovery()",
            &[
                &owner.tenant.account_id(),
                &device,
                &socket.site_id,
                &socket.instance_id,
                &socket.deployment_epoch,
            ],
        )
        .await?
        .ok_or(ConversationError::Unavailable)?;
    let phone = InboundSession {
        account_id: owner.tenant.account_id(),
        device_id: device,
        site_id: &socket.site_id,
        instance_id: &socket.instance_id,
        connection_epoch: row.get(0),
        deployment_epoch: socket.deployment_epoch,
    };
    if socket.draining.load(Ordering::Acquire) {
        return Err(ConversationError::Unavailable.into());
    }
    queue::enqueue_confirmed_send(
        &mut db,
        owner,
        phone,
        state.billing_enabled,
        ConfirmedPacket {
            envelope: &envelope,
            confirmation: &confirmation,
            signature: &signature,
        },
    )
    .await
}

#[cfg(test)]
mod tests;
