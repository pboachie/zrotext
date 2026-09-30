// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted owner-session conversation consent and sealed inbound reads.
//! No send, upload, key provisioning or production feature flag is added here.
//! A future integration must enforce this consent at phone capture and ingest
//! too; these reader fences alone do not authorize content transfer.

use crate::{
    auth::{self, SessionPrincipal, TokenHasher},
    http_auth::{
        self,
        preauth::{OwnerAuthState, OwnerMutation},
    },
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::{AdmissionError, outbound::lock_current},
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub mod activation;
pub mod channel;
pub mod enrollment;
pub(crate) mod lifecycle;
pub mod send;

pub const DISCLOSURE_VERSION: &str = "conversation-content-v1";
const CONTENT_TYPE: &str = "application/vnd.zrotext.sealed.v1";

#[derive(Clone)]
pub struct OwnerConversationsState {
    pub database_url: String,
    pub auth_hasher: Arc<TokenHasher>,
    pub canonical_origin: String,
}

impl OwnerAuthState for OwnerConversationsState {
    fn database_url(&self) -> &str {
        &self.database_url
    }
    fn session_hasher(&self) -> &TokenHasher {
        &self.auth_hasher
    }
    fn canonical_origin(&self) -> &str {
        &self.canonical_origin
    }
}

/// Deliberately not called by main. Completing phone consent, secure browser
/// custody, upload and retention integration is required before mounting.
pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/conversation", post(enable).delete(revoke))
        .route("/v1/owner/conversation/events/{event_id}", get(read))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn(no_store))
        .with_state(Arc::new(state))
}

async fn no_store(request: Request, next: Next) -> Response {
    // An API bearer is never an alternative owner-session authority.
    let mut response = if request.headers().contains_key(header::AUTHORIZATION) {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        next.run(request).await
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationConsent {
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub peer: String,
    pub disclosure_version: String,
    pub content_transfer_confirmed: bool,
}

impl ConversationConsent {
    fn valid(&self) -> bool {
        let peer = self.peer.as_bytes();
        !self.device_id.is_nil()
            && !self.line_id.is_nil()
            && self.binding_generation > 0
            && self.content_transfer_confirmed
            && self.disclosure_version == DISCLOSURE_VERSION
            && (3..=16).contains(&peer.len())
            && peer[0] == b'+'
            && (b'1'..=b'9').contains(&peer[1])
            && peer[2..].iter().all(u8::is_ascii_digit)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    #[error("invalid conversation consent")]
    Invalid,
    #[error("conversation authority unavailable")]
    Forbidden,
    #[error("conversation already enabled; withdraw before changing it")]
    Conflict,
    #[error("conversation content not available")]
    NotFound,
    #[error("conversation storage unavailable")]
    Unavailable,
    #[error("conversation storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

impl IntoResponse for ConversationError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Conflict => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Database(_) | Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        status.into_response()
    }
}

impl From<AdmissionError> for ConversationError {
    fn from(error: AdmissionError) -> Self {
        match error {
            AdmissionError::Database(error) => Self::Database(error),
            AdmissionError::Rejected(_) => Self::Forbidden,
        }
    }
}

/// Serialize with account disable, role changes and session revocation. Recheck
/// wall-clock expiry after every later lock wait and before returning content.
async fn lock_owner(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
) -> Result<(), ConversationError> {
    tx.query_opt(
        "SELECT 1 FROM accounts a JOIN memberships m ON m.account_id=a.id \
         JOIN users u ON u.id=m.user_id JOIN sessions s ON (s.account_id,s.user_id)=(m.account_id,m.user_id) \
         WHERE a.id=$1 AND u.id=$2 AND s.id=$3 AND a.disabled_at IS NULL \
           AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL \
           AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR UPDATE OF a FOR SHARE OF m,u,s",
        &[&owner.tenant.account_id(), &owner.user_id, &owner.session_id],
    ).await?.ok_or(ConversationError::Forbidden)?;
    fresh_owner(tx, owner).await
}

async fn fresh_owner(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
) -> Result<(), ConversationError> {
    auth::require_current_owner(tx, owner)
        .await
        .map_err(|error| match error {
            auth::AuthError::Database(error) => ConversationError::Database(error),
            _ => ConversationError::Forbidden,
        })
}

async fn lock_line(
    tx: &Transaction<'_>,
    account: Uuid,
    device: Uuid,
    line: Uuid,
    generation: i64,
) -> Result<(), ConversationError> {
    tx.query_opt(
        "SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
         JOIN phone_lines l ON l.account_id=d.account_id AND l.id=$3 \
         JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation)=(l.account_id,l.id,d.id,$4) \
         WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
           AND l.state='active' AND l.approved_at IS NOT NULL AND l.current_binding_generation=$4 \
           AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL \
           AND b.owner_approval_digest IS NOT NULL AND b.device_confirmation_digest IS NOT NULL \
         FOR SHARE OF d,k,l,b",
        &[&account, &device, &line, &generation],
    ).await?.ok_or(ConversationError::Forbidden)?;
    Ok(())
}

pub async fn enable_conversation(
    client: &mut Client,
    owner: &SessionPrincipal,
    consent: &ConversationConsent,
) -> Result<(), ConversationError> {
    if !consent.valid() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    // Account lock serializes initial inserts and withdrawal/re-enable.
    if tx
        .query_opt(
            "SELECT 1 FROM owner_conversation_consents WHERE account_id=$1 AND revoked_at IS NULL",
            &[&owner.tenant.account_id()],
        )
        .await?
        .is_some()
    {
        return Err(ConversationError::Conflict);
    }
    lock_line(
        &tx,
        owner.tenant.account_id(),
        consent.device_id,
        consent.line_id,
        consent.binding_generation,
    )
    .await?;
    tx.execute(
        "INSERT INTO owner_conversation_consents(account_id,device_id,line_id,binding_generation,peer,disclosure_version,enabled_by) \
         VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(account_id) DO UPDATE SET \
         device_id=EXCLUDED.device_id,line_id=EXCLUDED.line_id,binding_generation=EXCLUDED.binding_generation, \
         peer=EXCLUDED.peer,disclosure_version=EXCLUDED.disclosure_version,enabled_by=EXCLUDED.enabled_by, \
         enabled_at=clock_timestamp(),revoked_at=NULL",
        &[&owner.tenant.account_id(),&consent.device_id,&consent.line_id,&consent.binding_generation,
          &consent.peer,&consent.disclosure_version,&owner.user_id],
    ).await?;
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(())
}

/// Withdrawal remains possible even after device/line revocation.
pub async fn revoke_conversation(
    client: &mut Client,
    owner: &SessionPrincipal,
) -> Result<(), ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    tx.execute("UPDATE owner_conversation_consents SET revoked_at=clock_timestamp(),peer=NULL WHERE account_id=$1 AND revoked_at IS NULL",
        &[&owner.tenant.account_id()]).await?;
    fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(())
}

/// Return exact already-verified opaque bytes, never decrypt on the server.
/// Refuse records timestamped before consent, purged content, other peers and
/// stale bindings. Timestamps are not consent-interval capture proof: phone
/// clocks can be ahead. Capture/ingest consent-epoch fencing remains mandatory.
pub async fn read_event(
    client: &mut Client,
    owner: &SessionPrincipal,
    event: Uuid,
) -> Result<Vec<u8>, ConversationError> {
    if event.is_nil() {
        return Err(ConversationError::NotFound);
    }
    let tx = client.transaction().await?;
    // Shared ingest/read lock order: manifest authority BEFORE account. Never
    // append a manifest lock to the existing account-first owner inventory.
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    lock_owner(&tx, owner).await?;
    let selected = tx
        .query_opt(
            "SELECT device_id,line_id,binding_generation,peer FROM owner_conversation_consents \
         WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE",
            &[&owner.tenant.account_id()],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    let device: Uuid = selected.get(0);
    let line: Uuid = selected.get(1);
    let generation: i64 = selected.get(2);
    let peer: String = selected.get(3);
    lock_line(&tx, owner.tenant.account_id(), device, line, generation).await?;
    let row = tx.query_opt(
        "SELECT e.envelope FROM sealed_inbound_events e JOIN owner_conversation_consents c ON c.account_id=e.account_id \
         WHERE e.account_id=$1 AND e.id=$2 AND e.device_id=c.device_id AND e.line_id=c.line_id \
           AND e.binding_generation=c.binding_generation AND e.envelope_profile=2 AND e.envelope IS NOT NULL \
           AND NOT EXISTS (SELECT 1 FROM conversation_inbound_provenance p WHERE (p.account_id,p.event_id)=(e.account_id,e.id)) \
           AND e.observed_at>=c.enabled_at AND e.received_at>=c.enabled_at FOR SHARE OF e",
        &[&owner.tenant.account_id(), &event],
    ).await?.ok_or(ConversationError::NotFound)?;
    let bytes: Vec<u8> = row.get(0);
    let claims = sealed_envelope::parse(&bytes, Profile::Draft02Candidate)
        .map_err(|_| ConversationError::NotFound)?;
    if claims.kind != Kind::Inbound
        || claims.peer != peer.as_bytes()
        || claims.account_id != owner.tenant.account_id().as_bytes()
        || claims.device_id != device.as_bytes()
        || claims.line_id != line.as_bytes()
        || claims.event_id != Some(event.as_bytes())
    {
        return Err(ConversationError::NotFound);
    }
    let recipients: Vec<ExpectedRecipient> = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap
                    .key_id
                    .try_into()
                    .map_err(|_| ConversationError::NotFound)?,
            })
        })
        .collect::<Result<_, ConversationError>>()?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Inbound,
        account_id: *owner.tenant.account_id().as_bytes(),
        device_id: *device.as_bytes(),
        line_id: *line.as_bytes(),
        message_id: *event.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| ConversationError::NotFound)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    // Reverify under the exact current owner-signed manifest, including current
    // archive reader/signer validity and expiry after the event-row lock wait.
    // Historical-manifest content fails closed even if key bytes are unchanged.
    let context = authority.inbound_context(&wanted).await?;
    sealed_envelope::verify(&bytes, &context).map_err(|_| ConversationError::Forbidden)?;
    fresh_owner(&tx, owner).await?;
    authority.inbound_context(&wanted).await?;
    drop(authority);
    tx.commit().await?;
    Ok(bytes)
}

async fn enable(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    crate::api_json::ApiJson(consent): crate::api_json::ApiJson<ConversationConsent>,
) -> Result<StatusCode, ConversationError> {
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    enable_conversation(&mut client, &owner, &consent).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
) -> Result<StatusCode, ConversationError> {
    let mut client = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    revoke_conversation(&mut client, &owner).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read(
    State(state): State<Arc<OwnerConversationsState>>,
    Path(event): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = http_auth::require_owner_read_headers(&headers) {
        return error.into_response();
    }
    let mut client = match crate::runtime_db::connect(&state.database_url).await {
        Ok(client) => client,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let owner = match http_auth::require_owner_read(&client, &state.auth_hasher, &headers).await {
        Ok(owner) => owner,
        Err(error) => return error.into_response(),
    };
    match read_event(&mut client, &owner, event).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, CONTENT_TYPE)], bytes).into_response(),
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod tests;
