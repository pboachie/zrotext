// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-cookie adapters in default-disabled composition. No root custody or key creation.
use super::{
    ConversationConsent, ConversationError, OwnerConversationsState, activation, enrollment,
};
use crate::sealed_envelope::{ExpectedRecipient, Kind};
use crate::sealed_manifest::EnvelopeAuthority;
use crate::sealed_manifest_store::outbound::lock_current;
use crate::{api_json::ApiJson, http_auth::preauth::OwnerMutation};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub const STATEMENT_CONTENT_TYPE: &str = "application/vnd.zrotext.conversation-statement.v1";

/// Explicit host composition only. Existing owner authentication runs before body extraction.
pub fn router(state: OwnerConversationsState) -> Router {
    Router::new()
        .route("/v1/owner/conversation/activation", post(begin))
        .route("/v1/owner/conversation/enrollment", post(install))
        .route("/v1/owner/conversation/bootstrap", post(bootstrap))
        .layer(DefaultBodyLimit::max(20 * 1024))
        .layer(middleware::from_fn(super::no_store))
        .with_state(Arc::new(state))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationRequest {
    consent: ConversationConsent,
    next_manifest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentRequest {
    device_id: Uuid,
    line_id: Uuid,
    binding_generation: i64,
    peer: String,
    phone_reader: String,
    archive_reader: String,
    signer: String,
    public_point: String,
    predecessor: String,
    signed_successor: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapRequest {
    device_id: Uuid,
    line_id: Uuid,
    binding_generation: i64,
    peer: String,
}

async fn bootstrap(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(selected): ApiJson<BootstrapRequest>,
) -> Result<Json<serde_json::Value>, ConversationError> {
    let consent = ConversationConsent {
        device_id: selected.device_id,
        line_id: selected.line_id,
        binding_generation: selected.binding_generation,
        peer: selected.peer.clone(),
        disclosure_version: super::DISCLOSURE_VERSION.into(),
        content_transfer_confirmed: true,
    };
    if !consent.valid() {
        return Err(ConversationError::Invalid);
    }
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    let tx = db.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    super::lock_owner(&tx, &owner).await?;
    super::lock_line(
        &tx,
        owner.tenant.account_id(),
        selected.device_id,
        selected.line_id,
        selected.binding_generation,
    )
    .await?;
    bootstrap_device_live(&tx, owner.tenant.account_id(), selected.device_id).await?;
    let (archive, phone_signer) = authority
        .public_conversation_keys(selected.device_id, selected.line_id)
        .await?;
    let readers = [ExpectedRecipient {
        role: 2,
        key_id: archive,
    }];
    let wanted = EnvelopeAuthority {
        kind: Kind::Inbound,
        account_id: *owner.tenant.account_id().as_bytes(),
        device_id: *selected.device_id.as_bytes(),
        line_id: *selected.line_id.as_bytes(),
        message_id: *Uuid::new_v4().as_bytes(),
        signer_key_id: phone_signer,
        peer: selected.peer.as_bytes(),
        recipients: &readers,
    };
    let candidate = authority.public_candidate(&wanted).await?;
    let bytes = &candidate.snapshot.bytes;
    // This is parsing already verified canonical public records, never promoting relay bytes.
    let now = candidate.snapshot.accepted_ms;
    let records: Vec<_> = bytes[151..bytes.len() - 64].chunks_exact(149).collect();
    let active = |r: &&[u8]| {
        r[148] == 1
            && i64::from_be_bytes(r[132..140].try_into().unwrap()) <= now
            && now < i64::from_be_bytes(r[140..148].try_into().unwrap())
    };
    let mut phone = records
        .iter()
        .copied()
        .filter(|r| {
            r[0] == 1
                && r[98..114] == *selected.device_id.as_bytes()
                && r[114..130] == *selected.line_id.as_bytes()
                && u16::from_be_bytes(r[130..132].try_into().unwrap()) & 4 != 0
        })
        .filter(active);
    let phone = phone
        .next()
        .ok_or(ConversationError::Forbidden)
        .and_then(|first| {
            if phone.next().is_some() {
                Err(ConversationError::Forbidden)
            } else {
                Ok(first)
            }
        })?;
    let record = |id: [u8; 32]| {
        records
            .iter()
            .copied()
            .find(|r| r[1..33] == id)
            .ok_or(ConversationError::Forbidden)
    };
    let archive_record = record(archive)?;
    let signer_record = record(phone_signer)?;
    let interval = tx
        .query_opt(
            "SELECT id,phase FROM conversation_intervals WHERE account_id=$1 \
        AND initiating_session_id=$2 AND device_id=$3 AND line_id=$4 AND binding_generation=$5 \
        AND phase IN ('pending','install_pending','active') FOR SHARE",
            &[
                &owner.tenant.account_id(),
                &owner.session_id,
                &selected.device_id,
                &selected.line_id,
                &selected.binding_generation,
            ],
        )
        .await?;
    let (interval_id, phase, pending_deadline) = if let Some(row) = interval {
        let loaded = activation::load(&tx, owner.tenant.account_id(), row.get(0)).await?;
        if loaded.statement.peer != selected.peer
            || loaded.statement.reader != archive
            || loaded.statement.signer != phone_signer
            || (loaded.phase != "active" && now >= loaded.statement.expires_ms)
        {
            return Err(ConversationError::Forbidden);
        }
        let deadline = if loaded.phase == "active" {
            None
        } else {
            Some(loaded.statement.expires_ms)
        };
        (Some(loaded.statement.interval), loaded.phase, deadline)
    } else {
        (None, "unprepared".to_owned(), None)
    };
    super::fresh_owner(&tx, &owner).await?;
    super::lock_line(
        &tx,
        owner.tenant.account_id(),
        selected.device_id,
        selected.line_id,
        selected.binding_generation,
    )
    .await?;
    bootstrap_device_live(&tx, owner.tenant.account_id(), selected.device_id).await?;
    let consent_live = tx
        .query_opt(
            "SELECT 1 FROM owner_conversation_consents WHERE account_id=$1 \
        AND device_id=$2 AND line_id=$3 AND binding_generation=$4 AND peer=$5 \
        AND disclosure_version='conversation-content-v1' AND revoked_at IS NULL FOR SHARE",
            &[
                &owner.tenant.account_id(),
                &selected.device_id,
                &selected.line_id,
                &selected.binding_generation,
                &selected.peer,
            ],
        )
        .await?
        .is_some();
    bootstrap_device_live(&tx, owner.tenant.account_id(), selected.device_id).await?;
    super::fresh_owner(&tx, &owner).await?;
    let final_candidate = authority.public_candidate(&wanted).await?;
    let final_now = final_candidate.snapshot.accepted_ms;
    if pending_deadline.is_some_and(|deadline| final_now >= deadline) {
        return Err(ConversationError::Forbidden);
    }
    // Revalidate the selected phone payload key after all potentially blocking reads.
    if final_now < i64::from_be_bytes(phone[132..140].try_into().unwrap())
        || final_now >= i64::from_be_bytes(phone[140..148].try_into().unwrap())
    {
        return Err(ConversationError::Forbidden);
    }
    let response = serde_json::json!({"v":1,"trust_candidate":true,"owner_session_live":true,"consent_live":consent_live,
        "account_id":owner.tenant.account_id(),"session_id":owner.session_id,
        "device_id":selected.device_id,"line_id":selected.line_id,"binding_generation":selected.binding_generation.to_string(),
        "peer":selected.peer,"phase":phase,"interval_id":interval_id,"server_now_ms":final_now.to_string(),
        "root_pin":STANDARD.encode(&candidate.pin),"root_fingerprint":STANDARD.encode(candidate.fingerprint),
        "current_manifest":STANDARD.encode(bytes),"manifest_digest":STANDARD.encode(candidate.snapshot.digest),
        "manifest_version":candidate.snapshot.version.to_string(),"trust_generation":candidate.snapshot.generation.to_string(),
        "phone_reader_id":STANDARD.encode(&phone[1..33]),"phone_reader_point":STANDARD.encode(&phone[33..98]),
        "archive_reader_id":STANDARD.encode(archive),"archive_reader_point":STANDARD.encode(&archive_record[33..98]),
        "phone_signer_id":STANDARD.encode(phone_signer),"phone_signer_point":STANDARD.encode(&signer_record[33..98])});
    drop(authority);
    tx.commit().await?;
    Ok(Json(response))
}

async fn bootstrap_device_live(
    tx: &tokio_postgres::Transaction<'_>,
    account: Uuid,
    device: Uuid,
) -> Result<(), ConversationError> {
    // No caller can substitute a placement, deployment or device lease tuple.
    tx.query_opt("SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
        JOIN device_sessions s ON (s.account_id,s.device_id)=(d.account_id,d.id) JOIN sites t ON t.site_id=s.site_id \
        JOIN deployment_authority p ON p.singleton=TRUE WHERE d.account_id=$1 AND d.id=$2 \
        AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND s.lease_until>clock_timestamp() \
        AND t.enabled AND NOT t.draining AND p.epoch=s.deployment_epoch AND NOT pg_is_in_recovery() \
        FOR SHARE OF d,k,s,t,p",&[&account,&device]).await?.ok_or(ConversationError::Forbidden)?;
    Ok(())
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
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], ConversationError> {
    decode(value, N, N)?
        .try_into()
        .map_err(|_| ConversationError::Invalid)
}

async fn begin(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(request): ApiJson<ActivationRequest>,
) -> Result<Response, ConversationError> {
    let manifest = decode(&request.next_manifest, 364, 9751)?;
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    let statement = activation::begin(&mut db, &owner, &request.consent, &manifest).await?;
    Ok((
        [(header::CONTENT_TYPE, STATEMENT_CONTENT_TYPE)],
        statement.encode()?,
    )
        .into_response())
}

async fn install(
    State(state): State<Arc<OwnerConversationsState>>,
    OwnerMutation(owner, _slot): OwnerMutation,
    ApiJson(request): ApiJson<EnrollmentRequest>,
) -> Result<StatusCode, ConversationError> {
    let successor = decode(&request.signed_successor, 364, 9751)?;
    let selected = enrollment::Enrollment {
        device: request.device_id,
        line: request.line_id,
        generation: request.binding_generation,
        originating_session: owner.session_id,
        peer: request.peer,
        phone_reader: fixed(&request.phone_reader)?,
        archive_reader: fixed(&request.archive_reader)?,
        signer: fixed(&request.signer)?,
        public_point: fixed(&request.public_point)?,
        predecessor: fixed(&request.predecessor)?,
    };
    let mut db = crate::runtime_db::connect(&state.database_url)
        .await
        .map_err(|_| ConversationError::Unavailable)?;
    enrollment::install(&mut db, &owner, &selected, &successor).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
