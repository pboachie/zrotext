// SPDX-License-Identifier: AGPL-3.0-only
//! Opt-in library adapter; the shipped server never enables these routes.

use super::{AuthHttpError, AuthHttpState, connect, map_auth, require_owner};
use crate::{api_json::ApiJson, sealed_root_ceremony as ceremony, sealed_root_custody as custody};
use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

fn decode(value: &str, maximum: usize) -> Result<Vec<u8>, AuthHttpError> {
    if value.len() > maximum.div_ceil(3) * 4 {
        return Err(AuthHttpError::BadRequest);
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| AuthHttpError::BadRequest)?;
    if bytes.len() > maximum || STANDARD.encode(&bytes) != value {
        return Err(AuthHttpError::BadRequest);
    }
    Ok(bytes)
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], AuthHttpError> {
    decode(value, N)?
        .try_into()
        .map_err(|_| AuthHttpError::BadRequest)
}

fn error(value: ceremony::CeremonyError) -> AuthHttpError {
    match value {
        ceremony::CeremonyError::Authentication(auth) => map_auth(auth),
        ceremony::CeremonyError::Database(_) => AuthHttpError::Unavailable,
        ceremony::CeremonyError::Rejected(_) => AuthHttpError::BadRequest,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChallengeBody {
    root_pin_b64: String,
    independently_compared_fingerprint_b64: String,
    encrypted_backup_b64: String,
    public_card_b64: String,
}

#[derive(Serialize)]
pub(super) struct ChallengeView {
    unsigned_enrollment_b64: String,
    custody_statement_b64: String,
    root_pin_b64: String,
}

pub(super) async fn challenge(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<ChallengeBody>,
) -> Result<Json<ChallengeView>, AuthHttpError> {
    let mut db = connect(&state.database_url).await?;
    let principal =
        require_owner(&db, &state.hasher, &state.canonical_origin, &headers, true).await?;
    let pin = fixed::<94>(&body.root_pin_b64)?;
    let compared = fixed::<32>(&body.independently_compared_fingerprint_b64)?;
    let fingerprint = crate::sealed_root_enrollment::root_fingerprint(
        &pin,
        principal.tenant.account_id().as_bytes(),
    )
    .map_err(|_| AuthHttpError::BadRequest)?;
    if compared != fingerprint {
        return Err(AuthHttpError::BadRequest);
    }
    let backup = decode(&body.encrypted_backup_b64, custody::MAX_BACKUP)?;
    let card = decode(&body.public_card_b64, custody::MAX_CARD)?;
    let expected = crate::root_backup::ExpectedIdentity {
        account_id: *principal.tenant.account_id().as_bytes(),
        origin: state.canonical_origin.clone(),
        root_fingerprint: compared,
    };
    crate::root_backup::validate_public_header(&backup, &expected)
        .map_err(|_| AuthHttpError::BadRequest)?;
    use sha2::{Digest, Sha256};
    zrotext_root_material::recovery_kit::decode_public_card(
        &card,
        &expected,
        &Sha256::digest(&backup).into(),
    )
    .map_err(|_| AuthHttpError::BadRequest)?;
    if state.mfa_cipher.is_none() {
        return Err(AuthHttpError::Unavailable);
    }
    let issued = ceremony::issue_challenge(
        &mut db,
        &state.hasher,
        &principal,
        &state.canonical_origin,
        pin,
    )
    .await
    .map_err(error)?;
    let statement =
        custody::statement(&issued.unsigned, &backup, &card, &compared).map_err(error)?;
    Ok(Json(ChallengeView {
        unsigned_enrollment_b64: STANDARD.encode(&issued.unsigned),
        custody_statement_b64: STANDARD.encode(&statement),
        root_pin_b64: STANDARD.encode(pin),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompleteBody {
    unsigned_enrollment_b64: String,
    enrollment_signature_b64: String,
    custody_signature_b64: String,
    independently_compared_fingerprint_b64: String,
    encrypted_backup_b64: String,
    public_card_b64: String,
    mfa_code: String,
}

#[derive(Serialize)]
pub(super) struct ReceiptView {
    account_id: Uuid,
    challenge_id: Uuid,
    root_pin_b64: String,
    root_fingerprint_b64: String,
    completed_ms: i64,
}

pub(super) async fn complete(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<CompleteBody>,
) -> Result<Json<ReceiptView>, AuthHttpError> {
    let mut db = connect(&state.database_url).await?;
    let principal =
        require_owner(&db, &state.hasher, &state.canonical_origin, &headers, true).await?;
    let cipher = state
        .mfa_cipher
        .as_ref()
        .ok_or(AuthHttpError::Unavailable)?;
    let unsigned = decode(&body.unsigned_enrollment_b64, 663)?;
    let enrollment_signature = fixed::<64>(&body.enrollment_signature_b64)?;
    let custody_signature = fixed::<64>(&body.custody_signature_b64)?;
    let compared = fixed::<32>(&body.independently_compared_fingerprint_b64)?;
    let backup = decode(&body.encrypted_backup_b64, custody::MAX_BACKUP)?;
    let card = decode(&body.public_card_b64, custody::MAX_CARD)?;
    let receipt = ceremony::complete_with_custody(
        &mut db,
        &state.hasher,
        cipher,
        &principal,
        &state.canonical_origin,
        ceremony::Completion {
            unsigned: &unsigned,
            signature: &enrollment_signature,
            factor: &body.mfa_code,
        },
        custody::Publication {
            encrypted_backup: &backup,
            public_card: &card,
            independently_compared_fingerprint: compared,
            signature: &custody_signature,
        },
    )
    .await
    .map_err(error)?;
    Ok(Json(ReceiptView {
        account_id: receipt.account_id,
        challenge_id: receipt.challenge_id,
        root_pin_b64: STANDARD.encode(receipt.root_pin),
        root_fingerprint_b64: STANDARD.encode(receipt.root_fingerprint),
        completed_ms: receipt.completed_ms,
    }))
}

#[derive(Serialize)]
pub(super) struct ExportView {
    account_id: Uuid,
    challenge_id: Uuid,
    backup_id: Uuid,
    generation: i64,
    root_pin_b64: String,
    root_fingerprint_b64: String,
    encrypted_backup_b64: String,
    public_card_b64: String,
    committed_ms: i64,
    unsigned_enrollment_b64: String,
    custody_signature_b64: String,
}

pub(super) async fn export(
    State(state): State<Arc<AuthHttpState>>,
    headers: HeaderMap,
) -> Result<Json<ExportView>, AuthHttpError> {
    let mut db = connect(&state.database_url).await?;
    // Reads also require the owner Origin/CSRF proof to prevent cross-origin
    // encrypted backup exfiltration and reject sessions without a live MFA owner.
    let principal =
        require_owner(&db, &state.hasher, &state.canonical_origin, &headers, true).await?;
    let compared = headers
        .get("x-zrotext-root-fingerprint")
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthHttpError::BadRequest)
        .and_then(fixed::<32>)?;
    let bundle = custody::export(&mut db, &principal, &state.canonical_origin, &compared)
        .await
        .map_err(error)?
        .ok_or(AuthHttpError::NotFound)?;
    Ok(Json(ExportView {
        account_id: bundle.account_id,
        challenge_id: bundle.challenge_id,
        backup_id: bundle.backup_id,
        generation: bundle.generation,
        root_pin_b64: STANDARD.encode(bundle.root_pin),
        root_fingerprint_b64: STANDARD.encode(bundle.root_fingerprint),
        encrypted_backup_b64: STANDARD.encode(bundle.encrypted_backup),
        public_card_b64: STANDARD.encode(bundle.public_card),
        committed_ms: bundle.committed_ms,
        unsigned_enrollment_b64: STANDARD.encode(bundle.unsigned_enrollment),
        custody_signature_b64: STANDARD.encode(bundle.custody_signature),
    }))
}

#[cfg(test)]
mod tests;
