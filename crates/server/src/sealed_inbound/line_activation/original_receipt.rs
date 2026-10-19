// SPDX-License-Identifier: AGPL-3.0-only
//! Fresh registered SEALED-v2 originals are captured before activation writes.
//! The database capture function is structural persistence, never a substitute
//! for the real signatures and held current authority checked here and by the
//! enclosing activation transaction.
use super::*;
use crate::sealed_payload_election03::adapter_contract::RegistrationEvidence03;
use tokio_postgres::Transaction;
use zrotext_root_material::line_key_registration::{self as registration, Statement};

pub(super) struct Originals<'a> {
    pub principal: &'a SessionPrincipal,
    pub session: InboundSession<'a>,
    pub challenge: &'a LineChallenge,
    pub registration_id: Uuid,
    pub registration: &'a Statement,
    pub device_statement: &'a [u8],
    pub owner_statement: &'a [u8],
    pub device_der: &'a [u8],
    pub owner_der: &'a [u8],
    pub device_point: &'a [u8],
    pub owner_point: &'a [u8],
}

fn unavailable() -> LineActivationError {
    LineActivationError::Unavailable
}

/// A transaction-local final clock bound, not an activation/effect capability.
pub(super) struct CapturedOriginal {
    checked_ms: u64,
    expires_ms: u64,
}
impl CapturedOriginal {
    pub(super) async fn recheck(&self, tx: &Transaction<'_>) -> Result<(), LineActivationError> {
        let now = setup_registration::now(tx, self.checked_ms)
            .await
            .map_err(scope_error)?;
        if now >= self.expires_ms {
            return Err(unavailable());
        }
        Ok(())
    }
}

/// None is supported only for the validator's actual pre-installation case.
/// Changed/partial installations fail closed. Historical approved rows never
/// enter this fresh activation path and cannot gain replacement originals.
pub(super) async fn capture(
    tx: &Transaction<'_>,
    original: Originals<'_>,
) -> Result<Option<CapturedOriginal>, LineActivationError> {
    if !crate::payload_profile_v2_receipts::optional(tx)
        .await
        .map_err(|_| unavailable())?
    {
        return Ok(None);
    }
    crate::payload_profile_v2_receipts::require(tx)
        .await
        .map_err(|_| unavailable())?;
    let p = original.principal;
    let c = original.challenge;
    let statement = original.registration;
    let scope = statement.scope();
    if original.registration_id.is_nil()
        || c.account_id != p.tenant.account_id()
        || c.account_id != original.session.account_id
        || c.device_id != original.session.device_id
        || scope.account != *c.account_id.as_bytes()
        || scope.user != *p.user_id.as_bytes()
        || scope.owner_session != *p.session_id.as_bytes()
        || scope.device != *c.device_id.as_bytes()
        || scope.line != *c.line_id.as_bytes()
        || scope.challenge != *original.registration_id.as_bytes()
        || scope.next_generation != u64::try_from(c.generation).map_err(|_| unavailable())?
        || statement.approval_point().as_slice() != original.owner_point
        || digest(original.device_point) != scope.paired_signing_fingerprint
        || original.device_point == original.owner_point
        || original.device_point == &statement.root_pin()[29..]
    {
        return Err(unavailable());
    }
    let device =
        v2::DeviceStatementBytesV2::decode(v2::PurposeV2::Sealed, original.device_statement)
            .map_err(|_| unavailable())?;
    let observation =
        v2::ObservationV2::decode(&original.device_statement[134..]).map_err(|_| unavailable())?;
    let expected_device =
        v2::device_statement(v2::PurposeV2::Sealed, c, &observation).map_err(|_| unavailable())?;
    let owner = v2::owner_statement(&device, original.device_der).map_err(|_| unavailable())?;
    if device != expected_device
        || owner.bytes() != original.owner_statement
        || !v2::verify_device_signature(original.device_point, &device, original.device_der)
        || !v2::verify_owner_signature(original.owner_point, &owner, original.owner_der)
    {
        return Err(unavailable());
    }
    let row = tx.query_opt(
        "SELECT transcript,root_signature,approval_signature,approval_point,approval_fingerprint,paired_fingerprint,issued_ms,expires_ms,completed_ms FROM public.sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2 AND user_id=$3 AND session_id=$4 AND device_id=$5 AND line_id=$6 AND generation=$7 AND assigned_challenge_id=$8 AND retired_ms IS NULL AND activated_ms IS NULL FOR SHARE NOWAIT",
        &[&c.account_id,&original.registration_id,&p.user_id,&p.session_id,&c.device_id,&c.line_id,&c.generation,&c.id],
    ).await?.ok_or_else(unavailable)?;
    let transcript: Vec<u8> = row.try_get(0)?;
    let root_signature: [u8; 64] = row
        .try_get::<_, Vec<u8>>(1)?
        .try_into()
        .map_err(|_| unavailable())?;
    let approval_signature: [u8; 64] = row
        .try_get::<_, Vec<u8>>(2)?
        .try_into()
        .map_err(|_| unavailable())?;
    let point: [u8; 65] = row
        .try_get::<_, Vec<u8>>(3)?
        .try_into()
        .map_err(|_| unavailable())?;
    let fingerprint: [u8; 32] = row
        .try_get::<_, Vec<u8>>(4)?
        .try_into()
        .map_err(|_| unavailable())?;
    let paired: [u8; 32] = row
        .try_get::<_, Vec<u8>>(5)?
        .try_into()
        .map_err(|_| unavailable())?;
    let issued = u64::try_from(row.try_get::<_, i64>(6)?).map_err(|_| unavailable())?;
    let expires = u64::try_from(row.try_get::<_, i64>(7)?).map_err(|_| unavailable())?;
    let completed = u64::try_from(row.try_get::<_, i64>(8)?).map_err(|_| unavailable())?;
    if registration::encode(statement).map_err(|_| unavailable())? != transcript
        || point != *statement.approval_point()
        || fingerprint != scope.approval_fingerprint
        || paired != scope.paired_signing_fingerprint
        || issued != scope.issued_ms
        || expires != scope.expires_ms
    {
        return Err(unavailable());
    }
    statement
        .verify_root(&root_signature)
        .map_err(|_| unavailable())?;
    statement
        .verify_approval(&approval_signature)
        .map_err(|_| unavailable())?;
    // Reuse the exact existing canonical bounds and completion window. This is
    // historical evidence only; the fresh checks below remain independent.
    RegistrationEvidence03 {
        transcript: &transcript,
        root_signature: &root_signature,
        approval_signature: &approval_signature,
        approval_point: &point,
        approval_fingerprint: &fingerprint,
        paired_fingerprint: &paired,
        issued_ms: issued,
        expires_ms: expires,
        completed_ms: completed,
    }
    .canonical()
    .map_err(|_| unavailable())?;
    setup_registration::fresh(tx, p, statement, Some(original.session))
        .await
        .map_err(scope_error)?;
    let result = tx.query_one(
        "SELECT binding_id,accepted_ms FROM public.payload_profile_v2_capture($1,$2,$3,$4,$5,$6,$7,$8)",
        &[&c.account_id,&c.id,&original.device_statement,&original.device_der,
          &original.owner_statement,&original.owner_der,&original.device_point,&original.owner_point],
    ).await?;
    let binding: Uuid = result.try_get(0)?;
    let accepted: i64 = result.try_get(1)?;
    if binding.is_nil()
        || binding == c.id
        || accepted <= 0
        || (accepted as u64) < completed
        || (accepted as u64) >= expires
    {
        return Err(unavailable());
    }
    // The narrow function may wait. Recheck the actual original pending proof
    // and present scope before the enclosing transaction changes any state.
    let pending = v2_runtime::observation_store::load(tx, c.account_id, c.id).await?;
    v2_runtime::original_live(tx, &pending).await?;
    setup_registration::fresh(tx, p, statement, Some(original.session))
        .await
        .map_err(scope_error)?;
    if !owner_session_active(tx, p).await? {
        return Err(unavailable());
    }
    let checked_ms = setup_registration::now(tx, accepted as u64)
        .await
        .map_err(scope_error)?;
    if checked_ms >= expires {
        return Err(unavailable());
    }
    Ok(Some(CapturedOriginal {
        checked_ms,
        expires_ms: expires,
    }))
}
