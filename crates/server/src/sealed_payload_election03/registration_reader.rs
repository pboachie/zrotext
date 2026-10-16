// SPDX-License-Identifier: AGPL-3.0-only
//! Original accepted registration evidence read from the supplied application
//! database. This is historical signature evidence, never current owner/MFA,
//! device-lease, selection, commit or effect permission. Callers must use their
//! trusted application connection and independently configured canonical origin.
use super::adapter_contract::{self, RegistrationEvidence03};
use tokio_postgres::{Client, IsolationLevel, Row, Transaction};
use uuid::Uuid;
use zrotext_root_material::{line_key_registration as registration, sealed_root_enrollment};

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("original registration evidence unavailable")]
    Refused,
    #[error("original registration evidence fence busy")]
    Busy,
    #[error("original registration storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ReadError>;

/// Lookup selectors only; these UUIDs confer no account or receipt authority.
#[derive(Clone, Copy)]
pub struct Locator {
    pub account: Uuid,
    pub registration: Uuid,
}

/// Exact persisted historical identities, not an authenticated present session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OriginalIdentity {
    pub account: Uuid,
    pub registration: Uuid,
    pub user: Uuid,
    pub owner_session: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub generation: u64,
}

/// Only the database reader constructs this value. It may outlive its read
/// transaction because it represents immutable historical evidence, not a held
/// transaction capability. An effect adapter must separately acquire and verify
/// all current authority, schema, epoch, lease and accepted-election fences.
pub struct HistoricalRegistration03 {
    identity: OriginalIdentity,
    root_fingerprint: [u8; 32],
    paired_signing_key_id: [u8; 32],
    canonical: Vec<u8>,
    digest: [u8; 32],
}
impl HistoricalRegistration03 {
    pub fn identity(&self) -> OriginalIdentity {
        self.identity
    }
    pub fn root_fingerprint(&self) -> &[u8; 32] {
        &self.root_fingerprint
    }
    pub fn paired_signing_key_id(&self) -> &[u8; 32] {
        &self.paired_signing_key_id
    }
    pub fn canonical_evidence(&self) -> &[u8] {
        &self.canonical
    }
    pub fn evidence_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

fn fixed<const N: usize>(row: &Row, column: usize) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(column)?
        .try_into()
        .map_err(|_| ReadError::Refused)
}
fn positive(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ReadError::Refused)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let row = tx.query_one("SELECT pg_catalog.pg_is_in_recovery(), pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await?;
    let now = positive(row.try_get(1)?)?;
    if row.try_get::<_, bool>(0)? || now < floor {
        return Err(ReadError::Refused);
    }
    Ok(now)
}

/// Reads and verifies the actual original bytes in one bounded primary-database
/// transaction. No root, point, signature, receipt body or verification boolean
/// is accepted from the caller. Missing original roots/keys refuse; this reader
/// neither reconstructs missing history nor assigns an old-binding UUID.
pub async fn read(
    client: &mut Client,
    locator: Locator,
    configured_origin: &str,
) -> Result<HistoricalRegistration03> {
    if locator.account.is_nil() || locator.registration.is_nil() {
        return Err(ReadError::Refused);
    }
    adapter_contract::origin_digest(configured_origin).map_err(|_| ReadError::Refused)?;
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let proof = read_locked(&tx, locator, configured_origin).await?;
    tx.commit().await?;
    Ok(proof)
}

async fn read_locked(
    tx: &Transaction<'_>,
    locator: Locator,
    configured_origin: &str,
) -> Result<HistoricalRegistration03> {
    let mut floor = clock(tx, 0).await?;
    // Existing authority precedes account fences. No root is provisioned, and
    // an unsupported rotated/missing original root cannot become a new genesis.
    let root = tx.query_opt("SELECT root_pin,root_fingerprint,generation,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT", &[&locator.account]).await?.ok_or(ReadError::Refused)?;
    let pin: [u8; 94] = fixed(&root, 0)?;
    let fingerprint: [u8; 32] = fixed(&root, 1)?;
    let verified_floor: i64 = root.try_get(3)?;
    if root.try_get::<_, i64>(2)? != 1 || verified_floor < 0 {
        return Err(ReadError::Refused);
    }
    floor = floor.max(verified_floor as u64);
    if sealed_root_enrollment::root_fingerprint(&pin, locator.account.as_bytes())
        .map_err(|_| ReadError::Refused)?
        != fingerprint
    {
        return Err(ReadError::Refused);
    }
    let key = adapter_contract::account_fence_key(locator.account.as_bytes())
        .map_err(|_| ReadError::Refused)?;
    if !tx
        .query_one(
            "SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)",
            &[&key],
        )
        .await?
        .try_get::<_, bool>(0)?
    {
        return Err(ReadError::Busy);
    }
    let anchor = tx.query_opt("SELECT state,selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 FOR SHARE NOWAIT", &[&locator.account]).await?.ok_or(ReadError::Refused)?;
    if anchor.try_get::<_, String>(0)? != "live" || anchor.try_get::<_, i64>(1)? < 0 {
        return Err(ReadError::Refused);
    }
    tx.query_opt(
        "SELECT id FROM public.accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
        &[&locator.account],
    )
    .await?
    .ok_or(ReadError::Refused)?;
    let row = tx.query_opt("SELECT user_id,session_id,device_id,line_id,generation,transcript,root_signature,approval_signature,approval_point,approval_fingerprint,paired_fingerprint,issued_ms,expires_ms,completed_ms FROM public.sealed_line_key_receipts WHERE account_id=$1 AND registration_id=$2 FOR SHARE NOWAIT", &[&locator.account,&locator.registration]).await?.ok_or(ReadError::Refused)?;
    let identity = OriginalIdentity {
        account: locator.account,
        registration: locator.registration,
        user: row.try_get(0)?,
        owner_session: row.try_get(1)?,
        device: row.try_get(2)?,
        line: row.try_get(3)?,
        generation: positive(row.try_get(4)?)?,
    };
    let transcript: Vec<u8> = row.try_get(5)?;
    let root_signature: [u8; 64] = fixed(&row, 6)?;
    let approval_signature: [u8; 64] = fixed(&row, 7)?;
    let approval_point: [u8; 65] = fixed(&row, 8)?;
    let approval_fingerprint: [u8; 32] = fixed(&row, 9)?;
    let paired_fingerprint: [u8; 32] = fixed(&row, 10)?;
    let issued = positive(row.try_get(11)?)?;
    let expires = positive(row.try_get(12)?)?;
    let completed = positive(row.try_get(13)?)?;
    let statement = registration::decode(&transcript).map_err(|_| ReadError::Refused)?;
    let signed = statement.scope();
    if registration::encode(&statement).map_err(|_| ReadError::Refused)? != transcript
        || statement.root_pin() != &pin
        || statement.root_fingerprint() != &fingerprint
        || statement.approval_point() != &approval_point
        || signed.account != *identity.account.as_bytes()
        || signed.user != *identity.user.as_bytes()
        || signed.owner_session != *identity.owner_session.as_bytes()
        || signed.device != *identity.device.as_bytes()
        || signed.line != *identity.line.as_bytes()
        || signed.challenge != *identity.registration.as_bytes()
        || signed.next_generation != identity.generation
        || signed.issued_ms != issued
        || signed.expires_ms != expires
        || signed.origin != configured_origin
        || signed.approval_fingerprint != approval_fingerprint
        || signed.paired_signing_fingerprint != paired_fingerprint
    {
        return Err(ReadError::Refused);
    }
    // Revocation is not erased history. These rows supply the exact original
    // points; their present status does NOT grant a current device/owner role.
    let paired = tx.query_opt("SELECT signing_key_sec1,fingerprint FROM public.device_keys WHERE account_id=$1 AND device_id=$2 FOR SHARE NOWAIT", &[&identity.account,&identity.device]).await?.ok_or(ReadError::Refused)?;
    let paired_point: Vec<u8> = paired.try_get(0)?;
    let stored_pair: [u8; 32] = fixed(&paired, 1)?;
    let paired_signing_key_id =
        adapter_contract::enrollment_signing_key_id(&paired_point, &stored_pair)
            .map_err(|_| ReadError::Refused)?;
    let approval = tx.query_opt("SELECT signing_key_sec1 FROM public.line_owner_approval_keys WHERE account_id=$1 AND fingerprint=$2 FOR SHARE NOWAIT", &[&identity.account,&&approval_fingerprint[..]]).await?.ok_or(ReadError::Refused)?;
    if stored_pair != paired_fingerprint
        || approval.try_get::<_, Vec<u8>>(0)? != approval_point
        || paired_point == approval_point
        || paired_point.as_slice() == &pin[29..]
    {
        return Err(ReadError::Refused);
    }
    statement
        .verify_root(&root_signature)
        .map_err(|_| ReadError::Refused)?;
    statement
        .verify_approval(&approval_signature)
        .map_err(|_| ReadError::Refused)?;
    let evidence = RegistrationEvidence03 {
        transcript: &transcript,
        root_signature: &root_signature,
        approval_signature: &approval_signature,
        approval_point: &approval_point,
        approval_fingerprint: &approval_fingerprint,
        paired_fingerprint: &paired_fingerprint,
        issued_ms: issued,
        expires_ms: expires,
        completed_ms: completed,
    };
    let canonical = evidence.canonical().map_err(|_| ReadError::Refused)?;
    let digest = evidence.digest().map_err(|_| ReadError::Refused)?;
    clock(tx, floor.max(completed)).await?;
    Ok(HistoricalRegistration03 {
        identity,
        root_fingerprint: fingerprint,
        paired_signing_key_id,
        canonical,
        digest,
    })
}

#[cfg(test)]
mod tests;
