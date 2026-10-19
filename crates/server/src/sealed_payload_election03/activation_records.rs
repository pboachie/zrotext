// SPDX-License-Identifier: AGPL-3.0-only
//! Actual immutable original-activation records, not current effect authority.
//! Schema provenance, original registration and both received activation
//! signatures are independently rechecked in one primary-database transaction.
use super::{
    activation_evidence::{ActivationEvidence03, ExpectedActivation03},
    adapter_contract::{self, DeviceSessionIdentity03},
    registration_reader::{self, HistoricalRegistration03, OriginalIdentity},
};
use tokio_postgres::{Client, IsolationLevel, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("original activation evidence unavailable")]
    Refused,
    #[error("original activation evidence storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}
type Result<T> = std::result::Result<T, ReadError>;

/// Lookup values only. A matching UUID, reader ID or detached result does not
/// establish authorization, selected-reader role or present device permission.
#[derive(Clone, Copy)]
pub struct Locator {
    pub account: Uuid,
    pub binding: Uuid,
    pub selected_reader_key_id: [u8; 32],
}

/// The actual observation tuple retained at original activation capture. It is
/// neither the earlier registration lease nor a current device-session proof.
pub struct OriginalProofLease03 {
    site: String,
    instance: String,
    connection: u64,
    deployment: u64,
}
impl OriginalProofLease03 {
    pub fn site_id(&self) -> &str {
        &self.site
    }
    pub fn instance_id(&self) -> &str {
        &self.instance
    }
    pub fn connection_epoch(&self) -> u64 {
        self.connection
    }
    pub fn deployment_epoch(&self) -> u64 {
        self.deployment
    }
}

/// Immutable historical originals and mapping only. Consumers must acquire
/// all current owner, selected-manifest/reader, lease, installation and election
/// fences again in the same transaction that authorizes an effect.
pub struct HistoricalActivation03 {
    registration: HistoricalRegistration03,
    binding: Uuid,
    challenge: Uuid,
    accepted_ms: u64,
    canonical: Vec<u8>,
    old_binding_digest: [u8; 32],
    proof_lease: OriginalProofLease03,
}
impl HistoricalActivation03 {
    pub fn registration(&self) -> &HistoricalRegistration03 {
        &self.registration
    }
    pub fn identity(&self) -> OriginalIdentity {
        self.registration.identity()
    }
    pub fn binding_id(&self) -> Uuid {
        self.binding
    }
    pub fn activation_challenge_id(&self) -> Uuid {
        self.challenge
    }
    pub fn accepted_ms(&self) -> u64 {
        self.accepted_ms
    }
    pub fn canonical_evidence(&self) -> &[u8] {
        &self.canonical
    }
    pub fn old_binding_proof_digest(&self) -> &[u8; 32] {
        &self.old_binding_digest
    }
    pub fn original_proof_lease(&self) -> &OriginalProofLease03 {
        &self.proof_lease
    }
}

fn refused() -> ReadError {
    ReadError::Refused
}
fn fixed<const N: usize>(row: &Row, column: usize) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(column)?
        .try_into()
        .map_err(|_| refused())
}
fn positive(n: i64) -> Result<u64> {
    u64::try_from(n).ok().filter(|n| *n > 0).ok_or_else(refused)
}
async fn clock(tx: &Transaction<'_>, floor: u64) -> Result<u64> {
    let row = tx.query_one("SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint", &[]).await?;
    let now = positive(row.try_get(1)?)?;
    if row.try_get::<_, bool>(0)? || now < floor {
        return Err(refused());
    }
    Ok(now)
}

pub async fn read(
    client: &mut Client,
    locator: Locator,
    configured_origin: &str,
) -> Result<HistoricalActivation03> {
    let tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await?;
    let evidence = read_locked(&tx, locator, configured_origin).await?;
    tx.commit().await?;
    Ok(evidence)
}

/// The caller's transaction is retained, allowing the current election adapter
/// to perform its independent locked selections before committing any effect.
pub(super) async fn read_locked(
    tx: &Transaction<'_>,
    locator: Locator,
    configured_origin: &str,
) -> Result<HistoricalActivation03> {
    if locator.account.is_nil()
        || locator.binding.is_nil()
        || locator.selected_reader_key_id == [0; 32]
    {
        return Err(refused());
    }
    adapter_contract::origin_digest(configured_origin).map_err(|_| refused())?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    crate::payload_profile_v2_receipts::require(tx)
        .await
        .map_err(|_| refused())?;
    let initial = clock(tx, 0).await?;
    // Nonlocking discovery is a locator only. Authority/root/account fences
    // precede the authoritative evidence read, and every identity is rechecked.
    let registration_id: Uuid = tx.query_opt(
        "SELECT registration_id FROM public.payload_profile_v2_activation_receipts WHERE account_id=$1 AND binding_id=$2",
        &[&locator.account,&locator.binding],
    ).await?.ok_or_else(refused)?.try_get(0)?;
    let registration = registration_reader::read_locked(
        tx,
        registration_reader::Locator {
            account: locator.account,
            registration: registration_id,
        },
        configured_origin,
    )
    .await
    .map_err(|error| match error {
        registration_reader::ReadError::Database(error) => ReadError::Database(error),
        _ => ReadError::Refused,
    })?;
    // The closed schema grants runtime SELECT only here. Insert-once evidence
    // needs no UPDATE privilege or fabricated row-lock capability: retained
    // account/anchor fences prevent erasure while the originals are consumed.
    let row = tx.query_opt(
        "SELECT challenge_id,registration_id,initiating_user_id,initiating_session_id,line_id,device_id,generation,protocol_version,purpose,device_statement,device_signature_der,owner_statement,owner_signature_der,device_point,owner_point,device_fingerprint,owner_fingerprint,device_statement_sha256,device_signature_sha256,owner_statement_sha256,owner_signature_sha256,device_confirmation_digest,owner_approval_digest,proof_site_id,proof_instance_id,proof_connection_epoch,proof_deployment_epoch,accepted_ms FROM public.payload_profile_v2_activation_receipts WHERE account_id=$1 AND binding_id=$2",
        &[&locator.account,&locator.binding],
    ).await?.ok_or_else(refused)?;
    let identity = registration.identity();
    let challenge: Uuid = row.try_get(0)?;
    if challenge.is_nil()
        || challenge == locator.binding
        || row.try_get::<_, Uuid>(1)? != identity.registration
        || row.try_get::<_, Uuid>(2)? != identity.user
        || row.try_get::<_, Uuid>(3)? != identity.owner_session
        || row.try_get::<_, Uuid>(4)? != identity.line
        || row.try_get::<_, Uuid>(5)? != identity.device
        || positive(row.try_get(6)?)? != identity.generation
        || row.try_get::<_, i16>(7)? != 2
        || row.try_get::<_, String>(8)? != "sealed"
    {
        return Err(refused());
    }
    let evidence = ActivationEvidence03 {
        registration_id: *identity.registration.as_bytes(),
        old_binding_id: *locator.binding.as_bytes(),
        device_statement: fixed(&row, 9)?,
        device_signature_der: row.try_get(10)?,
        owner_statement: fixed(&row, 11)?,
        owner_signature_der: row.try_get(12)?,
        device_point: fixed(&row, 13)?,
        owner_point: fixed(&row, 14)?,
        accepted_ms: positive(row.try_get(27)?)?,
    };
    let device = evidence.device_statement.as_slice();
    let owner = evidence.owner_statement.as_slice();
    let device_signature = evidence.device_signature_der.as_slice();
    let owner_signature = evidence.owner_signature_der.as_slice();
    let sha = crate::sealed_manifest03::sha;
    if device[86..102] != *challenge.as_bytes()
        || fixed::<32>(&row, 15)? != sha(&evidence.device_point)
        || fixed::<32>(&row, 16)? != sha(&evidence.owner_point)
        || fixed::<32>(&row, 17)? != sha(device)
        || fixed::<32>(&row, 18)? != sha(device_signature)
        || fixed::<32>(&row, 19)? != sha(owner)
        || fixed::<32>(&row, 20)? != sha(owner_signature)
        || fixed::<32>(&row, 21)? != sha(&[device, device_signature].concat())
        || fixed::<32>(&row, 22)? != sha(&[owner, owner_signature].concat())
    {
        return Err(refused());
    }
    let proof_lease = OriginalProofLease03 {
        site: row.try_get(23)?,
        instance: row.try_get(24)?,
        connection: positive(row.try_get(25)?)?,
        deployment: positive(row.try_get(26)?)?,
    };
    // Validate this original tuple in its own domain; never substitute it for
    // either the signed registration lease or a later current socket selection.
    DeviceSessionIdentity03 {
        account_id: *identity.account.as_bytes(),
        device_id: *identity.device.as_bytes(),
        site_id: &proof_lease.site,
        instance_id: &proof_lease.instance,
        connection_epoch: proof_lease.connection,
        deployment_epoch: proof_lease.deployment,
        line_activation_version: 2,
        enrollment_signing_key_id: *registration.paired_signing_key_id(),
    }
    .canonical()
    .map_err(|_| refused())?;
    let verified = evidence
        .verify_original(
            registration.canonical_evidence(),
            &ExpectedActivation03 {
                identity,
                old_binding_id: *locator.binding.as_bytes(),
                root_fingerprint: *registration.root_fingerprint(),
                paired_signing_key_id: *registration.paired_signing_key_id(),
                selected_reader_key_id: locator.selected_reader_key_id,
                canonical_origin: configured_origin,
            },
        )
        .map_err(|_| refused())?;
    clock(
        tx,
        initial
            .max(registration.checked_primary_ms())
            .max(evidence.accepted_ms),
    )
    .await?;
    Ok(HistoricalActivation03 {
        registration,
        binding: locator.binding,
        challenge,
        accepted_ms: evidence.accepted_ms,
        canonical: verified.canonical_evidence().to_vec(),
        old_binding_digest: *verified.old_binding_proof_digest(),
        proof_lease,
    })
}

#[cfg(test)]
mod tests;
